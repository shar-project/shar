#![forbid(unsafe_code)]

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{ConnectInfo, Path as AxumPath, Query, State},
    http::{HeaderMap, HeaderValue, Request as HttpRequest, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    serve::ListenerExt,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use num_bigint::BigUint;
use num_integer::Integer;
use postgres::{Client as PostgresClient, Config as PostgresConfig, config::SslMode};
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use shar_core::trust::TrustKeyPair;
use shar_core::{
    AuditStore, ChallengeRequest, ConfigStore, Engine, FallbackCompletionRequest, FallbackPlan,
    NonceStore, PresencePlan, PressureStore, RedeemRequest, SharError, SigningMaterial,
    SiteVerifyRequest, TimeLockKey, VerificationMaterial, WorkPolicy, daily_network_pseudonym,
    default_work_policy, validate_time_lock_key, verify_site_verify_secret,
};
use shar_server::{
    postgres::PostgresStore,
    redis::{RedisStore, low_latency_client},
    sqlite::SqliteStore,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{HashMap, HashSet},
    env,
    future::IntoFuture,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::{Component, Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Condvar, Mutex, OnceLock, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct AppState {
    engine: Arc<Engine>,
    allowed_origins: Arc<HashSet<String>>,
    network_secret: [u8; 32],
    fallback_secret: Option<[u8; 32]>,
    admin_secret: Option<[u8; 32]>,
    siteverify_master_secret: Option<[u8; 32]>,
    region: Option<String>,
    trusted_proxies: Arc<Vec<Cidr>>,
    trusted_assurance_header: bool,
    metrics: Arc<Metrics>,
    request_log: bool,
    max_concurrent_requests: u64,
    request_body_timeout: Duration,
    readiness_admission: Arc<Admission>,
    admin_assets: Arc<PathBuf>,
}

type StoreSet = (
    Arc<dyn NonceStore>,
    Arc<dyn PressureStore>,
    Arc<dyn ConfigStore>,
    Arc<dyn AuditStore>,
);

#[derive(Default)]
struct Metrics {
    issued: AtomicU64,
    issue_engine_micros: AtomicU64,
    issue_handler_micros: AtomicU64,
    redeemed: AtomicU64,
    verified: AtomicU64,
    fallback: AtomicU64,
    audit_dropped: AtomicU64,
}

const AUDIT_QUEUE_CAPACITY: usize = 4_096;
const AUDIT_BATCH_SIZE: usize = 128;
const AUDIT_BATCH_WINDOW: Duration = Duration::from_millis(10);
const AUDIT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct BufferedAuditStore {
    sender: mpsc::SyncSender<shar_core::AuditEvent>,
    inner: Arc<dyn AuditStore>,
    metrics: Arc<Metrics>,
    pending: Arc<(Mutex<usize>, Condvar)>,
}

impl BufferedAuditStore {
    fn new(inner: Arc<dyn AuditStore>, metrics: Arc<Metrics>) -> Result<Self, std::io::Error> {
        let (sender, receiver) = mpsc::sync_channel(AUDIT_QUEUE_CAPACITY);
        let worker_store = inner.clone();
        let worker_metrics = metrics.clone();
        let pending = Arc::new((Mutex::new(0_usize), Condvar::new()));
        let worker_pending = pending.clone();
        thread::Builder::new()
            .name("shar-audit".into())
            .spawn(move || {
                while let Ok(event) = receiver.recv() {
                    let mut batch = Vec::with_capacity(AUDIT_BATCH_SIZE);
                    batch.push(event);
                    let deadline = Instant::now() + AUDIT_BATCH_WINDOW;
                    while batch.len() < AUDIT_BATCH_SIZE {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        match receiver.recv_timeout(remaining) {
                            Ok(event) => batch.push(event),
                            Err(_) => break,
                        }
                    }
                    if worker_store.record_batch(&batch).is_err() {
                        worker_metrics
                            .audit_dropped
                            .fetch_add(batch.len() as u64, Ordering::Relaxed);
                    }
                    let (lock, completed) = &*worker_pending;
                    let mut pending = lock.lock().unwrap_or_else(|error| error.into_inner());
                    *pending = pending.saturating_sub(batch.len());
                    if *pending == 0 {
                        completed.notify_all();
                    }
                }
            })?;
        Ok(Self {
            sender,
            inner,
            metrics,
            pending,
        })
    }

    fn flush(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (lock, completed) = &*self.pending;
        let mut pending = lock.lock().unwrap_or_else(|error| error.into_inner());
        while *pending > 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next, waited) = completed
                .wait_timeout(pending, remaining)
                .unwrap_or_else(|error| error.into_inner());
            pending = next;
            if waited.timed_out() && *pending > 0 {
                return false;
            }
        }
        true
    }
}

impl AuditStore for BufferedAuditStore {
    fn record(&self, event: &shar_core::AuditEvent) -> Result<(), shar_core::StoreError> {
        let (lock, completed) = &*self.pending;
        {
            let mut pending = lock.lock().unwrap_or_else(|error| error.into_inner());
            *pending = pending.saturating_add(1);
        }
        if self.sender.try_send(event.clone()).is_err() {
            let mut pending = lock.lock().unwrap_or_else(|error| error.into_inner());
            *pending = pending.saturating_sub(1);
            if *pending == 0 {
                completed.notify_all();
            }
            self.metrics.audit_dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn list(
        &self,
        tenant: &str,
        site_key: &str,
        action: &str,
        limit: u32,
    ) -> Result<Vec<shar_core::AuditEvent>, shar_core::StoreError> {
        self.inner.list(tenant, site_key, action, limit)
    }
}

struct Admission {
    active: AtomicU64,
    maximum: u64,
}

impl Admission {
    fn new(maximum: u64) -> Self {
        Self {
            active: AtomicU64::new(0),
            maximum,
        }
    }

    fn try_enter(self: &Arc<Self>) -> Option<AdmissionPermit> {
        let mut active = self.active.load(Ordering::Relaxed);
        loop {
            if active >= self.maximum {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(AdmissionPermit(self.clone())),
                Err(observed) => active = observed,
            }
        }
    }
}

struct AdmissionPermit(Arc<Admission>);
impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Release);
    }
}

#[derive(Clone)]
struct TransportState {
    request_log: bool,
    admission: Arc<Admission>,
    allowed_origins: Arc<HashSet<String>>,
}

#[derive(Clone)]
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ListenAddress {
    host: String,
    port: u16,
}

fn parse_listen_address(value: &str) -> Result<ListenAddress, &'static str> {
    if value.is_empty() {
        return Err("SHAR_LISTEN must be a host:port address");
    }
    let (host, port_text) = if let Some(remainder) = value.strip_prefix('[') {
        let Some(closing) = remainder.find(']') else {
            return Err("SHAR_LISTEN must be a host:port address");
        };
        let host = &remainder[..closing];
        let suffix = &remainder[closing + 1..];
        let Some(port) = suffix.strip_prefix(':') else {
            return Err("SHAR_LISTEN must be a host:port address");
        };
        if host.is_empty() {
            return Err("SHAR_LISTEN must be a host:port address");
        }
        (host, port)
    } else {
        let Some((host, port)) = value.rsplit_once(':') else {
            return Err("SHAR_LISTEN must be a host:port address");
        };
        if host.is_empty() {
            return Err("SHAR_LISTEN must be a host:port address");
        }
        if host.contains(':') {
            return Err("IPv6 SHAR_LISTEN addresses must use brackets");
        }
        (host, port)
    };
    if port_text.is_empty()
        || port_text.starts_with('0')
        || !port_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("SHAR_LISTEN port must be an integer from 1 through 65535");
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| "SHAR_LISTEN port must be an integer from 1 through 65535")?;
    Ok(ListenAddress {
        host: host.to_owned(),
        port,
    })
}

const ALLOWED_ORIGINS_ERROR: &str =
    "SHAR_ALLOWED_ORIGINS must contain unique, canonical HTTPS origins or local HTTP origins";

fn parse_allowed_origins(value: &str) -> Result<HashSet<String>, &'static str> {
    let mut origins = HashSet::new();
    for origin in value.split(',') {
        if origin.is_empty() || origin.len() > 512 || origin.chars().any(char::is_control) {
            return Err(ALLOWED_ORIGINS_ERROR);
        }
        let parsed = url::Url::parse(origin).map_err(|_| ALLOWED_ORIGINS_ERROR)?;
        let local_http = parsed.scheme() == "http"
            && matches!(
                parsed.host_str(),
                Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
            );
        if parsed.origin().ascii_serialization() != origin
            || (parsed.scheme() != "https" && !local_http)
            || !origins.insert(origin.to_owned())
        {
            return Err(ALLOWED_ORIGINS_ERROR);
        }
    }
    if origins.is_empty() {
        return Err(ALLOWED_ORIGINS_ERROR);
    }
    Ok(origins)
}

#[tokio::main]
async fn main() {
    if env::args().nth(1).as_deref() == Some("--healthcheck") {
        std::process::exit(if healthcheck() { 0 } else { 1 })
    }
    let listen_text = env::var("SHAR_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listen = parse_listen_address(&listen_text).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let key_file = load_key_file().unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let (signing, time_lock) = load_keys(&key_file).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let network_secret = load_network_secret(&key_file).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let fallback_secret = load_fallback_secret(&key_file).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let presence = load_presence_plan(&key_file).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let fallback_plan =
        load_fallback_plan(&key_file, fallback_secret.is_some()).unwrap_or_else(|message| {
            eprintln!("{message}");
            std::process::exit(78)
        });
    let admin_secret = load_admin_secret(&key_file).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let siteverify_master_secret =
        load_siteverify_master_secret(&key_file).unwrap_or_else(|message| {
            eprintln!("{message}");
            std::process::exit(78)
        });
    let previous_keys = load_previous_verification_keys(&key_file).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let previous_time_locks = load_previous_time_locks(&key_file).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let trusted_proxies = load_trusted_proxy_cidrs().unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let trusted_assurance_header = load_assurance_mode(&key_file, !trusted_proxies.is_empty())
        .unwrap_or_else(|message| {
            eprintln!("{message}");
            std::process::exit(78)
        });
    let region = load_region(&key_file).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let trust_keys = load_trust_keys(&key_file).unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let trust_retention_seconds = configured("SHAR_TRUST_RETENTION_SECONDS", &key_file)
        .map(|value| value.parse::<u64>())
        .transpose()
        .unwrap_or_else(|_| {
            eprintln!("SHAR_TRUST_RETENTION_SECONDS must be an integer from 60 through 2592000");
            std::process::exit(78)
        })
        .unwrap_or(86_400);
    if !(60..=2_592_000).contains(&trust_retention_seconds) {
        eprintln!("SHAR_TRUST_RETENTION_SECONDS must be an integer from 60 through 2592000");
        std::process::exit(78)
    }
    let request_log = match env::var("SHAR_REQUEST_LOG").as_deref() {
        Ok("0") => false,
        Ok("1") | Err(env::VarError::NotPresent) => true,
        _ => {
            eprintln!("SHAR_REQUEST_LOG must be 0 or 1");
            std::process::exit(78)
        }
    };
    let max_concurrent_requests = env::var("SHAR_MAX_CONCURRENT_REQUESTS")
        .unwrap_or_else(|_| "256".into())
        .parse::<u64>()
        .ok()
        .filter(|value| (1..=65_536).contains(value))
        .unwrap_or_else(|| {
            eprintln!("SHAR_MAX_CONCURRENT_REQUESTS must be an integer from 1 through 65536");
            std::process::exit(78)
        });
    let state_timeout = env::var("SHAR_STATE_TIMEOUT_MS")
        .unwrap_or_else(|_| "5000".into())
        .parse::<u64>()
        .ok()
        .filter(|value| (100..=60_000).contains(value))
        .map(Duration::from_millis)
        .unwrap_or_else(|| {
            eprintln!("SHAR_STATE_TIMEOUT_MS must be an integer from 100 through 60000");
            std::process::exit(78)
        });
    let request_body_timeout = env::var("SHAR_REQUEST_BODY_TIMEOUT_MS")
        .unwrap_or_else(|_| "15000".into())
        .parse::<u64>()
        .ok()
        .filter(|value| (100..=60_000).contains(value))
        .map(Duration::from_millis)
        .unwrap_or_else(|| {
            eprintln!("SHAR_REQUEST_BODY_TIMEOUT_MS must be an integer from 100 through 60000");
            std::process::exit(78)
        });
    let shutdown_timeout = env::var("SHAR_SHUTDOWN_TIMEOUT_MS")
        .unwrap_or_else(|_| "25000".into())
        .parse::<u64>()
        .ok()
        .filter(|value| (6_000..=300_000).contains(value))
        .map(Duration::from_millis)
        .unwrap_or_else(|| {
            eprintln!("SHAR_SHUTDOWN_TIMEOUT_MS must be an integer from 6000 through 300000");
            std::process::exit(78)
        });
    let policy = default_work_policy();
    let allowed_origins = parse_allowed_origins(
        &env::var("SHAR_ALLOWED_ORIGINS").unwrap_or_else(|_| "http://localhost:3000".into()),
    )
    .unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(78)
    });
    let store_policy = policy.clone();
    let (nonces, pressure, config, audit) =
        tokio::task::spawn_blocking(move || load_stores(store_policy, state_timeout))
            .await
            .unwrap_or_else(|error| {
                eprintln!("cannot initialize blocking state worker: {error}");
                std::process::exit(78)
            });
    let metrics = Arc::new(Metrics::default());
    let buffered_audit = Arc::new(
        BufferedAuditStore::new(audit, metrics.clone()).unwrap_or_else(|error| {
            eprintln!("cannot start bounded audit worker: {error}");
            std::process::exit(78)
        }),
    );
    let audit: Arc<dyn AuditStore> = buffered_audit.clone();
    let mut engine = Engine::with_stores_and_rotation_and_audit(
        signing,
        time_lock,
        policy,
        nonces,
        pressure,
        config,
        previous_keys,
        previous_time_locks,
        Some(audit),
    );
    if !trust_keys.is_empty() {
        engine = engine
            .with_trust_keys(trust_keys, trust_retention_seconds)
            .unwrap_or_else(|_| {
                eprintln!("invalid trust-credit configuration");
                std::process::exit(78)
            });
    }
    engine = engine
        .with_browser_plans(presence, fallback_plan)
        .unwrap_or_else(|_| {
            eprintln!("invalid browser presence/fallback configuration");
            std::process::exit(78)
        });
    let admin_assets = canonical_admin_assets_root(
        &env::var("SHAR_ADMIN_ASSETS").unwrap_or_else(|_| "dist/admin".into()),
    )
    .unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(78)
    });
    let state = AppState {
        engine: Arc::new(engine),
        allowed_origins: Arc::new(allowed_origins),
        network_secret,
        fallback_secret,
        admin_secret,
        siteverify_master_secret,
        region,
        trusted_proxies: Arc::new(trusted_proxies),
        trusted_assurance_header,
        metrics,
        request_log,
        max_concurrent_requests,
        request_body_timeout,
        readiness_admission: Arc::new(Admission::new(1)),
        admin_assets: Arc::new(admin_assets),
    };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind((listen.host.as_str(), listen.port))
        .await
        .unwrap_or_else(|error| {
            eprintln!("cannot bind SHAR_LISTEN {listen_text}: {error}");
            std::process::exit(78)
        })
        .tap_io(|stream| {
            if let Err(error) = stream.set_nodelay(true) {
                eprintln!("cannot enable TCP_NODELAY on accepted connection: {error}");
            }
        });
    eprintln!("Shar server listening on {listen_text}");
    let (shutdown_started_tx, mut shutdown_started_rx) = tokio::sync::oneshot::channel();
    let shutdown_signal = async move {
        shutdown().await;
        let _ = shutdown_started_tx.send(());
    };
    let mut serve = Box::pin(
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal)
        .into_future(),
    );
    let graceful_budget = shutdown_timeout.saturating_sub(AUDIT_SHUTDOWN_TIMEOUT);
    let (serve_result, forced_shutdown) = tokio::select! {
        result = &mut serve => (result, false),
        Ok(()) = &mut shutdown_started_rx => {
            match tokio::time::timeout(graceful_budget, &mut serve).await {
                Ok(result) => (result, false),
                Err(_) => {
                    eprintln!("graceful request drain exceeded its bounded deadline");
                    (Ok(()), true)
                }
            }
        }
    };
    drop(serve);
    let flushed = tokio::task::spawn_blocking(move || buffered_audit.flush(AUDIT_SHUTDOWN_TIMEOUT))
        .await
        .unwrap_or(false);
    if !flushed {
        eprintln!("audit queue did not drain before the bounded shutdown deadline");
    }
    if let Err(error) = serve_result {
        eprintln!("Shar server stopped unexpectedly: {error}");
        std::process::exit(1)
    }
    if forced_shutdown {
        std::process::exit(1)
    }
}

fn load_stores(policy: WorkPolicy, state_timeout: Duration) -> StoreSet {
    let (mut nonces, mut pressure, config, mut audit): StoreSet = if let Ok(url) =
        env::var("SHAR_POSTGRES_URL")
    {
        let mut configuration = PostgresConfig::from_str(&url).unwrap_or_else(|error| {
            eprintln!("invalid SHAR_POSTGRES_URL: {error}");
            std::process::exit(78)
        });
        let postgres_tls = configuration.get_ssl_mode() == SslMode::Require;
        if !postgres_tls && env::var("SHAR_INSECURE_DEVELOPMENT").as_deref() != Ok("1") {
            eprintln!("SHAR_POSTGRES_URL must set sslmode=require outside insecure development");
            std::process::exit(78)
        }
        configuration
            .connect_timeout(state_timeout)
            .tcp_user_timeout(state_timeout);
        let timeout_ms = state_timeout.as_millis();
        let mut options = configuration.get_options().unwrap_or_default().to_owned();
        options.push_str(&format!(
                " -c statement_timeout={timeout_ms} -c lock_timeout={timeout_ms} -c idle_in_transaction_session_timeout={timeout_ms}"
            ));
        configuration.options(options.trim());
        let mut tls = native_tls::TlsConnector::builder();
        tls.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
        if let Ok(path) = env::var("SHAR_POSTGRES_CA_FILE") {
            let pem = std::fs::read(&path).unwrap_or_else(|error| {
                eprintln!("cannot read SHAR_POSTGRES_CA_FILE {path}: {error}");
                std::process::exit(78)
            });
            let certificate = native_tls::Certificate::from_pem(&pem).unwrap_or_else(|error| {
                eprintln!("invalid SHAR_POSTGRES_CA_FILE {path}: {error}");
                std::process::exit(78)
            });
            tls.add_root_certificate(certificate);
        }
        let connector = MakeTlsConnector::new(tls.build().unwrap_or_else(|error| {
            eprintln!("cannot configure PostgreSQL TLS: {error}");
            std::process::exit(78)
        }));
        let connect: Arc<dyn Fn() -> Result<PostgresClient, postgres::Error> + Send + Sync> =
            Arc::new(move || {
                if postgres_tls {
                    configuration.connect(connector.clone())
                } else {
                    configuration.connect(postgres::NoTls)
                }
            });
        let first = connect().unwrap_or_else(|error| {
            eprintln!("cannot connect to PostgreSQL: {error}");
            std::process::exit(78)
        });
        let mut additional = Vec::with_capacity(9);
        for _ in 1..10 {
            additional.push(connect().unwrap_or_else(|error| {
                eprintln!("cannot complete PostgreSQL connection pool: {error}");
                std::process::exit(78)
            }));
        }
        let store = Arc::new(
            PostgresStore::from_clients_with_reconnect(first, additional, policy.clone(), connect)
                .unwrap_or_else(|error| {
                    eprintln!("cannot initialize PostgreSQL state: {error}");
                    std::process::exit(78)
                }),
        );
        (store.clone(), store.clone(), store.clone(), store)
    } else {
        let database = env::var("SHAR_DATABASE").unwrap_or_else(|_| "shar.sqlite".into());
        let store = Arc::new(
            SqliteStore::open_with_timeout(&database, policy.clone(), state_timeout)
                .unwrap_or_else(|error| {
                    eprintln!("cannot open SQLite state at {database}: {error}");
                    std::process::exit(78)
                }),
        );
        (store.clone(), store.clone(), store.clone(), store)
    };
    if let Ok(url) = env::var("SHAR_REDIS_URL") {
        if !url.starts_with("rediss://")
            && env::var("SHAR_INSECURE_DEVELOPMENT").as_deref() != Ok("1")
        {
            eprintln!("SHAR_REDIS_URL must use rediss outside insecure development");
            std::process::exit(78)
        }
        let client = low_latency_client(&url).unwrap_or_else(|error| {
            eprintln!("invalid SHAR_REDIS_URL: {error}");
            std::process::exit(78)
        });
        let store = Arc::new(
            RedisStore::from_client(client, 10, 172_800, state_timeout).unwrap_or_else(|_| {
                eprintln!("cannot initialize Redis state");
                std::process::exit(78)
            }),
        );
        nonces = store.clone();
        pressure = store.clone();
        audit = store;
    }
    (nonces, pressure, config, audit)
}

fn healthcheck() -> bool {
    let configured = env::var("SHAR_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let Ok(listen) = parse_listen_address(&configured) else {
        return false;
    };
    let host = match listen.host.as_str() {
        "0.0.0.0" => "127.0.0.1",
        "::" => "::1",
        host => host,
    };
    let target = if host.contains(':') {
        format!("[{host}]:{}", listen.port)
    } else {
        format!("{host}:{}", listen.port)
    };
    let Ok(addresses) = target.to_socket_addrs() else {
        return false;
    };
    addresses.into_iter().any(healthcheck_address)
}

fn healthcheck_address(address: SocketAddr) -> bool {
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))
    else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    if stream
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    const READY_PREFIX: &[u8] = b"HTTP/1.1 200";
    let mut response = [0; 64];
    let mut length = 0;
    while length < READY_PREFIX.len() {
        match stream.read(&mut response[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(_) => return false,
        }
    }
    response[..length].starts_with(READY_PREFIX)
}

fn load_trusted_proxy_cidrs() -> Result<Vec<Cidr>, String> {
    let configured = env::var("SHAR_TRUSTED_PROXY_CIDRS").unwrap_or_default();
    configured
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            let (address, prefix) = value.trim().rsplit_once('/').ok_or_else(|| {
                "SHAR_TRUSTED_PROXY_CIDRS must contain comma-separated CIDRs".to_owned()
            })?;
            let network: IpAddr = address
                .parse()
                .map_err(|_| "SHAR_TRUSTED_PROXY_CIDRS contains an invalid CIDR".to_owned())?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| "SHAR_TRUSTED_PROXY_CIDRS contains an invalid CIDR".to_owned())?;
            let maximum = if network.is_ipv4() { 32 } else { 128 };
            if prefix > maximum {
                return Err("SHAR_TRUSTED_PROXY_CIDRS contains an invalid CIDR".into());
            }
            Ok(Cidr { network, prefix })
        })
        .collect()
}

fn client_address(remote: IpAddr, headers: &HeaderMap, trusted: &[Cidr]) -> IpAddr {
    let remote = normalize_ip(remote);
    if !trusted.iter().any(|cidr| cidr.contains(remote)) {
        return remote;
    }
    let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    else {
        return remote;
    };
    let Some(chain) = forwarded
        .split(',')
        .map(parse_forwarded_address)
        .collect::<Option<Vec<_>>>()
    else {
        return remote;
    };
    let mut current = remote;
    for address in chain.into_iter().rev() {
        if !trusted.iter().any(|cidr| cidr.contains(current)) {
            break;
        }
        current = address;
    }
    current
}

fn parse_forwarded_address(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    value
        .parse()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
        .or_else(|| value.strip_prefix('[')?.split_once(']')?.0.parse().ok())
        .map(normalize_ip)
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

impl Cidr {
    fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

fn router(state: AppState) -> Router {
    let transport = TransportState {
        request_log: state.request_log,
        admission: Arc::new(Admission::new(state.max_concurrent_requests)),
        allowed_origins: state.allowed_origins.clone(),
    };
    Router::new()
        .route("/admin", get(admin_redirect))
        .route("/admin/", get(admin_index))
        .route("/admin/{*path}", get(admin_asset))
        .route("/.well-known/shar/v1", get(well_known))
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/challenges", post(challenge).options(preflight))
        .route("/v1/challenges/redeem", post(redeem).options(preflight))
        .route("/v1/siteverify", post(siteverify))
        .route("/v1/fallback/complete", post(fallback))
        .route("/v1/admin/policy", get(admin_policy).put(set_admin_policy))
        .route("/v1/admin/audit", get(admin_audit))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(middleware::from_fn_with_state(transport, observe_request))
}

static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static REQUEST_ID_PREFIX: OnceLock<[u8; 8]> = OnceLock::new();

async fn observe_request(
    State(state): State<TransportState>,
    request: HttpRequest<Body>,
    next: Next,
) -> Response {
    let started = Instant::now();
    let method = observed_method(request.method().as_str());
    let route = observed_route(request.uri().path());
    let path = request.uri().path().to_owned();
    let request_id = new_request_id();
    let bypass = admission_bypass(request.method().as_str(), request.uri().path());
    let origin = request
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .filter(|value| state.allowed_origins.contains(*value))
        .map(str::to_owned);
    let permit = if bypass {
        None
    } else {
        state.admission.try_enter()
    };
    let mut response = if bypass || permit.is_some() {
        next.run(request).await
    } else {
        capacity_unavailable(origin.as_deref())
    };
    if matches!(path.as_str(), "/v1/challenges" | "/v1/challenges/redeem") {
        add_cors(&mut response, origin.as_deref());
    }
    if !response.headers().contains_key(header::CACHE_CONTROL) {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    if !response
        .headers()
        .contains_key(header::X_CONTENT_TYPE_OPTIONS)
    {
        response.headers_mut().insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
    }
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-shar-request-id", value);
    }
    if response
        .headers()
        .contains_key("access-control-allow-origin")
    {
        response.headers_mut().insert(
            "access-control-expose-headers",
            HeaderValue::from_static("X-Shar-Request-Id"),
        );
    }
    if state.request_log {
        eprintln!(
            "{}",
            json!({
                "version": "request-observation-v1",
                "request_id": request_id,
                "method": method,
                "route": route,
                "status": response.status().as_u16(),
                "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            })
        );
    }
    response
}

fn capacity_unavailable(origin: Option<&str>) -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "code": "capacity_unavailable",
            "retryable": true,
            "next_action": "retry",
            "retry_after": 1,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    add_cors(&mut response, origin);
    response
}

fn admission_bypass(method: &str, path: &str) -> bool {
    method == "GET" && matches!(path, "/healthz" | "/readyz" | "/metrics")
}

fn new_request_id() -> String {
    let prefix = REQUEST_ID_PREFIX.get_or_init(|| {
        let mut bytes = [0_u8; 8];
        if getrandom::fill(&mut bytes).is_err() {
            bytes[..4].copy_from_slice(&std::process::id().to_be_bytes());
            bytes[4..].copy_from_slice(&(now() as u32).to_be_bytes());
        }
        bytes
    });
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(prefix);
    bytes[8..].copy_from_slice(
        &REQUEST_ID_COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes(),
    );
    URL_SAFE_NO_PAD.encode(bytes)
}

fn observed_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        "PATCH" => "PATCH",
        _ => "OTHER",
    }
}

fn observed_route(path: &str) -> &'static str {
    match path {
        "/.well-known/shar/v1" => "/.well-known/shar/v1",
        "/healthz" => "/healthz",
        "/readyz" => "/readyz",
        "/metrics" => "/metrics",
        "/v1/challenges" => "/v1/challenges",
        "/v1/challenges/redeem" => "/v1/challenges/redeem",
        "/v1/siteverify" => "/v1/siteverify",
        "/v1/fallback/complete" => "/v1/fallback/complete",
        "/v1/admin/policy" => "/v1/admin/policy",
        "/v1/admin/audit" => "/v1/admin/audit",
        "/admin" | "/admin/" => "/admin/*",
        _ if path.starts_with("/admin/") => "/admin/*",
        _ => "unmatched",
    }
}

async fn admin_redirect() -> Redirect {
    Redirect::permanent("/admin/")
}

async fn admin_index(State(state): State<AppState>) -> Response {
    admin_file(&state.admin_assets, "index.html", false).await
}

async fn admin_asset(State(state): State<AppState>, AxumPath(path): AxumPath<String>) -> Response {
    if path.is_empty() {
        return admin_file(&state.admin_assets, "index.html", false).await;
    }
    let candidate = PathBuf::from(&path);
    if candidate
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return not_found().await.into_response();
    }
    admin_file(&state.admin_assets, &path, true).await
}

fn canonical_admin_assets_root(configured: &str) -> Result<PathBuf, String> {
    let root = std::fs::canonicalize(configured)
        .map_err(|error| format!("cannot read SHAR_ADMIN_ASSETS {configured}: {error}"))?;
    if root.parent().is_none() {
        return Err("SHAR_ADMIN_ASSETS must not be a filesystem root".into());
    }
    if !root.is_dir() {
        return Err("SHAR_ADMIN_ASSETS must name an existing directory".into());
    }
    Ok(root)
}

async fn admin_file(root: &Path, relative: &str, immutable: bool) -> Response {
    let Ok(path) = tokio::fs::canonicalize(root.join(relative)).await else {
        return not_found().await.into_response();
    };
    if path == root || !path.starts_with(root) {
        return not_found().await.into_response();
    }
    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        return not_found().await.into_response();
    };
    if !metadata.is_file() {
        return not_found().await.into_response();
    }
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return not_found().await.into_response();
    };
    let content_type = match path.extension().and_then(|value| value.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("map") | Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    };
    let mut response = (StatusCode::OK, bytes).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

#[cfg(unix)]
async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {_ = tokio::signal::ctrl_c()=>{},_ = terminate.recv()=>{}}
}
#[cfg(not(unix))]
async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
async fn health() -> Response {
    (
        [("cache-control", "no-store")],
        Json(json!({"status":"ok"})),
    )
        .into_response()
}

async fn ready(State(state): State<AppState>) -> Result<Response, ApiError> {
    let _permit = state.readiness_admission.try_enter().ok_or_else(|| {
        ApiError::new(
            SharError {
                status: 503,
                code: "readiness_unavailable",
                retryable: true,
                next_action: "retry",
                retry_after: Some(1),
            },
            None,
        )
    })?;
    let engine = state.engine.clone();
    blocking_engine(None, move || engine.ready()).await?;
    Ok((
        [("cache-control", "no-store")],
        Json(json!({"status":"ready"})),
    )
        .into_response())
}

async fn metrics(State(state): State<AppState>) -> Response {
    let engine_duration =
        duration_seconds(state.metrics.issue_engine_micros.load(Ordering::Relaxed));
    let handler_duration =
        duration_seconds(state.metrics.issue_handler_micros.load(Ordering::Relaxed));
    let body = format!(
        "# HELP shar_challenges_issued_total Successfully issued work quotes.\n# TYPE shar_challenges_issued_total counter\nshar_challenges_issued_total {}\n# HELP shar_challenge_engine_duration_seconds_total Cumulative successful challenge pricing and construction time, including blocking-worker scheduling.\n# TYPE shar_challenge_engine_duration_seconds_total counter\nshar_challenge_engine_duration_seconds_total {engine_duration}\n# HELP shar_challenge_handler_duration_seconds_total Cumulative successful challenge HTTP handler time through response serialization.\n# TYPE shar_challenge_handler_duration_seconds_total counter\nshar_challenge_handler_duration_seconds_total {handler_duration}\n# HELP shar_challenges_redeemed_total Successfully redeemed work quotes.\n# TYPE shar_challenges_redeemed_total counter\nshar_challenges_redeemed_total {}\n# HELP shar_site_verifications_total Successfully consumed verification tokens.\n# TYPE shar_site_verifications_total counter\nshar_site_verifications_total {}\n# HELP shar_fallback_completions_total Successfully consumed privileged fallback assertions.\n# TYPE shar_fallback_completions_total counter\nshar_fallback_completions_total {}\n# HELP shar_audit_events_dropped_total Privacy-filtered audit events dropped because the bounded queue was full or storage failed.\n# TYPE shar_audit_events_dropped_total counter\nshar_audit_events_dropped_total {}\n",
        state.metrics.issued.load(Ordering::Relaxed),
        state.metrics.redeemed.load(Ordering::Relaxed),
        state.metrics.verified.load(Ordering::Relaxed),
        state.metrics.fallback.load(Ordering::Relaxed),
        state.metrics.audit_dropped.load(Ordering::Relaxed),
    );
    (
        [
            ("content-type", "text/plain; version=0.0.4; charset=utf-8"),
            ("cache-control", "no-store"),
        ],
        body,
    )
        .into_response()
}

fn duration_seconds(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

fn record_duration(counter: &AtomicU64, duration: Duration) {
    counter.fetch_add(
        u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

#[derive(Deserialize)]
struct AdminScope {
    tenant: String,
    site_key: String,
    action: String,
}

#[derive(Deserialize)]
struct AdminAuditScope {
    tenant: Option<String>,
    site_key: Option<String>,
    action: Option<String>,
    limit: Option<String>,
}

fn load_region(file: &HashMap<String, String>) -> Result<Option<String>, String> {
    let Some(value) = configured("SHAR_REGION", file).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 64 || value.chars().any(char::is_control) {
        return Err("SHAR_REGION must be a non-control value of at most 64 bytes".into());
    }
    Ok(Some(value))
}

#[derive(Deserialize)]
struct AdminPolicyDocument {
    tenant: String,
    site_key: String,
    action: String,
    policy: AdminPolicyValues,
}

#[derive(Deserialize)]
struct AdminPolicyValues {
    version: String,
    base_iterations: String,
    base_render_rounds: u32,
    quiet_window_seconds: u64,
    base_lifetime_seconds: u64,
    iteration_allowance: String,
    round_allowance_seconds: u64,
    max_lifetime_seconds: u64,
}

fn admin_authorized(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(secret) = state.admin_secret else {
        return Err(ApiError::new(error(404, "not_found", false, "none"), None));
    };
    let expected = format!("Bearer {}", URL_SAFE_NO_PAD.encode(secret));
    let provided = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !constant_time_equal(provided.as_bytes(), expected.as_bytes()) {
        return Err(ApiError::new(
            error(401, "admin_unauthorized", false, "none"),
            None,
        ));
    }
    Ok(())
}

fn admin_policy_value(scope: &AdminScope, policy: &WorkPolicy) -> Value {
    json!({
        "tenant":scope.tenant,
        "site_key":scope.site_key,
        "action":scope.action,
        "policy":{
            "version":policy.version,
            "base_iterations":policy.base_iterations.to_string(),
            "base_render_rounds":policy.base_render_rounds,
            "quiet_window_seconds":policy.quiet_window_seconds,
            "base_lifetime_seconds":policy.base_lifetime_seconds,
            "iteration_allowance":policy.iteration_allowance.to_string(),
            "round_allowance_seconds":policy.round_allowance_seconds,
            "max_lifetime_seconds":policy.max_lifetime_seconds,
        }
    })
}

async fn admin_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(scope): Query<AdminScope>,
) -> Result<Json<Value>, ApiError> {
    admin_authorized(&state, &headers)?;
    let engine = state.engine.clone();
    let tenant = scope.tenant.clone();
    let site_key = scope.site_key.clone();
    let action = scope.action.clone();
    let policy = blocking_engine(None, move || {
        engine.admin_policy(&tenant, &site_key, &action)
    })
    .await?;
    Ok(Json(admin_policy_value(&scope, &policy)))
}

async fn admin_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(scope): Query<AdminAuditScope>,
) -> Result<Json<Value>, ApiError> {
    admin_authorized(&state, &headers)?;
    let limit = scope
        .limit
        .as_deref()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| ApiError::new(error(400, "invalid_audit_limit", false, "none"), None))
        })
        .transpose()?
        .unwrap_or(100);
    let tenant = scope.tenant.unwrap_or_default();
    let site_key = scope.site_key.unwrap_or_default();
    let action = scope.action.unwrap_or_default();
    let engine = state.engine.clone();
    let audit_tenant = tenant.clone();
    let audit_site_key = site_key.clone();
    let audit_action = action.clone();
    let events = blocking_engine(None, move || {
        engine.admin_audit(&audit_tenant, &audit_site_key, &audit_action, limit)
    })
    .await?;
    Ok(Json(json!({
        "tenant": tenant,
        "site_key": site_key,
        "action": action,
        "events": events,
    })))
}

async fn set_admin_policy(
    State(state): State<AppState>,
    request: HttpRequest<Body>,
) -> Result<Json<Value>, ApiError> {
    let (headers, bytes) = read_body(request, state.request_body_timeout).await?;
    admin_authorized(&state, &headers)?;
    let document: AdminPolicyDocument = parse_json(&headers, &bytes, None)?;
    let policy = WorkPolicy {
        version: document.policy.version,
        base_iterations: document
            .policy
            .base_iterations
            .parse()
            .map_err(|_| ApiError::new(error(400, "invalid_policy", false, "none"), None))?,
        base_render_rounds: document.policy.base_render_rounds,
        quiet_window_seconds: document.policy.quiet_window_seconds,
        base_lifetime_seconds: document.policy.base_lifetime_seconds,
        iteration_allowance: document
            .policy
            .iteration_allowance
            .parse()
            .map_err(|_| ApiError::new(error(400, "invalid_policy", false, "none"), None))?,
        round_allowance_seconds: document.policy.round_allowance_seconds,
        max_lifetime_seconds: document.policy.max_lifetime_seconds,
    };
    let engine = state.engine.clone();
    let tenant = document.tenant.clone();
    let site_key = document.site_key.clone();
    let action = document.action.clone();
    let policy_to_write = policy.clone();
    blocking_engine(None, move || {
        engine.set_admin_policy(&tenant, &site_key, &action, &policy_to_write)
    })
    .await?;
    let scope = AdminScope {
        tenant: document.tenant,
        site_key: document.site_key,
        action: document.action,
    };
    Ok(Json(admin_policy_value(&scope, &policy)))
}

async fn well_known(State(engine): State<AppState>) -> Json<Value> {
    let keys: Vec<Value> = engine
        .engine
        .verification_keys()
        .into_iter()
        .map(|key| {
            json!({
                "kid": URL_SAFE_NO_PAD.encode(key.key_id), "kty":"OKP", "crv":"Ed25519",
                "x": URL_SAFE_NO_PAD.encode(key.public_key), "use":"sig"
            })
        })
        .collect();
    let trust: Vec<Value> = engine
        .engine
        .trust_keys()
        .into_iter()
        .map(|(key_id, public_key)| {
            json!({
                "suite": shar_core::trust::TRUST_VOPRF_SUITE,
                "kid": URL_SAFE_NO_PAD.encode(key_id),
                "kty": "OKP",
                "crv": "Ristretto255",
                "x": URL_SAFE_NO_PAD.encode(public_key),
                "use": "trust",
            })
        })
        .collect();
    let mut document = json!({"version":"shar-v1","algorithms":["Ed25519","RSW-2048","render-v1"],"keys":keys,"modulus_id":engine.engine.time_lock.id,"modulus_ids":engine.engine.time_lock_ids()});
    if !trust.is_empty() {
        document["trust"] = trust.into();
    }
    Json(document)
}

fn trusted_assurance_tier(
    headers: &HeaderMap,
    origin: Option<String>,
) -> Result<Option<u8>, ApiError> {
    let mut values = headers.get_all("x-shar-assurance-tier").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    let invalid = || {
        ApiError::new(
            error(400, "invalid_assurance_tier", false, "none"),
            origin.clone(),
        )
    };
    if values.next().is_some() {
        return Err(invalid());
    }
    let value = value.to_str().map_err(|_| invalid())?;
    if value.is_empty()
        || value.len() > 2
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid());
    }
    value
        .parse::<u8>()
        .ok()
        .filter(|tier| *tier <= 32)
        .map(Some)
        .ok_or_else(invalid)
}

async fn challenge(
    State(state): State<AppState>,
    request: HttpRequest<Body>,
) -> Result<Response, ApiError> {
    let handler_started = Instant::now();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied();
    let (headers, bytes) = read_body(request, state.request_body_timeout).await?;
    let origin = cors_origin(&state, &headers, true)?;
    let mut parsed: ChallengeRequest = parse_json(&headers, &bytes, origin.clone())?;
    parsed.region = state.region.clone();
    let trusted_peer = peer
        .as_ref()
        .map(|ConnectInfo(address)| {
            state
                .trusted_proxies
                .iter()
                .any(|cidr| cidr.contains(normalize_ip(address.ip())))
        })
        .unwrap_or(false);
    parsed.session_binding = if trusted_peer {
        headers
            .get("x-shar-session-binding")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    } else {
        None
    };
    parsed.assurance_tier = if state.trusted_assurance_header && trusted_peer {
        trusted_assurance_tier(&headers, origin.clone())?
    } else {
        None
    };
    let issued_at = now();
    let network_scope = format!("{}\0{}", parsed.tenant, parsed.site_key);
    parsed.network_pseudonym = peer.map(|ConnectInfo(address)| {
        let address = client_address(address.ip(), &headers, state.trusted_proxies.as_slice());
        let scope = format!("{network_scope}\0{address}");
        URL_SAFE_NO_PAD.encode(
            daily_network_pseudonym(&state.network_secret, scope.as_bytes(), issued_at)
                .expect("fixed HMAC key"),
        )
    });
    if origin.as_deref() != Some(parsed.origin.as_str()) {
        return Err(ApiError::new(
            error(400, "origin_mismatch", false, "none"),
            origin,
        ));
    }
    let mut random = [0; 48];
    getrandom::fill(&mut random).map_err(|_| internal(origin.clone()))?;
    let mut nonce = [0; 16];
    nonce.copy_from_slice(&random[..16]);
    let mut seed = [0; 32];
    seed.copy_from_slice(&random[16..]);
    let engine = state.engine.clone();
    let engine_started = Instant::now();
    let response = blocking_engine(origin.clone(), move || {
        engine.issue(&parsed, issued_at, nonce, seed)
    })
    .await?;
    record_duration(&state.metrics.issue_engine_micros, engine_started.elapsed());
    state.metrics.issued.fetch_add(1, Ordering::Relaxed);
    let mut response = Json(response).into_response();
    add_cors(&mut response, origin.as_deref());
    record_duration(
        &state.metrics.issue_handler_micros,
        handler_started.elapsed(),
    );
    Ok(response)
}

async fn redeem(
    State(state): State<AppState>,
    request: HttpRequest<Body>,
) -> Result<Response, ApiError> {
    let (headers, bytes) = read_body(request, state.request_body_timeout).await?;
    let origin = cors_origin(&state, &headers, false)?;
    let parsed: RedeemRequest = parse_json(&headers, &bytes, origin.clone())?;
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| internal(origin.clone()))?;
    let engine = state.engine.clone();
    let completed_at = now();
    let result = blocking_engine(origin.clone(), move || {
        engine.redeem(&parsed, completed_at, nonce)
    })
    .await?;
    state.metrics.redeemed.fetch_add(1, Ordering::Relaxed);
    let mut response = Json(result).into_response();
    add_cors(&mut response, origin.as_deref());
    Ok(response)
}
async fn siteverify(
    State(state): State<AppState>,
    request: HttpRequest<Body>,
) -> Result<Json<Value>, ApiError> {
    let (headers, bytes) = read_body(request, state.request_body_timeout).await?;
    let form = is_form(&headers);
    let Some(master) = state.siteverify_master_secret else {
        return Err(ApiError::new(
            error(501, "siteverify_not_configured", false, "none"),
            None,
        ));
    };
    let (mut parsed, secret) = parse_verify(&headers, &bytes)?;
    let Some((tenant, site_key)) =
        verify_site_verify_secret(&master, &secret).map_err(|_| internal(None))?
    else {
        return Err(ApiError::new(
            error(401, "siteverify_unauthorized", false, "none"),
            None,
        ));
    };
    if parsed.tenant.as_ref().is_some_and(|value| value != &tenant)
        || parsed
            .site_key
            .as_ref()
            .is_some_and(|value| value != &site_key)
    {
        return Err(ApiError::new(
            error(401, "siteverify_unauthorized", false, "none"),
            None,
        ));
    }
    parsed.tenant = Some(tenant);
    parsed.site_key = Some(site_key);
    let engine = state.engine.clone();
    let verified_at = now();
    let result = blocking_engine(None, move || engine.siteverify(&parsed, verified_at)).await?;
    state.metrics.verified.fetch_add(1, Ordering::Relaxed);
    let mut value = serde_json::to_value(result).map_err(|_| internal(None))?;
    if form {
        value
            .as_object_mut()
            .expect("serialized struct")
            .insert("score".into(), json!(1.0));
    }
    Ok(Json(value))
}

async fn preflight(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let origin = cors_origin(&state, &headers, true)?;
    if headers
        .get("access-control-request-method")
        .and_then(|v| v.to_str().ok())
        != Some("POST")
    {
        return Err(ApiError::new(
            error(400, "invalid_preflight", false, "none"),
            origin,
        ));
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors(&mut response, origin.as_deref());
    response.headers_mut().insert(
        "access-control-allow-methods",
        "POST".parse().expect("static"),
    );
    response.headers_mut().insert(
        "access-control-allow-headers",
        "Content-Type".parse().expect("static"),
    );
    response
        .headers_mut()
        .insert("access-control-max-age", "600".parse().expect("static"));
    Ok(response)
}

const MAX_BODY_BYTES: usize = 16_384;
async fn read_body(
    request: HttpRequest<Body>,
    timeout: Duration,
) -> Result<(HeaderMap, Bytes), ApiError> {
    let (parts, body) = request.into_parts();
    let bytes = tokio::time::timeout(timeout, to_bytes(body, MAX_BODY_BYTES))
        .await
        .map_err(|_| {
            let mut timeout_error = error(408, "request_body_timeout", true, "retry");
            timeout_error.retry_after = Some(1);
            ApiError::new(timeout_error, None)
        })?
        .map_err(|_| ApiError::new(error(413, "body_too_large", false, "none"), None))?;
    Ok((parts.headers, bytes))
}
fn content_type(headers: &HeaderMap) -> &str {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .unwrap_or("")
        .trim()
}
fn is_form(headers: &HeaderMap) -> bool {
    content_type(headers) == "application/x-www-form-urlencoded"
}
fn parse_json<T: DeserializeOwned>(
    headers: &HeaderMap,
    bytes: &[u8],
    origin: Option<String>,
) -> Result<T, ApiError> {
    if content_type(headers) != "application/json" {
        return Err(ApiError::new(
            error(415, "unsupported_media_type", false, "none"),
            origin,
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| ApiError::new(error(400, "malformed_json", false, "none"), origin))
}
fn parse_verify(
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<(SiteVerifyRequest, String), ApiError> {
    if is_form(headers) {
        let values: HashMap<String, String> = serde_urlencoded::from_bytes(bytes)
            .map_err(|_| ApiError::new(error(400, "malformed_body", false, "none"), None))?;
        let token = values
            .get("token")
            .or_else(|| values.get("response"))
            .or_else(|| values.get("h-captcha-response"))
            .or_else(|| values.get("g-recaptcha-response"))
            .cloned()
            .ok_or_else(|| {
                ApiError::new(error(400, "token_required", false, "new_challenge"), None)
            })?;
        let secret = values.get("secret").cloned().ok_or_else(|| {
            ApiError::new(error(401, "siteverify_unauthorized", false, "none"), None)
        })?;
        Ok((
            SiteVerifyRequest {
                token,
                tenant: values.get("tenant").cloned(),
                site_key: values.get("site_key").cloned(),
                action: values.get("action").cloned(),
                origin: values.get("origin").cloned(),
                region: values.get("region").cloned(),
                session_binding: values.get("session_binding").cloned(),
            },
            secret,
        ))
    } else {
        let values: HashMap<String, Value> = parse_json(headers, bytes, None)?;
        let text = |key: &str| values.get(key).and_then(Value::as_str).map(str::to_owned);
        let token = [
            "token",
            "response",
            "h-captcha-response",
            "g-recaptcha-response",
        ]
        .into_iter()
        .find_map(text)
        .ok_or_else(|| ApiError::new(error(400, "token_required", false, "new_challenge"), None))?;
        let secret = text("secret").ok_or_else(|| {
            ApiError::new(error(401, "siteverify_unauthorized", false, "none"), None)
        })?;
        Ok((
            SiteVerifyRequest {
                token,
                tenant: text("tenant"),
                site_key: text("site_key"),
                action: text("action"),
                origin: text("origin"),
                region: text("region"),
                session_binding: text("session_binding"),
            },
            secret,
        ))
    }
}
fn cors_origin(
    state: &AppState,
    headers: &HeaderMap,
    required: bool,
) -> Result<Option<String>, ApiError> {
    let origin = headers.get("origin").and_then(|v| v.to_str().ok());
    match origin {
        None if required => Err(ApiError::new(
            error(400, "origin_required", false, "none"),
            None,
        )),
        None => Ok(None),
        Some(value) if state.allowed_origins.contains(value) => Ok(Some(value.to_owned())),
        Some(_) => Err(ApiError::new(
            error(400, "origin_not_configured", false, "none"),
            None,
        )),
    }
}
fn add_cors(response: &mut Response, origin: Option<&str>) {
    if let Some(origin) = origin
        && let Ok(value) = origin.parse()
    {
        response
            .headers_mut()
            .insert("access-control-allow-origin", value);
        response
            .headers_mut()
            .insert("vary", "Origin".parse().expect("static"));
    }
}
fn error(status: u16, code: &'static str, retryable: bool, next_action: &'static str) -> SharError {
    SharError {
        status,
        code,
        retryable,
        next_action,
        retry_after: None,
    }
}
async fn fallback(
    State(state): State<AppState>,
    request: HttpRequest<Body>,
) -> Result<Json<Value>, ApiError> {
    let Some(secret) = state.fallback_secret else {
        return Err(ApiError::new(
            error(501, "fallback_not_configured", false, "fallback"),
            None,
        ));
    };
    let (headers, bytes) = read_body(request, state.request_body_timeout).await?;
    let expected = format!("Bearer {}", URL_SAFE_NO_PAD.encode(secret));
    let provided = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !constant_time_equal(provided.as_bytes(), expected.as_bytes()) {
        return Err(ApiError::new(
            error(401, "fallback_unauthorized", false, "none"),
            None,
        ));
    }
    let parsed: FallbackCompletionRequest = parse_json(&headers, &bytes, None)?;
    let engine = state.engine.clone();
    let completed_at = now();
    let result = blocking_engine(None, move || {
        engine.complete_fallback(&parsed, completed_at)
    })
    .await?;
    state.metrics.fallback.fetch_add(1, Ordering::Relaxed);
    Ok(Json(
        serde_json::to_value(result).map_err(|_| internal(None))?,
    ))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}
async fn not_found() -> ApiError {
    ApiError::new(error(404, "not_found", false, "none"), None)
}
async fn method_not_allowed() -> ApiError {
    ApiError::new(error(405, "method_not_allowed", false, "none"), None)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs()
}
fn internal(origin: Option<String>) -> ApiError {
    ApiError::new(
        SharError {
            status: 500,
            code: "internal_error",
            retryable: true,
            next_action: "retry",
            retry_after: None,
        },
        origin,
    )
}

async fn blocking_engine<T, F>(origin: Option<String>, operation: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, SharError> + Send + 'static,
{
    let join_origin = origin.clone();
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| internal(join_origin))?
        .map_err(|error| ApiError::new(error, origin))
}

struct ApiError {
    error: SharError,
    origin: Option<String>,
}
impl ApiError {
    fn new(error: SharError, origin: Option<String>) -> Self {
        Self { error, origin }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut value = json!({"code":self.error.code,"retryable":self.error.retryable,"next_action":self.error.next_action});
        if let Some(retry_after) = self.error.retry_after {
            value["retry_after"] = retry_after.into();
        }
        let body = Json(value);
        let mut response = (status, [("cache-control", "no-store")], body).into_response();
        if let Some(retry_after) = self.error.retry_after
            && let Ok(value) = retry_after.to_string().parse()
        {
            response.headers_mut().insert("retry-after", value);
        }
        add_cors(&mut response, self.origin.as_deref());
        response
    }
}

fn load_key_file() -> Result<HashMap<String, String>, String> {
    let Some(path) = env::var_os("SHAR_KEY_FILE") else {
        return Ok(HashMap::new());
    };
    let metadata = std::fs::metadata(&path)
        .map_err(|error| format!("cannot inspect SHAR_KEY_FILE: {error}"))?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("SHAR_KEY_FILE must not be accessible by group or other users".into());
    }
    let bytes =
        std::fs::read(&path).map_err(|error| format!("cannot read SHAR_KEY_FILE: {error}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| "SHAR_KEY_FILE must contain a JSON object of string values".into())
}
fn configured(name: &str, file: &HashMap<String, String>) -> Option<String> {
    env::var(name).ok().or_else(|| file.get(name).cloned())
}
fn load_network_secret(file: &HashMap<String, String>) -> Result<[u8; 32], String> {
    if let Some(value) = configured("SHAR_NETWORK_SECRET", file) {
        return URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| "SHAR_NETWORK_SECRET must be base64url".to_owned())?
            .try_into()
            .map_err(|_| "SHAR_NETWORK_SECRET must decode to 32 bytes".to_owned());
    }
    if env::var("SHAR_INSECURE_DEVELOPMENT").as_deref() != Ok("1") {
        return Err("SHAR_NETWORK_SECRET is required".into());
    }
    let mut secret = [0; 32];
    getrandom::fill(&mut secret)
        .map_err(|_| "operating-system randomness is required".to_owned())?;
    Ok(secret)
}

fn load_fallback_secret(file: &HashMap<String, String>) -> Result<Option<[u8; 32]>, String> {
    let Some(value) = configured("SHAR_FALLBACK_SECRET", file) else {
        return Ok(None);
    };
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "SHAR_FALLBACK_SECRET must be base64url".to_owned())?
        .try_into()
        .map(Some)
        .map_err(|_| "SHAR_FALLBACK_SECRET must decode to 32 bytes".to_owned())
}

fn load_presence_plan(file: &HashMap<String, String>) -> Result<PresencePlan, String> {
    match configured("SHAR_PRESENCE_MODE", file).as_deref() {
        None | Some("none") => Ok(PresencePlan::None),
        Some("host") => Ok(PresencePlan::Host),
        Some(_) => Err("SHAR_PRESENCE_MODE must be none or host".into()),
    }
}

fn load_assurance_mode(
    file: &HashMap<String, String>,
    has_trusted_proxy: bool,
) -> Result<bool, String> {
    match configured("SHAR_ASSURANCE_MODE", file).as_deref() {
        None | Some("off") => Ok(false),
        Some("trusted-header") if has_trusted_proxy => Ok(true),
        Some("trusted-header") => {
            Err("SHAR_ASSURANCE_MODE=trusted-header requires SHAR_TRUSTED_PROXY_CIDRS".into())
        }
        Some(_) => Err("SHAR_ASSURANCE_MODE must be off or trusted-header".into()),
    }
}

fn load_fallback_plan(
    file: &HashMap<String, String>,
    enabled: bool,
) -> Result<FallbackPlan, String> {
    let configured_methods = configured("SHAR_FALLBACK_METHODS", file);
    if !enabled {
        if configured_methods.is_some() {
            return Err("SHAR_FALLBACK_METHODS requires SHAR_FALLBACK_SECRET".into());
        }
        return Ok(FallbackPlan {
            available: false,
            methods: Vec::new(),
        });
    }
    let text =
        configured_methods.unwrap_or_else(|| "passkey,email,authenticated-session,support".into());
    Ok(FallbackPlan {
        available: true,
        methods: text
            .split(',')
            .map(|method| method.trim().to_owned())
            .collect(),
    })
}

fn load_admin_secret(file: &HashMap<String, String>) -> Result<Option<[u8; 32]>, String> {
    let Some(value) = configured("SHAR_ADMIN_SECRET", file) else {
        return Ok(None);
    };
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "SHAR_ADMIN_SECRET must be base64url".to_owned())?
        .try_into()
        .map(Some)
        .map_err(|_| "SHAR_ADMIN_SECRET must decode to 32 bytes".to_owned())
}

fn load_siteverify_master_secret(
    file: &HashMap<String, String>,
) -> Result<Option<[u8; 32]>, String> {
    let Some(value) = configured("SHAR_SITEVERIFY_MASTER_SECRET", file) else {
        if env::var("SHAR_INSECURE_DEVELOPMENT").as_deref() == Ok("1") {
            return Ok(None);
        }
        return Err("SHAR_SITEVERIFY_MASTER_SECRET is required".into());
    };
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "SHAR_SITEVERIFY_MASTER_SECRET must be base64url".to_owned())?
        .try_into()
        .map(Some)
        .map_err(|_| "SHAR_SITEVERIFY_MASTER_SECRET must decode to 32 bytes".to_owned())
}

#[derive(Deserialize)]
struct PreviousKey {
    kid: String,
    x: String,
}
fn load_previous_verification_keys(
    file: &HashMap<String, String>,
) -> Result<Vec<VerificationMaterial>, String> {
    let Some(json) = configured("SHAR_PREVIOUS_VERIFY_KEYS", file) else {
        return Ok(Vec::new());
    };
    let values: Vec<PreviousKey> = serde_json::from_str(&json).map_err(|_| {
        "SHAR_PREVIOUS_VERIFY_KEYS must be a JSON array of {kid,x} base64url strings".to_owned()
    })?;
    values
        .into_iter()
        .map(|value| {
            let key_id = URL_SAFE_NO_PAD
                .decode(value.kid)
                .map_err(|_| "previous kid must be base64url".to_owned())?;
            if key_id.is_empty() || key_id.len() > 32 {
                return Err("previous kid must decode to 1..32 bytes".into());
            }
            let public_key: [u8; 32] = URL_SAFE_NO_PAD
                .decode(value.x)
                .map_err(|_| "previous x must be base64url".to_owned())?
                .try_into()
                .map_err(|_| "previous x must decode to 32 bytes".to_owned())?;
            Ok(VerificationMaterial { key_id, public_key })
        })
        .collect()
}

#[derive(Deserialize)]
struct PreviousTimeLock {
    id: String,
    modulus: String,
    lambda: String,
}
fn load_previous_time_locks(file: &HashMap<String, String>) -> Result<Vec<TimeLockKey>, String> {
    let Some(json) = configured("SHAR_PREVIOUS_RSW_KEYS", file) else {
        return Ok(Vec::new());
    };
    let values: Vec<PreviousTimeLock> = serde_json::from_str(&json).map_err(|_| {
        "SHAR_PREVIOUS_RSW_KEYS must be a JSON array of {id,modulus,lambda} strings".to_owned()
    })?;
    values
        .into_iter()
        .map(|value| {
            let modulus = BigUint::from_bytes_be(
                &URL_SAFE_NO_PAD
                    .decode(value.modulus)
                    .map_err(|_| "previous RSW modulus must be base64url".to_owned())?,
            );
            let lambda = BigUint::from_bytes_be(
                &URL_SAFE_NO_PAD
                    .decode(value.lambda)
                    .map_err(|_| "previous RSW lambda must be base64url".to_owned())?,
            );
            if modulus.bits() != 2048
                || modulus.is_even()
                || lambda <= BigUint::from(1_u8)
                || lambda >= modulus
                || value.id.is_empty()
                || value.id.len() > 64
            {
                return Err("previous RSW keys require an odd 2048-bit modulus, 1 < lambda < modulus, and a 1..64 byte id".into());
            }
            let key = TimeLockKey {
                id: value.id,
                modulus,
                lambda,
            };
            if !validate_time_lock_key(&key) {
                return Err("previous RSW trapdoor is inconsistent with its modulus".into());
            }
            Ok(key)
        })
        .collect()
}

fn load_keys(file: &HashMap<String, String>) -> Result<(SigningMaterial, TimeLockKey), String> {
    let configured = (
        configured("SHAR_SIGNING_SEED", file),
        configured("SHAR_KEY_ID", file),
        configured("SHAR_RSW_MODULUS", file),
        configured("SHAR_RSW_LAMBDA", file),
        configured("SHAR_RSW_ID", file),
    );
    if let (Some(seed), Some(key_id), Some(modulus), Some(lambda), Some(id)) = configured {
        let seed: [u8; 32] = URL_SAFE_NO_PAD
            .decode(seed)
            .map_err(|_| "SHAR_SIGNING_SEED must be base64url".to_owned())?
            .try_into()
            .map_err(|_| "SHAR_SIGNING_SEED must decode to 32 bytes".to_owned())?;
        let key_id = URL_SAFE_NO_PAD
            .decode(key_id)
            .map_err(|_| "SHAR_KEY_ID must be base64url".to_owned())?;
        if key_id.is_empty() || key_id.len() > 32 {
            return Err("SHAR_KEY_ID must decode to 1..32 bytes".into());
        }
        let modulus = BigUint::from_bytes_be(
            &URL_SAFE_NO_PAD
                .decode(modulus)
                .map_err(|_| "SHAR_RSW_MODULUS must be base64url".to_owned())?,
        );
        let lambda = BigUint::from_bytes_be(
            &URL_SAFE_NO_PAD
                .decode(lambda)
                .map_err(|_| "SHAR_RSW_LAMBDA must be base64url".to_owned())?,
        );
        if modulus.bits() != 2048
            || modulus.is_even()
            || lambda <= BigUint::from(1_u8)
            || lambda >= modulus
            || id.is_empty()
            || id.len() > 64
        {
            return Err("production RSW configuration requires an odd 2048-bit modulus, 1 < lambda < modulus, and a 1..64 byte id".into());
        }
        let time_lock = TimeLockKey {
            id,
            modulus,
            lambda,
        };
        if !validate_time_lock_key(&time_lock) {
            return Err("SHAR_RSW trapdoor is inconsistent with its modulus".into());
        }
        return Ok((SigningMaterial { key_id, seed }, time_lock));
    }
    if env::var("SHAR_INSECURE_DEVELOPMENT").as_deref() != Ok("1") {
        return Err("configure all SHAR_SIGNING_SEED, SHAR_KEY_ID, SHAR_RSW_MODULUS, SHAR_RSW_LAMBDA, and SHAR_RSW_ID variables; or set SHAR_INSECURE_DEVELOPMENT=1 only for local evaluation".into());
    }
    eprintln!("WARNING: using an ephemeral signing key and tiny development-only RSW modulus");
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).map_err(|_| "operating-system randomness is required".to_owned())?;
    let p = BigUint::from(1_000_003_u64);
    let q = BigUint::from(1_000_033_u64);
    Ok((
        SigningMaterial {
            key_id: vec![1],
            seed,
        },
        TimeLockKey {
            id: "development-only".into(),
            modulus: &p * &q,
            lambda: BigUint::from(166_672_333_344_u64),
        },
    ))
}

#[derive(Deserialize)]
struct PreviousTrustKey {
    seed: String,
    key_id: String,
}

fn load_trust_keys(file: &HashMap<String, String>) -> Result<Vec<TrustKeyPair>, String> {
    let seed = configured("SHAR_TRUST_SEED", file);
    let key_id = configured("SHAR_TRUST_KEY_ID", file);
    let mut keys = Vec::new();
    match (seed, key_id) {
        (None, None) => {}
        (Some(seed), Some(key_id)) => {
            let seed: [u8; 32] = URL_SAFE_NO_PAD
                .decode(seed)
                .map_err(|_| "SHAR_TRUST_SEED must be base64url".to_owned())?
                .try_into()
                .map_err(|_| "SHAR_TRUST_SEED must decode to 32 bytes".to_owned())?;
            let key_id = URL_SAFE_NO_PAD
                .decode(key_id)
                .map_err(|_| "SHAR_TRUST_KEY_ID must be base64url".to_owned())?;
            keys.push(
                TrustKeyPair::from_seed(&seed, &key_id)
                    .map_err(|_| "invalid SHAR_TRUST_SEED or SHAR_TRUST_KEY_ID".to_owned())?,
            );
        }
        _ => return Err("configure both SHAR_TRUST_SEED and SHAR_TRUST_KEY_ID".into()),
    }
    if let Some(value) = configured("SHAR_PREVIOUS_TRUST_KEYS", file) {
        let previous: Vec<PreviousTrustKey> = serde_json::from_str(&value)
            .map_err(|_| "SHAR_PREVIOUS_TRUST_KEYS must be a JSON array".to_owned())?;
        for entry in previous {
            let seed: [u8; 32] = URL_SAFE_NO_PAD
                .decode(entry.seed)
                .map_err(|_| "previous trust seed must be base64url".to_owned())?
                .try_into()
                .map_err(|_| "previous trust seed must decode to 32 bytes".to_owned())?;
            let key_id = URL_SAFE_NO_PAD
                .decode(entry.key_id)
                .map_err(|_| "previous trust key id must be base64url".to_owned())?;
            let key = TrustKeyPair::from_seed(&seed, &key_id)
                .map_err(|_| "invalid previous trust key".to_owned())?;
            if !keys.iter().any(|existing| existing.key_id == key.key_id) {
                keys.push(key);
            }
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use axum::http::Method;
    use shar_core::{
        Cbor, RenderingProof, TimeLockProof, cose_verify, decode_cbor, derive_site_verify_secret,
        public_from_seed, solve_rendering, solve_timelock,
    };
    use tower::ServiceExt;

    #[derive(Deserialize)]
    struct ListenVectors {
        version: String,
        valid: Vec<ListenVector>,
        invalid: Vec<String>,
    }

    #[derive(Deserialize)]
    struct ListenVector {
        input: String,
        host: String,
        port: u16,
    }

    #[derive(Deserialize)]
    struct AllowedOriginDocument {
        version: String,
        vectors: Vec<AllowedOriginVector>,
    }

    #[derive(Deserialize)]
    struct AllowedOriginVector {
        name: String,
        input: String,
        valid: bool,
        origins: Option<Vec<String>>,
    }

    #[test]
    fn standalone_listen_parsing_matches_language_neutral_vectors() {
        let vectors: ListenVectors = serde_json::from_str(include_str!(
            "../../../protocol/standalone-listen-vectors.json"
        ))
        .unwrap();
        assert_eq!(vectors.version, "standalone-listen-v1");
        for vector in vectors.valid {
            assert_eq!(
                parse_listen_address(&vector.input).unwrap(),
                ListenAddress {
                    host: vector.host,
                    port: vector.port,
                }
            );
        }
        for value in vectors.invalid {
            assert!(parse_listen_address(&value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn standalone_allowlists_match_language_neutral_origin_vectors() {
        let document: AllowedOriginDocument = serde_json::from_str(include_str!(
            "../../../protocol/allowed-origin-vectors.json"
        ))
        .unwrap();
        assert_eq!(document.version, "allowed-origin-v1");
        for vector in document.vectors {
            let result = parse_allowed_origins(&vector.input);
            if vector.valid {
                let origins = vector.origins.unwrap();
                for origin in &origins {
                    parse_allowed_origins(origin)
                        .unwrap_or_else(|error| panic!("{} ({origin}): {error}", vector.name));
                }
                let expected: HashSet<String> = origins.into_iter().collect();
                let actual = result.unwrap_or_else(|error| panic!("{}: {error}", vector.name));
                assert_eq!(actual, expected, "{}", vector.name);
            } else {
                assert!(result.is_err(), "accepted {}", vector.name);
            }
        }
    }

    #[derive(Default)]
    struct CapturingAudit(Mutex<Vec<shar_core::AuditEvent>>);

    impl AuditStore for CapturingAudit {
        fn record(&self, event: &shar_core::AuditEvent) -> Result<(), shar_core::StoreError> {
            self.record_batch(std::slice::from_ref(event))
        }

        fn record_batch(
            &self,
            events: &[shar_core::AuditEvent],
        ) -> Result<(), shar_core::StoreError> {
            self.0
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .extend_from_slice(events);
            Ok(())
        }
    }

    struct BlockingAudit {
        state: Mutex<(bool, bool)>,
        changed: Condvar,
    }

    impl BlockingAudit {
        fn new() -> Self {
            Self {
                state: Mutex::new((false, false)),
                changed: Condvar::new(),
            }
        }

        fn wait_started(&self) {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            let (state, result) = self
                .changed
                .wait_timeout_while(state, Duration::from_secs(1), |state| !state.0)
                .unwrap_or_else(|error| error.into_inner());
            assert!(state.0 && !result.timed_out());
        }

        fn release(&self) {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.1 = true;
            self.changed.notify_all();
        }
    }

    impl AuditStore for BlockingAudit {
        fn record(&self, event: &shar_core::AuditEvent) -> Result<(), shar_core::StoreError> {
            self.record_batch(std::slice::from_ref(event))
        }

        fn record_batch(
            &self,
            _events: &[shar_core::AuditEvent],
        ) -> Result<(), shar_core::StoreError> {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.0 = true;
            self.changed.notify_all();
            while !state.1 {
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(|error| error.into_inner());
            }
            Ok(())
        }
    }

    struct FailingAudit;

    impl AuditStore for FailingAudit {
        fn record(&self, _event: &shar_core::AuditEvent) -> Result<(), shar_core::StoreError> {
            Err(shar_core::StoreError)
        }
    }

    fn audit_event(action: &str) -> shar_core::AuditEvent {
        shar_core::AuditEvent {
            version: "audit-v1".into(),
            kind: "challenge_issued".into(),
            occurred_at: 1_700_000_000,
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: action.into(),
            tier: Some(0),
            backend: None,
            code: None,
        }
    }

    #[test]
    fn request_ids_are_fixed_width_and_process_unique() {
        let values: HashSet<_> = (0..1_024).map(|_| new_request_id()).collect();
        assert_eq!(values.len(), 1_024);
        assert!(values.iter().all(|value| value.len() == 22));
    }

    #[test]
    fn buffered_audit_flush_persists_accepted_events_and_counts_failure() {
        let metrics = Arc::new(Metrics::default());
        let captured = Arc::new(CapturingAudit::default());
        let audit = BufferedAuditStore::new(captured.clone(), metrics.clone()).unwrap();
        for action in ["one", "two", "three"] {
            audit.record(&audit_event(action)).unwrap();
        }
        assert!(audit.flush(Duration::from_secs(1)));
        assert_eq!(
            captured
                .0
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            3
        );
        assert_eq!(metrics.audit_dropped.load(Ordering::Relaxed), 0);

        let failing_metrics = Arc::new(Metrics::default());
        let failing =
            BufferedAuditStore::new(Arc::new(FailingAudit), failing_metrics.clone()).unwrap();
        for action in ["one", "two", "three"] {
            failing.record(&audit_event(action)).unwrap();
        }
        assert!(failing.flush(Duration::from_secs(1)));
        assert_eq!(failing_metrics.audit_dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn buffered_audit_flush_has_a_hard_deadline() {
        let metrics = Arc::new(Metrics::default());
        let blocking = Arc::new(BlockingAudit::new());
        let audit = BufferedAuditStore::new(blocking.clone(), metrics).unwrap();
        audit.record(&audit_event("blocked")).unwrap();
        blocking.wait_started();
        assert!(!audit.flush(Duration::from_millis(1)));
        blocking.release();
        assert!(audit.flush(Duration::from_secs(1)));
    }

    fn test_app() -> (Router, AppState, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let admin_assets = directory.path().join("admin");
        std::fs::create_dir(&admin_assets).unwrap();
        std::fs::write(admin_assets.join("index.html"), b"admin").unwrap();
        let admin_assets = std::fs::canonicalize(admin_assets).unwrap();
        let policy = WorkPolicy {
            version: "test".into(),
            base_iterations: 16,
            base_render_rounds: 1,
            quiet_window_seconds: 60,
            base_lifetime_seconds: 120,
            iteration_allowance: 1000,
            round_allowance_seconds: 1,
            max_lifetime_seconds: 86400,
        };
        let store = Arc::new(
            SqliteStore::open(directory.path().join("state.sqlite"), policy.clone()).unwrap(),
        );
        let p = BigUint::from(1_000_003_u64);
        let q = BigUint::from(1_000_033_u64);
        let engine = Engine::with_stores_and_rotation_and_audit(
            SigningMaterial {
                key_id: vec![1],
                seed: [7; 32],
            },
            TimeLockKey {
                id: "test".into(),
                modulus: &p * &q,
                lambda: BigUint::from(166_672_333_344_u64),
            },
            policy,
            store.clone(),
            store.clone(),
            store.clone(),
            Vec::new(),
            Vec::new(),
            Some(store),
        )
        .with_browser_plans(
            PresencePlan::Host,
            FallbackPlan {
                available: true,
                methods: vec!["passkey".into(), "support".into()],
            },
        )
        .unwrap();
        let state = AppState {
            engine: Arc::new(engine),
            allowed_origins: Arc::new(HashSet::from(["https://app.example".into()])),
            network_secret: [3; 32],
            fallback_secret: Some([11; 32]),
            admin_secret: Some([12; 32]),
            siteverify_master_secret: Some([13; 32]),
            region: None,
            trusted_proxies: Arc::new(Vec::new()),
            trusted_assurance_header: false,
            metrics: Arc::new(Metrics::default()),
            request_log: false,
            max_concurrent_requests: 256,
            request_body_timeout: Duration::from_secs(15),
            readiness_admission: Arc::new(Admission::new(1)),
            admin_assets: Arc::new(admin_assets),
        };
        (router(state.clone()), state, directory)
    }
    async fn response_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn retryable_errors_include_body_and_header_guidance() {
        let response = ApiError::new(
            SharError {
                status: 503,
                code: "pricing_unavailable",
                retryable: true,
                next_action: "retry",
                retry_after: Some(2),
            },
            None,
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get("retry-after").unwrap(), "2");
        assert_eq!(response_json(response).await["retry_after"], 2);
    }

    #[tokio::test]
    async fn capacity_admission_is_bounded_retryable_and_recovers() {
        let admission = Arc::new(Admission::new(1));
        let first = admission.try_enter().expect("first request is admitted");
        assert!(admission.try_enter().is_none());
        let response = capacity_unavailable(Some("https://app.example"));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "https://app.example"
        );
        assert_eq!(
            response_json(response).await,
            json!({
                "code": "capacity_unavailable",
                "retryable": true,
                "next_action": "retry",
                "retry_after": 1,
            })
        );
        drop(first);
        assert!(admission.try_enter().is_some());
        assert!(admission_bypass("GET", "/healthz"));
        assert!(!admission_bypass("POST", "/healthz"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_engine_work_does_not_pin_the_async_worker() {
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let operation_entered = entered.clone();
        let operation_release = release.clone();
        let task = tokio::spawn(async move {
            blocking_engine(None, move || {
                operation_entered.store(true, Ordering::Release);
                while !operation_release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                Ok::<_, SharError>(())
            })
            .await
        });
        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        assert!(!task.is_finished());
        // Reaching and yielding on a single-thread runtime while the closure is
        // held proves that the synchronous operation runs off the async worker.
        tokio::task::yield_now().await;
        release.store(true, Ordering::Release);
        assert!(task.await.unwrap().is_ok());

        let unavailable = blocking_engine(None, || {
            Err::<(), _>(SharError {
                status: 503,
                code: "pricing_unavailable",
                retryable: true,
                next_action: "retry",
                retry_after: Some(1),
            })
        })
        .await
        .unwrap_err();
        assert_eq!(unavailable.error.code, "pricing_unavailable");
        assert_eq!(unavailable.error.retry_after, Some(1));
    }

    #[tokio::test]
    async fn liveness_and_readiness_are_distinct_no_store_probes() {
        let (app, _state, _directory) = test_app();
        let live = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(live.status(), StatusCode::OK);
        assert_eq!(
            live.headers()
                .get("x-shar-request-id")
                .unwrap()
                .to_str()
                .unwrap()
                .len(),
            22
        );
        assert_eq!(
            live.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response_json(live).await, json!({"status":"ok"}));

        let ready = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);
        assert_eq!(
            ready.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response_json(ready).await, json!({"status":"ready"}));

        let wrong_method = app
            .oneshot(
                HttpRequest::builder()
                    .method(Method::POST)
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response_json(wrong_method).await["code"],
            "method_not_allowed"
        );
        assert_eq!(observed_route("/private-tenant-name"), "unmatched");
        assert_eq!(observed_route("/admin/private-asset"), "/admin/*");
        assert_eq!(observed_method("TRACE"), "OTHER");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn admin_assets_cannot_escape_their_canonical_root_through_symlinks() {
        use std::os::unix::fs::symlink;

        assert_eq!(
            canonical_admin_assets_root("/").unwrap_err(),
            "SHAR_ADMIN_ASSETS must not be a filesystem root"
        );
        let (app, state, directory) = test_app();
        let outside = directory.path().join("outside.txt");
        std::fs::write(&outside, b"secret").unwrap();
        symlink(&outside, state.admin_assets.join("leak.txt")).unwrap();

        let safe = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/admin/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(safe.status(), StatusCode::OK);

        let escaped = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/admin/leak.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(escaped.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    #[ignore = "requires a loopback TCP listener; CI runs this test explicitly"]
    fn container_healthcheck_accepts_a_ready_http_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 128];
            let length = stream.read(&mut request).unwrap();
            assert!(request[..length].starts_with(b"GET /readyz HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        assert!(healthcheck_address(address));
        server.join().unwrap();
    }

    #[test]
    fn forwarding_chain_requires_a_trusted_proxy_suffix() {
        let trusted = vec![
            Cidr {
                network: "127.0.0.0".parse().unwrap(),
                prefix: 8,
            },
            Cidr {
                network: "10.0.0.0".parse().unwrap(),
                prefix: 8,
            },
            Cidr {
                network: "2001:db8:1::".parse().unwrap(),
                prefix: 48,
            },
        ];
        let headers = HeaderMap::from_iter([(
            "x-forwarded-for".parse().unwrap(),
            "192.0.2.44, 198.51.100.7, 10.0.0.9".parse().unwrap(),
        )]);
        assert_eq!(
            client_address("127.0.0.1".parse().unwrap(), &headers, &trusted),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_address("::ffff:127.0.0.1".parse().unwrap(), &headers, &trusted),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_address("203.0.113.5".parse().unwrap(), &headers, &trusted),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        let malformed = HeaderMap::from_iter([(
            "x-forwarded-for".parse().unwrap(),
            "not-an-address".parse().unwrap(),
        )]);
        assert_eq!(
            client_address("127.0.0.1".parse().unwrap(), &malformed, &trusted),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn cors_preflight_and_redemption_routes_are_browser_usable() {
        let (app, _state, _directory) = test_app();
        let request = HttpRequest::builder()
            .method(Method::OPTIONS)
            .uri("/v1/challenges/redeem")
            .header("origin", "https://app.example")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "https://app.example"
        );
    }

    #[tokio::test]
    async fn browser_supplied_pricing_signals_are_ignored() {
        let (app, _state, _directory) = test_app();
        let body = json!({"tenant":"tenant","site_key":"site","action":"submit","origin":"https://app.example","assurance_tier":32,"network_pseudonym":"attacker","session_binding":"attacker-selected"});
        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/challenges")
            .header("origin", "https://app.example")
            .header("content-type", "application/json")
            .header("x-shar-assurance-tier", "32")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["quote"]["tier"], 0);
        assert_eq!(body["presence"], json!({"mode":"host"}));
        assert_eq!(
            body["fallback"],
            json!({"available":true,"methods":["passkey","support"]})
        );
        let token = body["token"].as_str().unwrap();
        let payload = cose_verify(
            token,
            &[VerificationMaterial {
                key_id: vec![1],
                public_key: public_from_seed(&[7; 32]),
            }],
        )
        .unwrap();
        let claims = decode_cbor(&payload).unwrap();
        let map = match claims {
            Cbor::Map(entries) => entries,
            _ => panic!("challenge claims must be a map"),
        };
        assert!(!map.iter().any(|(key, _)| *key == Cbor::Unsigned(15)));
    }

    #[tokio::test]
    async fn trusted_proxy_assurance_header_prices_new_work_only() {
        let (_unused, mut state, _directory) = test_app();
        state.trusted_proxies = Arc::new(vec![Cidr {
            network: "127.0.0.1".parse().unwrap(),
            prefix: 32,
        }]);
        state.trusted_assurance_header = true;
        let app = router(state);
        let peer = ConnectInfo("127.0.0.1:43123".parse::<SocketAddr>().unwrap());
        let body = json!({
            "tenant":"tenant",
            "site_key":"site",
            "action":"trusted-assurance",
            "origin":"https://app.example"
        });
        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/challenges")
            .header("origin", "https://app.example")
            .header("content-type", "application/json")
            .header("x-shar-assurance-tier", "7")
            .extension(peer)
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["quote"]["tier"], 7);

        for invalid in ["", "07", "33", "-1", "bot"] {
            let request = HttpRequest::builder()
                .method(Method::POST)
                .uri("/v1/challenges")
                .header("origin", "https://app.example")
                .header("content-type", "application/json")
                .header("x-shar-assurance-tier", invalid)
                .extension(peer)
                .body(Body::from(body.to_string()))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response_json(response).await["code"],
                "invalid_assurance_tier"
            );
        }
    }

    #[test]
    fn assurance_mode_requires_an_explicit_trusted_proxy_boundary() {
        assert!(!load_assurance_mode(&HashMap::new(), false).unwrap());
        let configured = HashMap::from([(
            "SHAR_ASSURANCE_MODE".to_owned(),
            "trusted-header".to_owned(),
        )]);
        assert!(load_assurance_mode(&configured, true).unwrap());
        assert!(load_assurance_mode(&configured, false).is_err());
        let invalid = HashMap::from([(
            "SHAR_ASSURANCE_MODE".to_owned(),
            "browser-header".to_owned(),
        )]);
        assert!(load_assurance_mode(&invalid, true).is_err());

        let mut duplicate = HeaderMap::new();
        duplicate.append("x-shar-assurance-tier", HeaderValue::from_static("1"));
        duplicate.append("x-shar-assurance-tier", HeaderValue::from_static("2"));
        assert!(trusted_assurance_tier(&duplicate, None).is_err());
    }

    #[tokio::test]
    async fn successful_challenge_metrics_expose_engine_and_handler_phases() {
        let (app, _state, _directory) = test_app();
        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/challenges")
            .header("origin", "https://app.example")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "tenant":"tenant",
                    "site_key":"site",
                    "action":"submit",
                    "origin":"https://app.example"
                })
                .to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );

        let metrics = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = String::from_utf8(
            to_bytes(metrics.into_body(), MAX_BODY_BYTES)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let value = |name: &str| {
            body.lines()
                .find_map(|line| {
                    line.strip_prefix(name)
                        .and_then(|value| value.strip_prefix(' '))
                        .and_then(|value| value.parse::<f64>().ok())
                })
                .unwrap_or_else(|| panic!("missing metric {name}"))
        };
        let engine = value("shar_challenge_engine_duration_seconds_total");
        let handler = value("shar_challenge_handler_duration_seconds_total");
        assert_eq!(value("shar_challenges_issued_total"), 1.0);
        assert!(engine > 0.0);
        assert!(handler >= engine);
    }

    #[tokio::test]
    async fn malformed_oversized_and_unknown_requests_use_stable_errors() {
        let (app, _state, _directory) = test_app();
        let malformed = HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/challenges")
            .header("origin", "https://app.example")
            .header("content-type", "application/json")
            .body(Body::from("{".to_owned()))
            .unwrap();
        let response = app.clone().oneshot(malformed).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(response).await["code"], "malformed_json");
        let null_commitment = HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/challenges/redeem")
            .header("origin", "https://app.example")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "token":"shr1_invalid",
                    "time_lock":{"output":"AA"},
                    "rendering":{
                        "backend":"css",
                        "digest":"AA",
                        "css_commitment":null
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(null_commitment).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(response).await["code"], "malformed_json");
        let oversized = HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/challenges")
            .header("origin", "https://app.example")
            .header("content-type", "application/json")
            .body(Body::from(vec![b'x'; MAX_BODY_BYTES + 1]))
            .unwrap();
        let response = app.clone().oneshot(oversized).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .unwrap(),
            "https://app.example"
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-expose-headers")
                .unwrap(),
            "X-Shar-Request-Id"
        );
        assert_eq!(response_json(response).await["code"], "body_too_large");
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response_json(response).await["code"], "not_found");
    }

    #[tokio::test]
    async fn scoped_admin_audit_is_authenticated_and_bounded() {
        let (app, _state, _directory) = test_app();
        let challenge = HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/challenges")
            .header("origin", "https://app.example")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "tenant":"tenant",
                    "site_key":"site",
                    "action":"submit",
                    "origin":"https://app.example"
                })
                .to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(challenge).await.unwrap().status(),
            StatusCode::OK
        );
        let unauthorized = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/admin/audit?tenant=tenant&site_key=site&action=submit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/admin/audit?tenant=tenant&site_key=site&action=submit&limit=1")
                    .header(
                        "authorization",
                        format!("Bearer {}", URL_SAFE_NO_PAD.encode([12; 32])),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["events"][0]["kind"], "challenge_issued");
        let invalid = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/admin/audit?tenant=tenant&site_key=site&action=submit&limit=101")
                    .header(
                        "authorization",
                        format!("Bearer {}", URL_SAFE_NO_PAD.encode([12; 32])),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(invalid).await["code"], "invalid_audit_limit");
        let malformed_limit = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/admin/audit?tenant=tenant&site_key=site&action=submit&limit=slow")
                    .header(
                        "authorization",
                        format!("Bearer {}", URL_SAFE_NO_PAD.encode([12; 32])),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed_limit.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(malformed_limit).await["code"],
            "invalid_audit_limit"
        );
    }

    #[tokio::test]
    async fn privileged_fallback_is_authenticated_and_replay_safe() {
        let (app, _state, _directory) = test_app();
        let body = json!({"tenant":"tenant","site_key":"site","action":"submit","origin":"https://app.example","method":"passkey","assertion_id":"host-assertion-0001"});
        let request = |authorized: bool| {
            let mut builder = HttpRequest::builder()
                .method(Method::POST)
                .uri("/v1/fallback/complete")
                .header("content-type", "application/json");
            if authorized {
                builder = builder.header(
                    "authorization",
                    format!("Bearer {}", URL_SAFE_NO_PAD.encode([11; 32])),
                );
            }
            builder.body(Body::from(body.to_string())).unwrap()
        };
        let unauthorized = app.clone().oneshot(request(false)).await.unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let unsupported = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method(Method::POST)
                    .uri("/v1/fallback/complete")
                    .header("content-type", "application/json")
                    .header(
                        "authorization",
                        format!("Bearer {}", URL_SAFE_NO_PAD.encode([11; 32])),
                    )
                    .body(Body::from(
                        json!({"tenant":"tenant","site_key":"site","action":"submit","origin":"https://app.example","method":"email","assertion_id":"host-assertion-unsupported"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(unsupported).await["code"],
            "invalid_fallback_method"
        );
        let completed = app.clone().oneshot(request(true)).await.unwrap();
        assert_eq!(completed.status(), StatusCode::OK);
        assert_eq!(
            response_json(completed).await["verification_method"],
            "fallback"
        );
        let replay = app.clone().oneshot(request(true)).await.unwrap();
        assert_eq!(replay.status(), StatusCode::CONFLICT);
        assert_eq!(
            response_json(replay).await["code"],
            "replayed_fallback_assertion"
        );
        let metrics = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(metrics.into_body(), MAX_BODY_BYTES).await.unwrap();
        assert!(
            String::from_utf8(bytes.to_vec())
                .unwrap()
                .contains("shar_fallback_completions_total 1\n")
        );
    }

    #[tokio::test]
    async fn admin_policy_is_authenticated_validated_and_changes_new_quotes() {
        let (app, state, _directory) = test_app();
        let query = "/v1/admin/policy?tenant=tenant&site_key=site&action=submit";
        let unauthorized = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(query)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(unauthorized).await["code"],
            "admin_unauthorized"
        );

        let authorization = format!("Bearer {}", URL_SAFE_NO_PAD.encode([12; 32]));
        let read = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(query)
                    .header("authorization", &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::OK);
        let mut document = response_json(read).await;
        assert_eq!(document["policy"]["base_iterations"], "16");
        document["policy"]["version"] = json!("policy-admin-v2");
        document["policy"]["base_iterations"] = json!("32");
        let write = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method(Method::PUT)
                    .uri("/v1/admin/policy")
                    .header("authorization", &authorization)
                    .header("content-type", "application/json")
                    .body(Body::from(document.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(write.status(), StatusCode::OK);
        assert_eq!(
            response_json(write).await["policy"]["base_iterations"],
            "32"
        );
        let challenge = state
            .engine
            .issue(
                &ChallengeRequest {
                    tenant: "tenant".into(),
                    site_key: "site".into(),
                    action: "submit".into(),
                    origin: "https://app.example".into(),
                    region: None,
                    session_binding: None,
                    network_pseudonym: None,
                    assurance_tier: None,
                    trust_token: None,
                },
                1_800_000_000,
                [0; 16],
                [1; 32],
            )
            .unwrap();
        assert_eq!(challenge.quote.time_lock_iterations, "32");

        document["policy"]["base_iterations"] = json!(u64::MAX.to_string());
        let invalid = app
            .oneshot(
                HttpRequest::builder()
                    .method(Method::PUT)
                    .uri("/v1/admin/policy")
                    .header("authorization", authorization)
                    .header("content-type", "application/json")
                    .body(Body::from(document.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(invalid).await["code"], "invalid_policy");
    }

    #[tokio::test]
    async fn form_encoded_compatibility_aliases_are_normalized() {
        let (app, state, _directory) = test_app();
        let challenge_request = ChallengeRequest {
            tenant: "tenant".into(),
            site_key: "site".into(),
            action: "submit".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: None,
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        };
        let challenge = state
            .engine
            .issue(&challenge_request, 1_800_000_000, [0; 16], [1; 32])
            .unwrap();
        let input =
            BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&challenge.time_lock.input).unwrap());
        let iterations = challenge.time_lock.iterations.parse().unwrap();
        let output = solve_timelock(&input, iterations, &state.engine.time_lock.modulus);
        let digest = URL_SAFE_NO_PAD.encode(
            solve_rendering(
                &[1; 32],
                challenge.render.rounds,
                challenge.render.triangles,
                challenge.render.samples,
            )
            .unwrap(),
        );
        let redeemed = state
            .engine
            .redeem(
                &RedeemRequest {
                    token: challenge.token,
                    time_lock: TimeLockProof {
                        output: URL_SAFE_NO_PAD.encode(output.to_bytes_be()),
                    },
                    rendering: RenderingProof {
                        digest,
                        backend: "css".into(),
                        css_commitment: None,
                    },
                    trust_blinded: None,
                },
                1_800_000_001,
                [2; 16],
            )
            .unwrap();
        let unauthorized_form = serde_urlencoded::to_string([
            ("g-recaptcha-response", redeemed.token.clone()),
            ("secret", "wrong".to_owned()),
        ])
        .unwrap();
        let unauthorized = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method(Method::POST)
                    .uri("/v1/siteverify")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(unauthorized_form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(unauthorized).await["code"],
            "siteverify_unauthorized"
        );

        let secret = derive_site_verify_secret(&[13; 32], "tenant", "site").unwrap();
        let form = serde_urlencoded::to_string([
            ("g-recaptcha-response", redeemed.token),
            ("secret", secret),
        ])
        .unwrap();
        let request = HttpRequest::builder()
            .method(Method::POST)
            .uri("/v1/siteverify")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["success"], true);
        assert_eq!(body["score"], 1.0);
    }
}
