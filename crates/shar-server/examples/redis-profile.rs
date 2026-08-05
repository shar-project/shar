use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use num_bigint::BigUint;
use serde_json::{Value, json};
use shar_core::{
    AuditEvent, AuditStore, ChallengeRequest, Engine, PressureStore, SigningMaterial, TimeLockKey,
    default_work_policy, trust::TrustKeyPair,
};
use shar_server::{
    redis::{RedisStore, low_latency_client},
    sqlite::SqliteStore,
};
use std::{
    env, fs,
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const OPERATIONS: usize = 3_000;
const CONCURRENCY: usize = 32;

fn main() {
    let mut arguments = env::args().skip(1);
    let url = arguments.next().expect(
        "usage: cargo run -p shar-server --release --example redis-profile -- REDIS_URL [KEY_FILE]",
    );
    let key_file = arguments.next();
    assert!(arguments.next().is_none(), "too many arguments");
    let client = low_latency_client(&url).expect("Redis URL");
    let store = Arc::new(
        RedisStore::from_client(client, 10, 172_800, Duration::from_secs(5)).expect("Redis store"),
    );
    let request = Arc::new(ChallengeRequest {
        tenant: "profile".into(),
        site_key: "site".into(),
        action: format!("atomic-issue-{}", std::process::id()),
        origin: "http://localhost:3000".into(),
        region: None,
        session_binding: None,
        network_pseudonym: Some("daily-network".into()),
        assurance_tier: None,
        trust_token: None,
    });
    let policy = Arc::new(default_work_policy());
    verify_audit_batch(&store, &request);
    let store_started = Instant::now();
    run_concurrent({
        let store = store.clone();
        let request = request.clone();
        let policy = policy.clone();
        move |index| {
            black_box(index);
            store
                .price_and_record(&request, &policy, 1_800_000_000)
                .expect("price and reserve");
        }
    });
    let store_elapsed = store_started.elapsed().as_secs_f64();
    let full = key_file.map(|path| profile_full(&path, store.clone()));
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "shar-rust-redis-profile-v1",
            "operations": OPERATIONS,
            "concurrency": CONCURRENCY,
            "atomic_pricing": {
                "elapsed_ms": store_elapsed * 1_000.0,
                "operations_per_second": OPERATIONS as f64 / store_elapsed,
            },
            "full_issue_with_sqlite_config_and_json": full,
        }))
        .expect("serialize profile")
    );
}

fn verify_audit_batch(store: &RedisStore, request: &ChallengeRequest) {
    let audit = [1_u64; 3].map(|offset| AuditEvent {
        version: "audit-v1".into(),
        kind: "challenge_issued".into(),
        occurred_at: 1_800_000_000 + offset,
        tenant: request.tenant.clone(),
        site_key: request.site_key.clone(),
        action: request.action.clone(),
        tier: Some(offset as u8),
        backend: None,
        code: None,
    });
    store.record_batch(&audit).expect("batched audit write");
    let retained = store
        .list(&request.tenant, &request.site_key, &request.action, 3)
        .expect("batched audit read");
    assert_eq!(
        retained
            .iter()
            .map(|event| event.occurred_at)
            .collect::<Vec<_>>(),
        vec![1_800_000_001; 3]
    );
}

fn run_concurrent(operation: impl Fn(usize) + Send + Sync + 'static) {
    let next = Arc::new(AtomicUsize::new(0));
    let operation = Arc::new(operation);
    let workers: Vec<_> = (0..CONCURRENCY)
        .map(|_| {
            let next = next.clone();
            let operation = operation.clone();
            thread::spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= OPERATIONS {
                        break;
                    }
                    operation(index);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker");
    }
}

fn profile_full(path: &str, store: Arc<RedisStore>) -> Value {
    let document: Value =
        serde_json::from_slice(&fs::read(path).expect("read key file")).expect("parse key file");
    let signing = SigningMaterial {
        key_id: decode(&document, "SHAR_KEY_ID"),
        seed: decode(&document, "SHAR_SIGNING_SEED")
            .try_into()
            .expect("32-byte signing seed"),
    };
    let time_lock = TimeLockKey {
        id: text(&document, "SHAR_RSW_ID").to_owned(),
        modulus: BigUint::from_bytes_be(&decode(&document, "SHAR_RSW_MODULUS")),
        lambda: BigUint::from_bytes_be(&decode(&document, "SHAR_RSW_LAMBDA")),
    };
    let trust = TrustKeyPair::from_seed(
        &decode(&document, "SHAR_TRUST_SEED"),
        &decode(&document, "SHAR_TRUST_KEY_ID"),
    )
    .expect("trust key");
    let policy = default_work_policy();
    let directory = tempfile::tempdir().expect("temporary config directory");
    let config = Arc::new(
        SqliteStore::open(directory.path().join("config.sqlite"), policy.clone())
            .expect("SQLite config"),
    );
    let engine = Arc::new(
        Engine::with_stores(signing, time_lock, policy, store.clone(), store, config)
            .with_trust_keys(vec![trust], 86_400)
            .expect("trust configuration"),
    );
    let request = Arc::new(ChallengeRequest {
        tenant: "profile".into(),
        site_key: "site".into(),
        action: format!("full-issue-{}", std::process::id()),
        origin: "http://localhost:3000".into(),
        region: None,
        session_binding: None,
        network_pseudonym: Some("daily-network".into()),
        assurance_tier: None,
        trust_token: None,
    });
    let started = Instant::now();
    run_concurrent(move |index| {
        let mut nonce = [0_u8; 16];
        nonce[8..].copy_from_slice(&(index as u64).to_be_bytes());
        let mut seed = [0_u8; 32];
        seed[24..].copy_from_slice(&(index as u64).to_be_bytes());
        let response = engine
            .issue(&request, 1_800_000_000, nonce, seed)
            .expect("full issue");
        black_box(serde_json::to_vec(&response).expect("serialize response"));
    });
    let elapsed = started.elapsed().as_secs_f64();
    json!({
        "elapsed_ms": elapsed * 1_000.0,
        "operations_per_second": OPERATIONS as f64 / elapsed,
    })
}

fn text<'a>(document: &'a Value, name: &str) -> &'a str {
    document[name]
        .as_str()
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn decode(document: &Value, name: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(text(document, name))
        .unwrap_or_else(|_| panic!("invalid {name}"))
}
