use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{
    Client, Connection, FromRedisValue, IntoConnectionInfo, RedisError, Script,
    io::tcp::TcpSettings,
};
use sha2::{Digest, Sha256};
use shar_core::{
    AuditEvent, AuditStore, ChallengeRequest, FailureKind, NonceStore, PressureInput,
    PressureStore, StoreError, WorkPolicy, WorkQuote, price_work,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const READ_PRESSURE: &str = r#"local now=tonumber(ARGV[1]);local quiet=tonumber(ARGV[2]);local assurance=tonumber(ARGV[3]);local has_session=ARGV[4]=='1';local retention=tonumber(ARGV[5]);local has_network=ARGV[6]=='1'
local function tier(count) local result=0;local threshold=1;while count>threshold and result<32 do threshold=threshold*2;result=result+1 end;return result end
redis.call('ZREMRANGEBYSCORE',KEYS[4],'-inf','('..tostring(now))
local av=redis.call('HMGET',KEYS[1],'window','count');local aw=tonumber(av[1]) or now;local ac=tonumber(av[2]) or 0;if now-aw>=quiet then aw=now;ac=0 end;ac=ac+1;redis.call('HSET',KEYS[1],'last',now,'window',aw,'count',ac)
local cv=redis.call('HMGET',KEYS[2],'last','failure','assurance','base','trust');local cl=tonumber(cv[1]) or now;local decay=math.floor(math.max(0,now-cl)/quiet);local failure=math.max(0,(tonumber(cv[2]) or 0)-decay);local stored=math.max(0,(tonumber(cv[3]) or 0)-decay);local current=math.max(stored,assurance);redis.call('HSET',KEYS[2],'failure',failure,'assurance',has_session and current or stored,'last',now)
local network_tier=0;if has_network then local nv=redis.call('HMGET',KEYS[3],'last','failure','window','count','network');local nl=tonumber(nv[1]) or now;local nd=math.floor(math.max(0,now-nl)/quiet);local nf=math.max(0,(tonumber(nv[2]) or 0)-nd);local nw=tonumber(nv[3]) or now;local nc=tonumber(nv[4]) or 0;if now-nw>=quiet then nw=now;nc=0 end;nc=nc+1;network_tier=math.max(tonumber(nv[5]) or 0,nf,tier(nc));redis.call('HSET',KEYS[3],'failure',nf,'last',now,'window',nw,'count',nc) end
local base=tonumber(cv[4]) or 0;local velocity=tier(ac);local outstanding=tier(redis.call('ZCARD',KEYS[4])+1);local trust=tonumber(cv[5]) or 0
if ARGV[7]=='1' then redis.call('EXPIRE',KEYS[2],retention);if has_network then redis.call('EXPIRE',KEYS[3],retention) end;local debt=math.max(0,failure+current-trust);local total=math.min(32,base+velocity+outstanding+math.min(4,network_tier)+debt);local expires=tonumber(ARGV[8+total]);local sequence=redis.call('INCR',KEYS[5]);redis.call('ZADD',KEYS[4],expires,tostring(now)..':'..tostring(sequence));local deadline=math.max(expires+3600,now+retention);redis.call('EXPIREAT',KEYS[4],deadline);redis.call('EXPIREAT',KEYS[5],deadline);redis.call('EXPIREAT',KEYS[1],deadline) else redis.call('EXPIRE',KEYS[1],retention);redis.call('EXPIRE',KEYS[2],retention);redis.call('EXPIRE',KEYS[4],retention);if has_network then redis.call('EXPIRE',KEYS[3],retention) end end
return {base,velocity,outstanding,network_tier,failure,current,trust}"#;
const RECORD_ISSUED: &str = r#"local now=tonumber(ARGV[1]);local expires=tonumber(ARGV[2]);local retention=tonumber(ARGV[3]);local sequence=redis.call('INCR',KEYS[3]);redis.call('ZADD',KEYS[2],expires,tostring(now)..':'..tostring(sequence));redis.call('HSETNX',KEYS[1],'last',now);redis.call('HSET',KEYS[1],'last',now);local deadline=math.max(expires+3600,now+retention);redis.call('EXPIREAT',KEYS[2],deadline);redis.call('EXPIREAT',KEYS[3],deadline);redis.call('EXPIREAT',KEYS[1],deadline);return 1"#;
const RECORD_OUTCOME: &str = r#"local now=tonumber(ARGV[1]);local delta=tonumber(ARGV[2]);local remove=ARGV[3]=='1';local retention=tonumber(ARGV[4]);local expires=tonumber(ARGV[5]);redis.call('HSETNX',KEYS[1],'failure',0);local debt=tonumber(redis.call('HGET',KEYS[1],'failure'));if delta>0 then debt=math.min(32,debt+1) else debt=math.max(0,debt-1) end;redis.call('HSET',KEYS[1],'failure',debt,'last',now);redis.call('EXPIRE',KEYS[1],retention);if remove then local matching=redis.call('ZRANGEBYSCORE',KEYS[2],tostring(expires),tostring(expires),'LIMIT',0,1);if #matching>0 then redis.call('ZREM',KEYS[2],matching[1]) end end;return debt"#;
const RECORD_TRUST: &str = r#"local now=tonumber(ARGV[1]);local retention=tonumber(ARGV[2]);redis.call('HSETNX',KEYS[1],'failure',0);redis.call('HSETNX',KEYS[1],'assurance',0);local failure=tonumber(redis.call('HGET',KEYS[1],'failure'));local assurance=tonumber(redis.call('HGET',KEYS[1],'assurance'));if failure>0 then failure=failure-1 else assurance=math.max(0,assurance-1) end;redis.call('HSET',KEYS[1],'failure',failure,'assurance',assurance,'last',now);redis.call('EXPIRE',KEYS[1],retention);return 1"#;
const RECORD_AUDIT: &str = r#"local cutoff=tonumber(ARGV[1]);local count=(#ARGV-1)/2;if count<1 then return 0 end;local last=redis.call('INCRBY',KEYS[2],count);local first=last-count+1;local entries={};local item=0;for index=2,#ARGV,2 do item=item+1;local occurred=tonumber(ARGV[index]);local payload=ARGV[index+1];local member=tostring(occurred)..':'..tostring(first+item-1)..':'..payload;entries[#entries+1]=occurred;entries[#entries+1]=member end;redis.call('ZADD',KEYS[1],unpack(entries));redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf','('..tostring(cutoff));redis.call('EXPIRE',KEYS[1],86400);redis.call('EXPIRE',KEYS[2],86400);return count"#;
const MAX_AUDIT_BATCH_SIZE: usize = 128;

// Redis Lua numbers are IEEE-754 doubles. Keep timestamps in their exact
// integer range before passing them to scripts that add retention/deadline
// values, otherwise Lua can round a valid Rust integer and alter pressure or
// expiry behavior.
const LUA_MAX_INTEGER: u64 = 9_007_199_254_740_991;

/// Build Redis connections for latency-sensitive atomic proof state. Redis-rs
/// deliberately defaults to Nagle enabled, which can hold small EVALSHA
/// requests while waiting for prior acknowledgements. Shar performs one
/// request/response command on the quote-critical path, so every pooled TCP
/// connection must disable that coalescing delay.
pub fn low_latency_client(url: &str) -> Result<Client, RedisError> {
    let connection = url
        .into_connection_info()?
        .set_tcp_settings(TcpSettings::default().set_nodelay(true));
    Client::open(connection)
}

fn configured_connection(client: &Client, timeout: Duration) -> Result<Connection, StoreError> {
    let connection = client
        .get_connection_with_timeout(timeout)
        .map_err(|_| StoreError)?;
    connection
        .set_read_timeout(Some(timeout))
        .and_then(|_| connection.set_write_timeout(Some(timeout)))
        .map_err(|_| StoreError)?;
    Ok(connection)
}

pub struct RedisStore {
    connections: Vec<Mutex<ConnectionSlot>>,
    reconnect: Option<ReconnectConfig>,
    next_connection: AtomicUsize,
    retention_seconds: u64,
    read_pressure: Script,
    record_issued: Script,
    record_outcome: Script,
    record_trust: Script,
    record_audit: Script,
    expiry_arguments: ExpiryArgumentCache,
    pressure_keys: PressureKeyCache,
}

struct ConnectionSlot {
    connection: Option<Connection>,
}

struct ReconnectConfig {
    client: Client,
    timeout: Duration,
}

#[derive(Default)]
struct ExpiryArgumentCache(Mutex<Option<CachedExpiryArguments>>);

struct CachedExpiryArguments {
    policy: WorkPolicy,
    now: u64,
    values: Arc<[String; 33]>,
}

impl ExpiryArgumentCache {
    fn values(
        &self,
        policy: &WorkPolicy,
        now: u64,
        retention_seconds: u64,
    ) -> Result<Arc<[String; 33]>, StoreError> {
        let mut cached = self.0.lock().map_err(|_| StoreError)?;
        if let Some(entry) = cached.as_ref()
            && entry.now == now
            && entry.policy == *policy
        {
            return Ok(entry.values.clone());
        }
        let mut values = Vec::with_capacity(33);
        for total_tier in 0..=32 {
            let quote = price_work(
                &PressureInput {
                    base_tier: total_tier,
                    velocity_tier: 0,
                    outstanding_tier: 0,
                    network_tier: 0,
                    failure_debt: 0,
                    assurance_debt: 0,
                    trust_credits: 0,
                },
                policy,
                now,
            )
            .map_err(|_| StoreError)?;
            validate_lua_deadline(now, quote.expires_at, retention_seconds)?;
            values.push(quote.expires_at.to_string());
        }
        let values: Arc<[String; 33]> = Arc::new(values.try_into().map_err(|_| StoreError)?);
        *cached = Some(CachedExpiryArguments {
            policy: policy.clone(),
            now,
            values: values.clone(),
        });
        Ok(values)
    }
}

impl RedisStore {
    pub fn from_connections(
        first: Connection,
        additional: Vec<Connection>,
        retention_seconds: u64,
    ) -> Result<Self, StoreError> {
        if !(3600..=LUA_MAX_INTEGER - 3600).contains(&retention_seconds) {
            return Err(StoreError);
        }
        Ok(Self {
            connections: std::iter::once(first)
                .chain(additional)
                .map(|connection| {
                    Mutex::new(ConnectionSlot {
                        connection: Some(connection),
                    })
                })
                .collect(),
            reconnect: None,
            next_connection: AtomicUsize::new(0),
            retention_seconds,
            read_pressure: Script::new(READ_PRESSURE),
            record_issued: Script::new(RECORD_ISSUED),
            record_outcome: Script::new(RECORD_OUTCOME),
            record_trust: Script::new(RECORD_TRUST),
            record_audit: Script::new(RECORD_AUDIT),
            expiry_arguments: ExpiryArgumentCache::default(),
            pressure_keys: PressureKeyCache::default(),
        })
    }

    pub fn from_client(
        client: Client,
        pool_size: usize,
        retention_seconds: u64,
        timeout: Duration,
    ) -> Result<Self, StoreError> {
        if pool_size == 0 || timeout.is_zero() {
            return Err(StoreError);
        }
        let mut connections = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            connections.push(configured_connection(&client, timeout)?);
        }
        let mut store = Self::from_connections(
            connections.pop().ok_or(StoreError)?,
            connections,
            retention_seconds,
        )?;
        store.reconnect = Some(ReconnectConfig { client, timeout });
        Ok(store)
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, RedisError>,
    ) -> Result<T, StoreError> {
        let index = self.next_connection.fetch_add(1, Ordering::Relaxed) % self.connections.len();
        let mut slot = self.connections[index].lock().map_err(|_| StoreError)?;
        if slot.connection.is_none() {
            let reconnect = self.reconnect.as_ref().ok_or(StoreError)?;
            slot.connection = Some(configured_connection(&reconnect.client, reconnect.timeout)?);
        }
        let result = operation(slot.connection.as_mut().ok_or(StoreError)?);
        if result.is_err() {
            // Never retry an operation whose outcome could be ambiguous: a
            // mutation may have reached Redis before the connection failed.
            // Discard the socket so the next independent request reconnects.
            slot.connection = None;
        }
        result.map_err(|_| StoreError)
    }

    fn eval<T: FromRedisValue>(
        &self,
        script: &Script,
        keys: &[String],
        arguments: &[String],
    ) -> Result<T, StoreError> {
        let mut invocation = script.prepare_invoke();
        for key in keys {
            invocation.key(key);
        }
        for argument in arguments {
            invocation.arg(argument);
        }
        self.with_connection(|connection| invocation.invoke(connection))
    }

    fn outcome(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
        delta: i8,
        remove: bool,
    ) -> Result<(), StoreError> {
        validate_lua_deadline(now, expires_at, self.retention_seconds)?;
        let keys = self.pressure_keys.values(input)?;
        let _: i64 = self.eval(
            &self.record_outcome,
            &[keys.failure(input), keys.outstanding],
            &[
                now.to_string(),
                delta.to_string(),
                if remove { "1" } else { "0" }.into(),
                self.retention_seconds.to_string(),
                expires_at.to_string(),
            ],
        )?;
        Ok(())
    }

    fn check_health(&self) -> Result<(), StoreError> {
        let command = redis::cmd("PING");
        let response: String = self.with_connection(|connection| command.query(connection))?;
        if response == "PONG" {
            Ok(())
        } else {
            Err(StoreError)
        }
    }
}

impl NonceStore for RedisStore {
    fn health(&self) -> Result<(), StoreError> {
        self.check_health()
    }

    fn consume(&self, namespace: &str, nonce: &[u8], expires_at: u64) -> Result<bool, StoreError> {
        let key = format!("shar:nonce:{namespace}:{}", URL_SAFE_NO_PAD.encode(nonce));
        // Shar treats the signed expiry as inclusive: a proof at exactly
        // `expires_at` is still valid. Redis removes EXAT keys at the
        // boundary, so retain the one-shot marker for one additional second
        // to match the SQL and in-memory stores. Do not wrap at u64::MAX.
        let retention_expiry = inclusive_nonce_expiry(expires_at)?;
        let mut command = redis::cmd("SET");
        command
            .arg(key)
            .arg("1")
            .arg("EXAT")
            .arg(retention_expiry)
            .arg("NX");
        let result: Option<String> =
            self.with_connection(|connection| command.query(connection))?;
        Ok(result.as_deref() == Some("OK"))
    }
}

impl PressureStore for RedisStore {
    fn health(&self) -> Result<(), StoreError> {
        self.check_health()
    }

    fn read(
        &self,
        input: &ChallengeRequest,
        now: u64,
        quiet_window_seconds: u64,
    ) -> Result<PressureInput, StoreError> {
        if quiet_window_seconds == 0
            || now > LUA_MAX_INTEGER
            || quiet_window_seconds > LUA_MAX_INTEGER
        {
            return Err(StoreError);
        }
        let keys = self.pressure_keys.values(input)?;
        let values: Vec<i64> = self.eval(
            &self.read_pressure,
            &[
                keys.action,
                keys.client.clone(),
                keys.network.clone().unwrap_or(keys.client),
                keys.outstanding,
            ],
            &[
                now.to_string(),
                quiet_window_seconds.to_string(),
                input.assurance_tier.unwrap_or(0).to_string(),
                if input.session_binding.is_some() {
                    "1"
                } else {
                    "0"
                }
                .into(),
                self.retention_seconds.to_string(),
                if keys.network.is_some() { "1" } else { "0" }.into(),
            ],
        )?;
        pressure_from_values(&values)
    }

    fn price_and_record(
        &self,
        input: &ChallengeRequest,
        policy: &WorkPolicy,
        now: u64,
    ) -> Result<WorkQuote, StoreError> {
        if policy.quiet_window_seconds == 0
            || now > LUA_MAX_INTEGER
            || policy.quiet_window_seconds > LUA_MAX_INTEGER
        {
            return Err(StoreError);
        }
        let keys = self.pressure_keys.values(input)?;
        let arguments = [
            now.to_string(),
            policy.quiet_window_seconds.to_string(),
            input.assurance_tier.unwrap_or(0).to_string(),
            if input.session_binding.is_some() {
                "1"
            } else {
                "0"
            }
            .into(),
            self.retention_seconds.to_string(),
            if keys.network.is_some() { "1" } else { "0" }.into(),
            "1".into(),
        ];
        let expiry_arguments = self
            .expiry_arguments
            .values(policy, now, self.retention_seconds)?;
        let mut invocation = self.read_pressure.prepare_invoke();
        for key in [
            keys.action,
            keys.client.clone(),
            keys.network.clone().unwrap_or(keys.client),
            keys.outstanding,
            keys.sequence,
        ] {
            invocation.key(key);
        }
        for argument in &arguments {
            invocation.arg(argument);
        }
        for expires_at in expiry_arguments.iter() {
            invocation.arg(expires_at);
        }
        let values: Vec<i64> = self.with_connection(|connection| invocation.invoke(connection))?;
        let pressure = pressure_from_values(&values)?;
        price_work(&pressure, policy, now).map_err(|_| StoreError)
    }

    fn record_issued(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        validate_lua_deadline(now, expires_at, self.retention_seconds)?;
        let keys = self.pressure_keys.values(input)?;
        let _: i64 = self.eval(
            &self.record_issued,
            &[keys.action, keys.outstanding, keys.sequence],
            &[
                now.to_string(),
                expires_at.to_string(),
                self.retention_seconds.to_string(),
            ],
        )?;
        Ok(())
    }

    fn record_success(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        self.outcome(input, expires_at, now, -1, true)
    }

    fn record_failure(
        &self,
        input: &ChallengeRequest,
        kind: FailureKind,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        self.outcome(input, expires_at, now, 1, kind == FailureKind::Expired)
    }

    fn record_trust(&self, input: &ChallengeRequest, now: u64) -> Result<(), StoreError> {
        validate_lua_integer(now)?;
        let keys = self.pressure_keys.values(input)?;
        let _: i64 = self.eval(
            &self.record_trust,
            &[keys.client],
            &[now.to_string(), self.retention_seconds.to_string()],
        )?;
        Ok(())
    }
}

impl AuditStore for RedisStore {
    fn record(&self, event: &AuditEvent) -> Result<(), StoreError> {
        self.record_batch(std::slice::from_ref(event))
    }

    fn record_batch(&self, events: &[AuditEvent]) -> Result<(), StoreError> {
        let groups = audit_groups(events)?;
        for (key, events) in groups {
            let sequence = key.replace(":audit", ":audit-seq");
            let latest = events
                .iter()
                .map(|event| event.occurred_at)
                .max()
                .ok_or(StoreError)?;
            for chunk in events.chunks(MAX_AUDIT_BATCH_SIZE) {
                let mut arguments = Vec::with_capacity(1 + chunk.len() * 2);
                arguments.push(latest.saturating_sub(86_400).to_string());
                for event in chunk {
                    arguments.push(event.occurred_at.to_string());
                    arguments.push(event.encoded.clone());
                }
                let written: i64 = self.eval(
                    &self.record_audit,
                    &[key.clone(), sequence.clone()],
                    &arguments,
                )?;
                if written != i64::try_from(chunk.len()).map_err(|_| StoreError)? {
                    return Err(StoreError);
                }
            }
        }
        Ok(())
    }

    fn list(
        &self,
        tenant: &str,
        site_key: &str,
        action: &str,
        limit: u32,
    ) -> Result<Vec<AuditEvent>, StoreError> {
        if !(1..=100).contains(&limit) {
            return Err(StoreError);
        }
        let key = audit_key(tenant, site_key, action);
        let mut command = redis::cmd("ZREVRANGEBYSCORE");
        command
            .arg(&key)
            .arg("+inf")
            .arg("-inf")
            .arg("LIMIT")
            .arg(0)
            .arg(limit);
        let members: Vec<String> = self.with_connection(|connection| command.query(connection))?;
        members
            .into_iter()
            .map(|member| {
                let first = member.find(':').ok_or(StoreError)?;
                let second = member[first + 1..]
                    .find(':')
                    .map(|offset| first + 1 + offset)
                    .ok_or(StoreError)?;
                if first == 0 || second <= first + 1 {
                    return Err(StoreError);
                }
                let event: AuditEvent =
                    serde_json::from_str(&member[second + 1..]).map_err(|_| StoreError)?;
                validate_audit_event(&event)?;
                if event.tenant != tenant || event.site_key != site_key || event.action != action {
                    return Err(StoreError);
                }
                Ok(event)
            })
            .collect()
    }
}

struct EncodedAuditEvent {
    occurred_at: u64,
    encoded: String,
}

fn audit_groups(
    events: &[AuditEvent],
) -> Result<BTreeMap<String, Vec<EncodedAuditEvent>>, StoreError> {
    let mut groups: BTreeMap<String, Vec<EncodedAuditEvent>> = BTreeMap::new();
    for event in events {
        validate_audit_event(event)?;
        validate_lua_integer(event.occurred_at)?;
        groups
            .entry(audit_key(&event.tenant, &event.site_key, &event.action))
            .or_default()
            .push(EncodedAuditEvent {
                occurred_at: event.occurred_at,
                encoded: serde_json::to_string(event).map_err(|_| StoreError)?,
            });
    }
    Ok(groups)
}

fn validate_audit_event(event: &AuditEvent) -> Result<(), StoreError> {
    if event.version != "audit-v1"
        || event.tenant.is_empty()
        || event.tenant.len() > 128
        || event.site_key.is_empty()
        || event.site_key.len() > 256
        || event.action.is_empty()
        || event.action.len() > 128
        || [
            event.tenant.as_str(),
            event.site_key.as_str(),
            event.action.as_str(),
        ]
        .iter()
        .any(|value| value.chars().any(char::is_control))
        || event.tier.is_some_and(|tier| tier > 32)
        || event.kind.is_empty()
        || event.kind.len() > 64
        || !matches!(
            event.kind.as_str(),
            "challenge_issued"
                | "proof_redeemed"
                | "site_verified"
                | "fallback_completed"
                | "proof_failed"
                | "verification_failed"
        )
        || event
            .backend
            .as_deref()
            .is_some_and(|backend| !matches!(backend, "webgpu" | "webgl2" | "css"))
        || event.code.as_deref().is_some_and(|code| {
            code.is_empty()
                || code.len() > 128
                || !code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(StoreError);
    }
    Ok(())
}

#[derive(Clone)]
struct PressureKeys {
    action: String,
    client: String,
    network: Option<String>,
    outstanding: String,
    sequence: String,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct PressureKeyScope {
    tenant: String,
    site_key: String,
    action: String,
    session_binding: Option<String>,
    network_pseudonym: Option<String>,
}

impl From<&ChallengeRequest> for PressureKeyScope {
    fn from(input: &ChallengeRequest) -> Self {
        Self {
            tenant: input.tenant.clone(),
            site_key: input.site_key.clone(),
            action: input.action.clone(),
            session_binding: input.session_binding.clone(),
            network_pseudonym: input.network_pseudonym.clone(),
        }
    }
}

const MAX_PRESSURE_KEY_CACHE_ENTRIES: usize = 1_024;

#[derive(Default)]
struct PressureKeyCache(RwLock<HashMap<PressureKeyScope, PressureKeys>>);

impl PressureKeyCache {
    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.read().map_or(0, |entries| entries.len())
    }
}

impl PressureKeyCache {
    fn values(&self, input: &ChallengeRequest) -> Result<PressureKeys, StoreError> {
        let scope = PressureKeyScope::from(input);
        if let Some(keys) = self.0.read().map_err(|_| StoreError)?.get(&scope) {
            return Ok(keys.clone());
        }
        let keys = PressureKeys::new(input);
        let mut entries = self.0.write().map_err(|_| StoreError)?;
        if let Some(existing) = entries.get(&scope) {
            return Ok(existing.clone());
        }
        if entries.len() >= MAX_PRESSURE_KEY_CACHE_ENTRIES {
            let oldest = entries.keys().next().cloned().ok_or(StoreError)?;
            entries.remove(&oldest);
        }
        entries.insert(scope, keys.clone());
        Ok(keys)
    }
}

impl PressureKeys {
    fn new(input: &ChallengeRequest) -> Self {
        let base = format!("{}\0{}\0{}", input.tenant, input.site_key, input.action);
        let tag = digest("shar/redis/action/v1\0", &base);
        let prefix = format!("shar:{{{tag}}}");
        let client = digest(
            "shar/redis/client/v1\0",
            input.session_binding.as_deref().unwrap_or(""),
        );
        Self {
            action: format!("{prefix}:action"),
            client: format!("{prefix}:client:{client}"),
            network: input.network_pseudonym.as_ref().map(|network| {
                format!(
                    "{prefix}:network:{}",
                    digest("shar/redis/network/v1\0", network)
                )
            }),
            outstanding: format!("{prefix}:outstanding"),
            sequence: format!("{prefix}:sequence"),
        }
    }

    fn failure(&self, input: &ChallengeRequest) -> String {
        if input.session_binding.is_some() || self.network.is_none() {
            self.client.clone()
        } else {
            self.network.clone().expect("network present")
        }
    }
}

fn digest(domain: &str, value: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update(value.as_bytes());
    URL_SAFE_NO_PAD.encode(&hash.finalize()[..16])
}

fn audit_key(tenant: &str, site_key: &str, action: &str) -> String {
    let tag = digest(
        "shar/redis/audit/v1\0",
        &format!("{tenant}\0{site_key}\0{action}"),
    );
    format!("shar:{{{tag}}}:audit")
}

fn tier(value: i64) -> Result<u8, StoreError> {
    let value = u8::try_from(value).map_err(|_| StoreError)?;
    if value > 32 {
        return Err(StoreError);
    }
    Ok(value)
}

fn pressure_from_values(values: &[i64]) -> Result<PressureInput, StoreError> {
    if values.len() != 7 {
        return Err(StoreError);
    }
    Ok(PressureInput {
        base_tier: tier(values[0])?,
        velocity_tier: tier(values[1])?,
        outstanding_tier: tier(values[2])?,
        network_tier: tier(values[3])?,
        failure_debt: tier(values[4])?,
        assurance_debt: tier(values[5])?,
        trust_credits: tier(values[6])?,
    })
}

fn inclusive_nonce_expiry(expires_at: u64) -> Result<u64, StoreError> {
    // Keep the one-second retention marker inside Redis Lua's exact integer
    // range, matching the pure-TypeScript adapter's Number contract.
    if expires_at >= LUA_MAX_INTEGER {
        return Err(StoreError);
    }
    expires_at.checked_add(1).ok_or(StoreError)
}

fn validate_lua_integer(value: u64) -> Result<(), StoreError> {
    if value > LUA_MAX_INTEGER {
        return Err(StoreError);
    }
    Ok(())
}

fn validate_lua_deadline(
    now: u64,
    expires_at: u64,
    retention_seconds: u64,
) -> Result<(), StoreError> {
    validate_lua_integer(now)?;
    validate_lua_integer(expires_at)?;
    if now > LUA_MAX_INTEGER.saturating_sub(retention_seconds)
        || expires_at > LUA_MAX_INTEGER.saturating_sub(3600)
    {
        return Err(StoreError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        thread,
    };

    fn answer_until_ping(stream: &mut TcpStream) {
        let mut request = [0_u8; 512];
        loop {
            let length = stream.read(&mut request).expect("read Redis command");
            assert_ne!(length, 0, "Redis client closed before PING");
            let request = &request[..length];
            if request.windows(b"PING".len()).any(|part| part == b"PING") {
                stream.write_all(b"+PONG\r\n").expect("write PONG");
                stream.flush().expect("flush PONG");
                return;
            }
            // redis-rs sends one or more best-effort CLIENT SETINFO commands
            // when a connection is established. Acknowledge every RESP array
            // before waiting for the health probe used by this regression.
            let commands = request
                .iter()
                .enumerate()
                .filter(|(index, byte)| {
                    **byte == b'*' && (*index == 0 || request[*index - 1] == b'\n')
                })
                .count();
            assert_ne!(commands, 0, "unexpected Redis handshake");
            for _ in 0..commands {
                stream.write_all(b"+OK\r\n").expect("acknowledge handshake");
            }
            stream.flush().expect("flush handshake reply");
        }
    }

    #[test]
    #[ignore = "requires a loopback TCP listener; CI runs this test explicitly"]
    fn failed_connection_is_not_retried_and_the_next_request_reconnects() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock Redis");
        let address = listener.local_addr().expect("mock Redis address");
        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().expect("first Redis connection");
            answer_until_ping(&mut first);
            first
                .shutdown(Shutdown::Both)
                .expect("drop first Redis connection");

            let (mut second, _) = listener.accept().expect("reconnected Redis connection");
            answer_until_ping(&mut second);
        });

        let client = low_latency_client(&format!("redis://{address}"))
            .expect("construct reconnecting Redis client");
        let store = RedisStore::from_client(client, 1, 172_800, Duration::from_secs(1))
            .expect("construct Redis pool");
        assert!(store.check_health().is_ok());
        thread::sleep(Duration::from_millis(20));

        // The first operation after the disconnect fails instead of being
        // replayed with an ambiguous outcome. It discards the dead socket.
        assert!(store.check_health().is_err());
        // A separate request establishes a new connection and recovers.
        assert!(store.check_health().is_ok());
        server.join().expect("mock Redis server");
    }

    #[test]
    fn pressure_keys_match_typescript_vectors_and_hide_inputs() {
        let input = ChallengeRequest {
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: "signup".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: Some("private-session".into()),
            network_pseudonym: Some("daily-network".into()),
            assurance_tier: None,
            trust_token: None,
        };
        let keys = PressureKeys::new(&input);
        assert_eq!(keys.action, "shar:{99-im6AWtLvdOHO8SreaEg}:action");
        assert!(
            keys.client
                .starts_with("shar:{99-im6AWtLvdOHO8SreaEg}:client:")
        );
        assert!(!keys.client.contains("private-session"));
        assert!(!keys.network.unwrap().contains("daily-network"));
    }

    #[test]
    fn pressure_key_cache_reuses_exact_scopes_and_invalidates_bindings() {
        let cache = PressureKeyCache::default();
        let input = ChallengeRequest {
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: "signup".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: Some("session-a".into()),
            network_pseudonym: Some("network-a".into()),
            assurance_tier: None,
            trust_token: None,
        };
        let first = cache.values(&input).unwrap();
        let same = cache.values(&input).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(first.action, same.action);
        assert_eq!(first.client, same.client);
        assert_eq!(first.network, same.network);

        let mut changed = input;
        changed.session_binding = Some("session-b".into());
        let session = cache.values(&changed).unwrap();
        assert_eq!(cache.len(), 2);
        assert_eq!(first.action, session.action);
        assert_ne!(first.client, session.client);
        assert_eq!(first.network, session.network);

        changed.network_pseudonym = Some("network-b".into());
        let network = cache.values(&changed).unwrap();
        assert_eq!(cache.len(), 3);
        assert_eq!(session.action, network.action);
        assert_eq!(session.client, network.client);
        assert_ne!(session.network, network.network);

        for index in 0..MAX_PRESSURE_KEY_CACHE_ENTRIES {
            changed.action = format!("action-{index}");
            cache.values(&changed).unwrap();
        }
        assert!(cache.len() <= MAX_PRESSURE_KEY_CACHE_ENTRIES);
    }

    #[test]
    fn latency_sensitive_redis_connections_disable_nagle() {
        let client = low_latency_client("redis://127.0.0.1:6379").unwrap();
        assert!(client.get_connection_info().tcp_settings().nodelay());
    }

    #[test]
    fn nonce_expiry_retains_the_inclusive_boundary_without_wrapping() {
        assert_eq!(
            inclusive_nonce_expiry(1_900_000_000).unwrap(),
            1_900_000_001
        );
        assert!(inclusive_nonce_expiry(LUA_MAX_INTEGER).is_err());
        assert!(inclusive_nonce_expiry(u64::MAX).is_err());
    }

    #[test]
    fn lua_deadline_rejects_unrepresentable_exact_integer_arithmetic() {
        assert!(validate_lua_deadline(100, 1_900_000_000, 172_800).is_ok());
        assert!(validate_lua_deadline(LUA_MAX_INTEGER - 100, 1_900_000_000, 172_800).is_err());
        assert!(validate_lua_deadline(100, LUA_MAX_INTEGER - 1, 172_800).is_err());
        assert!(validate_lua_integer(LUA_MAX_INTEGER).is_ok());
        assert!(validate_lua_integer(LUA_MAX_INTEGER + 1).is_err());
    }

    #[test]
    fn expiry_argument_cache_matches_every_exact_tier_and_invalidates() {
        let cache = ExpiryArgumentCache::default();
        let policy = shar_core::default_work_policy();
        let now = 1_900_000_000;
        let first = cache.values(&policy, now, 172_800).unwrap();
        assert_eq!(first.len(), 33);
        for (tier, expires_at) in first.iter().enumerate() {
            let quote = price_work(
                &PressureInput {
                    base_tier: tier as u8,
                    ..PressureInput::default()
                },
                &policy,
                now,
            )
            .unwrap();
            assert_eq!(expires_at, &quote.expires_at.to_string());
        }
        let same = cache.values(&policy, now, 172_800).unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        let later = cache.values(&policy, now + 1, 172_800).unwrap();
        assert!(!Arc::ptr_eq(&first, &later));
        assert_eq!(
            later[0].parse::<u64>().unwrap(),
            first[0].parse::<u64>().unwrap() + 1
        );
    }

    #[test]
    fn pressure_script_uses_exact_integer_tiers() {
        assert!(!READ_PRESSURE.contains("math.log"));
        assert!(!READ_PRESSURE.contains("local function ensure"));
        assert!(READ_PRESSURE.contains("threshold=threshold*2"));
        assert!(READ_PRESSURE.contains("local base=tonumber(cv[4]) or 0"));
        assert!(READ_PRESSURE.contains("local aw=tonumber(av[1]) or now"));
        assert!(READ_PRESSURE.contains("ZREMRANGEBYSCORE',KEYS[4],'-inf','('..tostring(now)"));
        assert!(RECORD_OUTCOME.contains("ZRANGEBYSCORE"));
        assert!(RECORD_OUTCOME.contains("tostring(expires)"));
        assert!(!RECORD_OUTCOME.contains("local oldest"));
    }

    #[test]
    fn audit_script_allocates_one_sequence_range_and_one_sorted_set_write() {
        assert!(RECORD_AUDIT.contains("redis.call('INCRBY',KEYS[2],count)"));
        assert!(!RECORD_AUDIT.contains("redis.call('INCR',"));
        assert_eq!(RECORD_AUDIT.matches("redis.call('ZADD'").count(), 1);
        assert!(RECORD_AUDIT.contains("first+item-1"));
    }
}
