use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use shar_core::{
    AuditEvent, AuditStore, ChallengeRequest, ConfigStore, FailureKind, NonceStore, PressureInput,
    PressureStore, StoreError, WorkPolicy, WorkQuote, price_work,
};
use std::{
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct SqliteStore {
    connection: Mutex<Connection>,
    default_policy: WorkPolicy,
}
type PolicyRow = (String, String, u32, u64, u64, String, u64, u64);

impl SqliteStore {
    pub fn open(
        path: impl AsRef<Path>,
        default_policy: WorkPolicy,
    ) -> Result<Self, rusqlite::Error> {
        Self::open_with_timeout(path, default_policy, Duration::from_secs(5))
    }

    pub fn open_with_timeout(
        path: impl AsRef<Path>,
        default_policy: WorkPolicy,
        busy_timeout: Duration,
    ) -> Result<Self, rusqlite::Error> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(busy_timeout)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS nonce_consumptions(namespace TEXT NOT NULL,nonce TEXT NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(namespace,nonce)) STRICT;
          CREATE TABLE IF NOT EXISTS pressure(scope TEXT PRIMARY KEY,base_tier INTEGER NOT NULL DEFAULT 0,network_tier INTEGER NOT NULL DEFAULT 0,failure_debt INTEGER NOT NULL DEFAULT 0,assurance_debt INTEGER NOT NULL DEFAULT 0,trust_credits INTEGER NOT NULL DEFAULT 0,last_activity INTEGER NOT NULL,window_start INTEGER NOT NULL,request_count INTEGER NOT NULL DEFAULT 0) STRICT;
          CREATE TABLE IF NOT EXISTS outstanding(id INTEGER PRIMARY KEY,scope TEXT NOT NULL,expires_at INTEGER NOT NULL) STRICT;
          CREATE INDEX IF NOT EXISTS outstanding_scope_expiry ON outstanding(scope,expires_at);
          CREATE TABLE IF NOT EXISTS outstanding_counts(scope TEXT PRIMARY KEY,count INTEGER NOT NULL CHECK(count>=0)) STRICT;
          CREATE TRIGGER IF NOT EXISTS outstanding_count_after_insert AFTER INSERT ON outstanding BEGIN
            INSERT INTO outstanding_counts(scope,count) VALUES(NEW.scope,1)
            ON CONFLICT(scope) DO UPDATE SET count=CASE WHEN count>=9007199254740991 THEN 9007199254740991 ELSE count+1 END;
          END;
          CREATE TRIGGER IF NOT EXISTS outstanding_count_after_delete AFTER DELETE ON outstanding BEGIN
            UPDATE outstanding_counts SET count=MAX(0,count-1) WHERE scope=OLD.scope;
          END;
          CREATE TABLE IF NOT EXISTS policies(tenant TEXT NOT NULL,site_key TEXT NOT NULL,action TEXT NOT NULL,version TEXT NOT NULL,base_iterations TEXT NOT NULL,base_render_rounds INTEGER NOT NULL,quiet_window_seconds INTEGER NOT NULL,base_lifetime_seconds INTEGER NOT NULL,iteration_allowance TEXT NOT NULL,round_allowance_seconds INTEGER NOT NULL,max_lifetime_seconds INTEGER NOT NULL,PRIMARY KEY(tenant,site_key,action)) STRICT;
          CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,version TEXT NOT NULL CHECK(version='audit-v1'),kind TEXT NOT NULL,occurred_at INTEGER NOT NULL CHECK(occurred_at>=0),tenant TEXT NOT NULL,site_key TEXT NOT NULL,action TEXT NOT NULL,tier INTEGER CHECK(tier BETWEEN 0 AND 32),backend TEXT CHECK(backend IN ('webgpu','webgl2','css') OR backend IS NULL),code TEXT) STRICT;
          CREATE INDEX IF NOT EXISTS audit_events_expiry ON audit_events(occurred_at);")?;
        connection.execute(
            "INSERT OR IGNORE INTO outstanding_counts(scope,count) SELECT scope,COUNT(*) FROM outstanding GROUP BY scope",
            [],
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            default_policy,
        })
    }

    fn check_health(&self) -> Result<(), StoreError> {
        let value: i64 = self
            .connection
            .lock()
            .map_err(|_| StoreError)?
            .query_row("SELECT 1", [], |row| row.get(0))
            .map_err(|_| StoreError)?;
        if value == 1 { Ok(()) } else { Err(StoreError) }
    }
    fn base_scope(input: &ChallengeRequest) -> String {
        format!("{}\0{}\0{}", input.tenant, input.site_key, input.action)
    }
    fn action_scope(input: &ChallengeRequest) -> String {
        format!("action\0{}", Self::base_scope(input))
    }
    fn client_scope(input: &ChallengeRequest) -> String {
        format!(
            "client\0{}\0{}",
            Self::base_scope(input),
            input.session_binding.as_deref().unwrap_or("")
        )
    }
    fn network_scope(input: &ChallengeRequest) -> Option<String> {
        input
            .network_pseudonym
            .as_ref()
            .map(|network| format!("network\0{}\0{network}", Self::base_scope(input)))
    }
    fn failure_scope(input: &ChallengeRequest) -> String {
        if input.session_binding.is_some() || input.network_pseudonym.is_none() {
            Self::client_scope(input)
        } else {
            Self::network_scope(input).expect("network pseudonym present")
        }
    }
}

impl NonceStore for SqliteStore {
    fn health(&self) -> Result<(), StoreError> {
        self.check_health()
    }

    fn consume(&self, namespace: &str, nonce: &[u8], expires_at: u64) -> Result<bool, StoreError> {
        let expires = i64::try_from(expires_at).map_err(|_| StoreError)?;
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| StoreError)?
                .as_secs(),
        )
        .map_err(|_| StoreError)?;
        let mut c = self.connection.lock().map_err(|_| StoreError)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError)?;
        tx.execute("DELETE FROM nonce_consumptions WHERE expires_at<?1", [now])
            .map_err(|_| StoreError)?;
        let changed=tx.execute("INSERT OR IGNORE INTO nonce_consumptions(namespace,nonce,expires_at) VALUES(?1,?2,?3)",params![namespace,nonce,expires]).map_err(|_|StoreError)?;
        tx.commit().map_err(|_| StoreError)?;
        Ok(changed == 1)
    }
}

impl PressureStore for SqliteStore {
    fn health(&self) -> Result<(), StoreError> {
        self.check_health()
    }

    fn read(
        &self,
        input: &ChallengeRequest,
        now: u64,
        quiet_window_seconds: u64,
    ) -> Result<PressureInput, StoreError> {
        let stored_now = i64::try_from(now).map_err(|_| StoreError)?;
        let quiet = i64::try_from(quiet_window_seconds).map_err(|_| StoreError)?;
        if quiet <= 0 {
            return Err(StoreError);
        }
        let mut connection = self.connection.lock().map_err(|_| StoreError)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError)?;
        let pressure = read_pressure_transaction(&transaction, input, stored_now, quiet)?;
        transaction.commit().map_err(|_| StoreError)?;
        Ok(pressure)
    }
    fn price_and_record(
        &self,
        input: &ChallengeRequest,
        policy: &WorkPolicy,
        now: u64,
    ) -> Result<WorkQuote, StoreError> {
        let stored_now = i64::try_from(now).map_err(|_| StoreError)?;
        let quiet = i64::try_from(policy.quiet_window_seconds).map_err(|_| StoreError)?;
        if quiet <= 0 {
            return Err(StoreError);
        }
        let mut connection = self.connection.lock().map_err(|_| StoreError)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError)?;
        let pressure = read_pressure_transaction(&transaction, input, stored_now, quiet)?;
        let quote = price_work(&pressure, policy, now).map_err(|_| StoreError)?;
        let expires = i64::try_from(quote.expires_at).map_err(|_| StoreError)?;
        let scope = Self::action_scope(input);
        transaction
            .prepare_cached("INSERT INTO outstanding(scope,expires_at) VALUES(?1,?2)")
            .map_err(|_| StoreError)?
            .execute(params![scope, expires])
            .map_err(|_| StoreError)?;
        transaction.commit().map_err(|_| StoreError)?;
        Ok(quote)
    }
    fn record_issued(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        let scope = Self::action_scope(input);
        let expires = i64::try_from(expires_at).map_err(|_| StoreError)?;
        let now = i64::try_from(now).map_err(|_| StoreError)?;
        let mut c = self.connection.lock().map_err(|_| StoreError)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError)?;
        ensure_pressure(&tx, &scope, now)?;
        tx.execute(
            "INSERT INTO outstanding(scope,expires_at) VALUES(?1,?2)",
            params![scope, expires],
        )
        .map_err(|_| StoreError)?;
        tx.execute(
            "UPDATE pressure SET last_activity=?1 WHERE scope=?2",
            params![now, scope],
        )
        .map_err(|_| StoreError)?;
        tx.commit().map_err(|_| StoreError)
    }
    fn record_success(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        let failure_scope = Self::failure_scope(input);
        let action_scope = Self::action_scope(input);
        let expires_at = i64::try_from(expires_at).map_err(|_| StoreError)?;
        let now = i64::try_from(now).map_err(|_| StoreError)?;
        let mut c = self.connection.lock().map_err(|_| StoreError)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError)?;
        ensure_pressure(&tx, &failure_scope, now)?;
        tx.execute("UPDATE pressure SET failure_debt=MAX(0,failure_debt-1),last_activity=?1 WHERE scope=?2",params![now,failure_scope]).map_err(|_|StoreError)?;
        tx.execute("DELETE FROM outstanding WHERE id=(SELECT id FROM outstanding WHERE scope=?1 AND expires_at=?2 ORDER BY id LIMIT 1)",params![action_scope,expires_at]).map_err(|_|StoreError)?;
        tx.commit().map_err(|_| StoreError)
    }
    fn record_failure(
        &self,
        input: &ChallengeRequest,
        kind: FailureKind,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        let failure_scope = Self::failure_scope(input);
        let action_scope = Self::action_scope(input);
        let expires_at = i64::try_from(expires_at).map_err(|_| StoreError)?;
        let now = i64::try_from(now).map_err(|_| StoreError)?;
        let mut c = self.connection.lock().map_err(|_| StoreError)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError)?;
        ensure_pressure(&tx, &failure_scope, now)?;
        tx.execute("UPDATE pressure SET failure_debt=MIN(32,failure_debt+1),last_activity=?1 WHERE scope=?2",params![now,failure_scope]).map_err(|_|StoreError)?;
        if kind == FailureKind::Expired {
            tx.execute("DELETE FROM outstanding WHERE id=(SELECT id FROM outstanding WHERE scope=?1 AND expires_at=?2 ORDER BY id LIMIT 1)",params![action_scope,expires_at]).map_err(|_|StoreError)?;
        }
        tx.commit().map_err(|_| StoreError)
    }

    fn record_trust(&self, input: &ChallengeRequest, now: u64) -> Result<(), StoreError> {
        // Trust credits never reduce the rotating network-pressure bucket.
        let failure_scope = Self::client_scope(input);
        let now = i64::try_from(now).map_err(|_| StoreError)?;
        let mut c = self.connection.lock().map_err(|_| StoreError)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError)?;
        ensure_pressure(&tx, &failure_scope, now)?;
        tx.execute(
            "UPDATE pressure SET failure_debt=CASE WHEN failure_debt>0 THEN failure_debt-1 ELSE failure_debt END, assurance_debt=CASE WHEN failure_debt=0 THEN MAX(0,assurance_debt-1) ELSE assurance_debt END,last_activity=?1 WHERE scope=?2",
            params![now, failure_scope],
        )
        .map_err(|_| StoreError)?;
        tx.commit().map_err(|_| StoreError)
    }
}

impl ConfigStore for SqliteStore {
    fn health(&self) -> Result<(), StoreError> {
        self.check_health()
    }

    fn policy(&self, tenant: &str, site_key: &str, action: &str) -> Result<WorkPolicy, StoreError> {
        let c = self.connection.lock().map_err(|_| StoreError)?;
        let row:Option<PolicyRow>=c.query_row("SELECT version,base_iterations,base_render_rounds,quiet_window_seconds,base_lifetime_seconds,iteration_allowance,round_allowance_seconds,max_lifetime_seconds FROM policies WHERE tenant=?1 AND site_key=?2 AND action=?3",params![tenant,site_key,action],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional().map_err(|_|StoreError)?;
        match row {
            None => Ok(self.default_policy.clone()),
            Some((
                version,
                iterations,
                rounds,
                quiet,
                lifetime,
                allowance,
                round_allowance,
                max_lifetime,
            )) => Ok(WorkPolicy {
                version,
                base_iterations: iterations.parse().map_err(|_| StoreError)?,
                base_render_rounds: rounds,
                quiet_window_seconds: quiet,
                base_lifetime_seconds: lifetime,
                iteration_allowance: allowance.parse().map_err(|_| StoreError)?,
                round_allowance_seconds: round_allowance,
                max_lifetime_seconds: max_lifetime,
            }),
        }
    }

    fn set_policy(
        &self,
        tenant: &str,
        site_key: &str,
        action: &str,
        policy: &WorkPolicy,
    ) -> Result<(), StoreError> {
        self.connection.lock().map_err(|_| StoreError)?.execute("INSERT INTO policies VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) ON CONFLICT(tenant,site_key,action) DO UPDATE SET version=excluded.version,base_iterations=excluded.base_iterations,base_render_rounds=excluded.base_render_rounds,quiet_window_seconds=excluded.quiet_window_seconds,base_lifetime_seconds=excluded.base_lifetime_seconds,iteration_allowance=excluded.iteration_allowance,round_allowance_seconds=excluded.round_allowance_seconds,max_lifetime_seconds=excluded.max_lifetime_seconds",params![tenant,site_key,action,policy.version,policy.base_iterations.to_string(),policy.base_render_rounds,policy.quiet_window_seconds,policy.base_lifetime_seconds,policy.iteration_allowance.to_string(),policy.round_allowance_seconds,policy.max_lifetime_seconds]).map_err(|_|StoreError)?;
        Ok(())
    }
}

impl AuditStore for SqliteStore {
    fn record(&self, event: &AuditEvent) -> Result<(), StoreError> {
        validate_audit_event(event)?;
        let occurred_at = i64::try_from(event.occurred_at).map_err(|_| StoreError)?;
        let cutoff = occurred_at.saturating_sub(86_400);
        let mut c = self.connection.lock().map_err(|_| StoreError)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError)?;
        tx.execute(
            "INSERT INTO audit_events(version,kind,occurred_at,tenant,site_key,action,tier,backend,code) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                event.version,
                event.kind,
                occurred_at,
                event.tenant,
                event.site_key,
                event.action,
                event.tier.map(i64::from),
                event.backend,
                event.code,
            ],
        )
        .map_err(|_| StoreError)?;
        tx.execute("DELETE FROM audit_events WHERE occurred_at<?1", [cutoff])
            .map_err(|_| StoreError)?;
        tx.commit().map_err(|_| StoreError)
    }

    fn record_batch(&self, events: &[AuditEvent]) -> Result<(), StoreError> {
        if events.is_empty() {
            return Ok(());
        }
        let mut occurred = Vec::with_capacity(events.len());
        for event in events {
            validate_audit_event(event)?;
            occurred.push(i64::try_from(event.occurred_at).map_err(|_| StoreError)?);
        }
        let cutoff = occurred
            .iter()
            .copied()
            .max()
            .ok_or(StoreError)?
            .saturating_sub(86_400);
        let mut connection = self.connection.lock().map_err(|_| StoreError)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError)?;
        {
            let mut statement = tx
                .prepare_cached(
                    "INSERT INTO audit_events(version,kind,occurred_at,tenant,site_key,action,tier,backend,code) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                )
                .map_err(|_| StoreError)?;
            for (event, occurred_at) in events.iter().zip(occurred) {
                statement
                    .execute(params![
                        event.version,
                        event.kind,
                        occurred_at,
                        event.tenant,
                        event.site_key,
                        event.action,
                        event.tier.map(i64::from),
                        event.backend,
                        event.code,
                    ])
                    .map_err(|_| StoreError)?;
            }
        }
        tx.execute("DELETE FROM audit_events WHERE occurred_at<?1", [cutoff])
            .map_err(|_| StoreError)?;
        tx.commit().map_err(|_| StoreError)
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
        let connection = self.connection.lock().map_err(|_| StoreError)?;
        let mut statement = connection
            .prepare("SELECT version,kind,occurred_at,tenant,site_key,action,tier,backend,code FROM audit_events WHERE tenant=?1 AND site_key=?2 AND action=?3 ORDER BY id DESC LIMIT ?4")
            .map_err(|_| StoreError)?;
        let rows = statement
            .query_map(params![tenant, site_key, action, i64::from(limit)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            })
            .map_err(|_| StoreError)?;
        rows.map(|row| {
            let (version, kind, occurred_at, tenant, site_key, action, tier, backend, code) =
                row.map_err(|_| StoreError)?;
            let event = AuditEvent {
                version,
                kind,
                occurred_at: u64::try_from(occurred_at).map_err(|_| StoreError)?,
                tenant,
                site_key,
                action,
                tier: tier
                    .map(|value| u8::try_from(value).map_err(|_| StoreError))
                    .transpose()?,
                backend,
                code,
            };
            validate_audit_event(&event)?;
            Ok(event)
        })
        .collect()
    }
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
        || !matches!(
            event.kind.as_str(),
            "challenge_issued"
                | "proof_redeemed"
                | "site_verified"
                | "fallback_completed"
                | "proof_failed"
                | "verification_failed"
        )
        || event.kind.is_empty()
        || event.kind.len() > 64
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

fn ensure_pressure(tx: &Transaction<'_>, scope: &str, now: i64) -> Result<(), StoreError> {
    tx.prepare_cached(
        "INSERT OR IGNORE INTO pressure(scope,last_activity,window_start) VALUES(?1,?2,?2)",
    )
    .map_err(|_| StoreError)?
    .execute(params![scope, now])
    .map_err(|_| StoreError)?;
    Ok(())
}

fn read_pressure_transaction(
    tx: &Transaction<'_>,
    input: &ChallengeRequest,
    now: i64,
    quiet: i64,
) -> Result<PressureInput, StoreError> {
    let action_scope = SqliteStore::action_scope(input);
    let client_scope = SqliteStore::client_scope(input);
    let network_scope = SqliteStore::network_scope(input);
    tx.prepare_cached("DELETE FROM outstanding WHERE scope=?1 AND expires_at<?2")
        .map_err(|_| StoreError)?
        .execute(params![action_scope, now])
        .map_err(|_| StoreError)?;
    let action_count: i64 = tx
        .prepare_cached(
            "INSERT INTO pressure(scope,last_activity,window_start,request_count) VALUES(?1,?2,?2,1)
             ON CONFLICT(scope) DO UPDATE SET
               last_activity=excluded.last_activity,
               request_count=CASE WHEN MAX(0,excluded.last_activity-pressure.window_start)>=?3 THEN 1 WHEN pressure.request_count>=9007199254740991 THEN 9007199254740991 ELSE pressure.request_count+1 END,
               window_start=CASE WHEN MAX(0,excluded.last_activity-pressure.window_start)>=?3 THEN excluded.last_activity ELSE pressure.window_start END
             RETURNING request_count",
        )
        .map_err(|_| StoreError)?
        .query_row(params![action_scope, now, quiet], |row| row.get(0))
        .map_err(|_| StoreError)?;
    let requested_assurance = i64::from(input.assurance_tier.unwrap_or(0));
    let persist_assurance = i64::from(input.session_binding.is_some());
    let (base, failure, stored_assurance, trust): (i64, i64, i64, i64) = tx
        .prepare_cached(
            "INSERT INTO pressure(scope,last_activity,window_start,assurance_debt) VALUES(?1,?2,?2,CASE WHEN ?4=1 THEN ?5 ELSE 0 END)
             ON CONFLICT(scope) DO UPDATE SET
               failure_debt=MAX(0,pressure.failure_debt-CAST(MAX(0,excluded.last_activity-pressure.last_activity)/?3 AS INTEGER)),
               assurance_debt=CASE WHEN ?4=1
                 THEN MAX(MAX(0,pressure.assurance_debt-CAST(MAX(0,excluded.last_activity-pressure.last_activity)/?3 AS INTEGER)),?5)
                 ELSE MAX(0,pressure.assurance_debt-CAST(MAX(0,excluded.last_activity-pressure.last_activity)/?3 AS INTEGER)) END,
               last_activity=excluded.last_activity
             RETURNING base_tier,failure_debt,assurance_debt,trust_credits",
        )
        .map_err(|_| StoreError)?
        .query_row(
            params![
                client_scope,
                now,
                quiet,
                persist_assurance,
                requested_assurance
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| StoreError)?;
    let assurance = stored_assurance.max(requested_assurance);
    let mut network_tier = 0;
    if let Some(scope) = network_scope.as_deref() {
        let (configured, network_failure, count): (i64, i64, i64) = tx
            .prepare_cached(
                "INSERT INTO pressure(scope,last_activity,window_start,request_count) VALUES(?1,?2,?2,1)
                 ON CONFLICT(scope) DO UPDATE SET
                   failure_debt=MAX(0,pressure.failure_debt-CAST(MAX(0,excluded.last_activity-pressure.last_activity)/?3 AS INTEGER)),
                   last_activity=excluded.last_activity,
                   request_count=CASE WHEN MAX(0,excluded.last_activity-pressure.window_start)>=?3 THEN 1 WHEN pressure.request_count>=9007199254740991 THEN 9007199254740991 ELSE pressure.request_count+1 END,
                   window_start=CASE WHEN MAX(0,excluded.last_activity-pressure.window_start)>=?3 THEN excluded.last_activity ELSE pressure.window_start END
                 RETURNING network_tier,failure_debt,request_count",
            )
            .map_err(|_| StoreError)?
            .query_row(params![scope, now, quiet], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|_| StoreError)?;
        network_tier = configured
            .max(network_failure)
            .max(i64::from(logarithmic_tier(
                u64::try_from(count).map_err(|_| StoreError)?,
            )));
    }
    let outstanding: i64 = tx
        .prepare_cached("SELECT COALESCE((SELECT count FROM outstanding_counts WHERE scope=?1),0)")
        .map_err(|_| StoreError)?
        .query_row([&action_scope], |row| row.get(0))
        .map_err(|_| StoreError)?;
    Ok(PressureInput {
        base_tier: to_u8(base)?,
        velocity_tier: logarithmic_tier(u64::try_from(action_count).map_err(|_| StoreError)?),
        outstanding_tier: logarithmic_tier(
            u64::try_from(outstanding)
                .map_err(|_| StoreError)?
                .saturating_add(1),
        ),
        network_tier: to_u8(network_tier)?,
        failure_debt: to_u8(failure)?,
        assurance_debt: to_u8(assurance)?,
        trust_credits: to_u8(trust)?,
    })
}

fn to_u8(value: i64) -> Result<u8, StoreError> {
    u8::try_from(value).map_err(|_| StoreError)
}
fn logarithmic_tier(count: u64) -> u8 {
    if count <= 1 {
        0
    } else {
        (u64::BITS - (count - 1).leading_zeros()).min(32) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};
    fn policy() -> WorkPolicy {
        WorkPolicy {
            version: "test".into(),
            base_iterations: 16,
            base_render_rounds: 1,
            quiet_window_seconds: 10,
            base_lifetime_seconds: 120,
            iteration_allowance: 1000,
            round_allowance_seconds: 1,
            max_lifetime_seconds: 86400,
        }
    }
    fn request() -> ChallengeRequest {
        ChallengeRequest {
            tenant: "tenant".into(),
            site_key: "site".into(),
            action: "submit".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: None,
            network_pseudonym: None,
            assurance_tier: None,
            trust_token: None,
        }
    }
    #[test]
    fn atomic_state_persists_and_pressure_decays() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        let store = Arc::new(SqliteStore::open(&path, policy()).unwrap());
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let store = Arc::clone(&store);
                thread::spawn(move || store.consume("challenge", &[7; 16], 4_000_000_000).unwrap())
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
        let r = request();
        assert_eq!(store.read(&r, 100, 10).unwrap().velocity_tier, 0);
        store.record_issued(&r, 200, 100).unwrap();
        assert_eq!(store.read(&r, 101, 10).unwrap().outstanding_tier, 1);
        store
            .record_failure(&r, FailureKind::Invalid, 200, 101)
            .unwrap();
        assert_eq!(store.read(&r, 102, 10).unwrap().failure_debt, 1);
        assert_eq!(store.read(&r, 123, 10).unwrap().failure_debt, 0);
        let custom = WorkPolicy {
            version: "custom".into(),
            ..policy()
        };
        store
            .set_policy("tenant", "site", "submit", &custom)
            .unwrap();
        assert_eq!(
            store.policy("tenant", "site", "submit").unwrap().version,
            "custom"
        );
        drop(store);
        let reopened = SqliteStore::open(path, policy()).unwrap();
        assert!(
            !reopened
                .consume("challenge", &[7; 16], 4_000_000_000)
                .unwrap()
        );
        assert_eq!(
            reopened.policy("tenant", "site", "submit").unwrap().version,
            "custom"
        );
    }

    #[test]
    fn configured_busy_timeout_is_applied_to_sqlite_connections() {
        let directory = tempfile::tempdir().unwrap();
        let store = SqliteStore::open_with_timeout(
            directory.path().join("state.sqlite"),
            policy(),
            Duration::from_millis(750),
        )
        .unwrap();
        let configured: u64 = store
            .connection
            .lock()
            .unwrap()
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(configured, 750);
    }

    #[test]
    fn pricing_and_reservation_share_one_immediate_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let mut work_policy = policy();
        work_policy.base_iterations = 1;
        work_policy.iteration_allowance = 1_000_000;
        work_policy.round_allowance_seconds = 0;
        let store = Arc::new(
            SqliteStore::open(directory.path().join("state.sqlite"), work_policy.clone()).unwrap(),
        );
        let handles: Vec<_> = (0..64)
            .map(|_| {
                let store = store.clone();
                let input = request();
                let work_policy = work_policy.clone();
                thread::spawn(move || {
                    store
                        .price_and_record(&input, &work_policy, 1_800_000_000)
                        .unwrap()
                        .tier
                })
            })
            .collect();
        let mut tiers: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        tiers.sort_unstable();
        assert_eq!(
            tiers,
            (1_u64..=64)
                .map(|count| logarithmic_tier(count) * 2)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn network_failures_are_capped_separately_from_session_debt() {
        let directory = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(directory.path().join("state.sqlite"), policy()).unwrap();
        let mut network = request();
        network.network_pseudonym = Some("daily-network-a".into());
        store.read(&network, 100, 10).unwrap();
        for _ in 0..32 {
            store
                .record_failure(&network, FailureKind::Invalid, 200, 101)
                .unwrap();
        }
        let pressured = store.read(&network, 102, 10).unwrap();
        assert_eq!(pressured.failure_debt, 0);
        assert_eq!(pressured.network_tier, 32);
        let mut other_network = request();
        other_network.network_pseudonym = Some("daily-network-b".into());
        assert_eq!(store.read(&other_network, 102, 10).unwrap().network_tier, 0);
        let mut session = network;
        session.session_binding = Some("host-session".into());
        store
            .record_failure(&session, FailureKind::Invalid, 200, 103)
            .unwrap();
        assert_eq!(store.read(&session, 104, 10).unwrap().failure_debt, 1);
    }

    #[test]
    fn audit_events_are_retained_without_request_fingerprints() {
        let directory = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(directory.path().join("state.sqlite"), policy()).unwrap();
        store
            .record(&AuditEvent {
                version: "audit-v1".into(),
                kind: "proof_redeemed".into(),
                occurred_at: 100_000,
                tenant: "tenant".into(),
                site_key: "site".into(),
                action: "submit".into(),
                tier: Some(2),
                backend: Some("css".into()),
                code: None,
            })
            .unwrap();
        store
            .record(&AuditEvent {
                version: "audit-v1".into(),
                kind: "site_verified".into(),
                occurred_at: 186_401,
                tenant: "tenant".into(),
                site_key: "site".into(),
                action: "submit".into(),
                tier: None,
                backend: None,
                code: None,
            })
            .unwrap();
        let connection = store.connection.lock().unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        assert!(
            connection
                .query_row("SELECT origin FROM audit_events LIMIT 1", [], |row| row
                    .get::<_, String>(
                    0
                ),)
                .is_err()
        );
    }

    #[test]
    fn audit_batches_commit_together_and_prune_once() {
        let directory = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(directory.path().join("state.sqlite"), policy()).unwrap();
        let event = |kind: &str, occurred_at| AuditEvent {
            version: "audit-v1".into(),
            kind: kind.into(),
            occurred_at,
            tenant: "tenant".into(),
            site_key: "site".into(),
            action: "submit".into(),
            tier: None,
            backend: None,
            code: None,
        };
        store
            .record_batch(&[
                event("proof_redeemed", 100_000),
                event("site_verified", 186_401),
                event("challenge_issued", 186_402),
            ])
            .unwrap();
        let events = store.list("tenant", "site", "submit", 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "challenge_issued");
        assert_eq!(events[1].kind, "site_verified");

        let mut invalid = event("proof_redeemed", 186_403);
        invalid.code = Some("raw ip".into());
        assert!(
            store
                .record_batch(&[event("proof_redeemed", 186_403), invalid])
                .is_err()
        );
        assert_eq!(store.list("tenant", "site", "submit", 10).unwrap().len(), 2);
    }

    #[test]
    fn existing_outstanding_rows_initialize_and_update_the_counter() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        let scope = SqliteStore::action_scope(&request());
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE outstanding(id INTEGER PRIMARY KEY,scope TEXT NOT NULL,expires_at INTEGER NOT NULL) STRICT;",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO outstanding(scope,expires_at) VALUES(?1,200)",
                    [&scope],
                )
                .unwrap();
        }
        let store = SqliteStore::open(&path, policy()).unwrap();
        assert_eq!(store.read(&request(), 100, 10).unwrap().outstanding_tier, 1);
        store.record_success(&request(), 200, 101).unwrap();
        assert_eq!(store.read(&request(), 112, 10).unwrap().outstanding_tier, 0);
    }

    #[test]
    fn outcomes_remove_the_quote_with_the_exact_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(directory.path().join("state.sqlite"), policy()).unwrap();
        let request = request();
        store.record_issued(&request, 150, 100).unwrap();
        store.record_issued(&request, 300, 101).unwrap();
        store.record_success(&request, 300, 110).unwrap();
        assert_eq!(store.read(&request, 151, 60).unwrap().outstanding_tier, 0);

        store.record_issued(&request, 300, 200).unwrap();
        store.record_issued(&request, 250, 201).unwrap();
        store
            .record_failure(&request, FailureKind::Expired, 250, 251)
            .unwrap();
        assert_eq!(store.read(&request, 251, 60).unwrap().outstanding_tier, 1);
    }
}
