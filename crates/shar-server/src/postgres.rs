use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use postgres::{Client, Transaction, types::ToSql};
use shar_core::{
    AuditEvent, AuditStore, ChallengeRequest, ConfigStore, FailureKind, NonceStore, PressureInput,
    PressureStore, StoreError, WorkPolicy, WorkQuote, price_work,
};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

const DELETE_EXACT_OUTSTANDING: &str = "DELETE FROM shar_outstanding WHERE id=(SELECT id FROM shar_outstanding WHERE scope=$1 AND expires_at=$2 ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)";

pub const POSTGRES_SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS shar_nonce_consumptions (
  namespace text NOT NULL,
  nonce text NOT NULL,
  expires_at bigint NOT NULL CHECK (expires_at >= 0),
  PRIMARY KEY (namespace, nonce)
);
CREATE INDEX IF NOT EXISTS shar_nonce_expiry ON shar_nonce_consumptions (expires_at);
CREATE TABLE IF NOT EXISTS shar_pressure (
  scope text PRIMARY KEY,
  base_tier integer NOT NULL DEFAULT 0 CHECK (base_tier BETWEEN 0 AND 32),
  network_tier integer NOT NULL DEFAULT 0 CHECK (network_tier BETWEEN 0 AND 32),
  failure_debt integer NOT NULL DEFAULT 0 CHECK (failure_debt BETWEEN 0 AND 32),
  assurance_debt integer NOT NULL DEFAULT 0 CHECK (assurance_debt BETWEEN 0 AND 32),
  trust_credits integer NOT NULL DEFAULT 0 CHECK (trust_credits BETWEEN 0 AND 32),
  last_activity bigint NOT NULL CHECK (last_activity >= 0),
  window_start bigint NOT NULL CHECK (window_start >= 0),
  request_count bigint NOT NULL DEFAULT 0 CHECK (request_count >= 0)
);
CREATE TABLE IF NOT EXISTS shar_outstanding (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scope text NOT NULL,
  expires_at bigint NOT NULL CHECK (expires_at >= 0)
);
CREATE INDEX IF NOT EXISTS shar_outstanding_scope_expiry ON shar_outstanding (scope, expires_at);
CREATE TABLE IF NOT EXISTS shar_policies (
  tenant text NOT NULL,
  site_key text NOT NULL,
  action text NOT NULL,
  version text NOT NULL,
  base_iterations text NOT NULL CHECK (base_iterations ~ '^[0-9]+$'),
  base_render_rounds integer NOT NULL CHECK (base_render_rounds > 0),
  quiet_window_seconds bigint NOT NULL CHECK (quiet_window_seconds > 0),
  base_lifetime_seconds bigint NOT NULL CHECK (base_lifetime_seconds > 0),
  iteration_allowance text NOT NULL CHECK (iteration_allowance ~ '^[0-9]+$'),
  round_allowance_seconds bigint NOT NULL CHECK (round_allowance_seconds >= 0),
  max_lifetime_seconds bigint NOT NULL CHECK (max_lifetime_seconds > 0),
  PRIMARY KEY (tenant, site_key, action)
);
CREATE TABLE IF NOT EXISTS shar_audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  version text NOT NULL CHECK (version = 'audit-v1'),
  kind text NOT NULL CHECK (kind ~ '^[a-z_]{1,64}$'),
  occurred_at bigint NOT NULL CHECK (occurred_at >= 0),
  tenant text NOT NULL,
  site_key text NOT NULL,
  action text NOT NULL,
  tier integer CHECK (tier BETWEEN 0 AND 32),
  backend text CHECK (backend IN ('webgpu', 'webgl2', 'css')),
  code text CHECK (code ~ '^[a-z0-9_]{1,128}$')
);
CREATE INDEX IF NOT EXISTS shar_audit_events_expiry ON shar_audit_events (occurred_at);"#;

pub struct PostgresStore {
    clients: Vec<Mutex<Client>>,
    reconnect: Option<PostgresConnector>,
    next_client: AtomicUsize,
    default_policy: WorkPolicy,
}

pub type PostgresConnector = Arc<dyn Fn() -> Result<Client, postgres::Error> + Send + Sync>;

type PolicyRow = (String, String, i32, i64, i64, String, i64, i64);

impl PostgresStore {
    pub fn from_client(
        client: Client,
        default_policy: WorkPolicy,
    ) -> Result<Self, postgres::Error> {
        Self::from_clients(client, Vec::new(), default_policy)
    }

    pub fn from_clients(
        mut first: Client,
        additional: Vec<Client>,
        default_policy: WorkPolicy,
    ) -> Result<Self, postgres::Error> {
        first.batch_execute(POSTGRES_SCHEMA_V1)?;
        let clients = std::iter::once(first).chain(additional).collect::<Vec<_>>();
        Ok(Self {
            clients: clients.into_iter().map(Mutex::new).collect(),
            reconnect: None,
            next_client: AtomicUsize::new(0),
            default_policy,
        })
    }

    pub fn from_clients_with_reconnect(
        first: Client,
        additional: Vec<Client>,
        default_policy: WorkPolicy,
        reconnect: PostgresConnector,
    ) -> Result<Self, postgres::Error> {
        let mut store = Self::from_clients(first, additional, default_policy)?;
        store.reconnect = Some(reconnect);
        Ok(store)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Client>, StoreError> {
        let index = self.next_client.fetch_add(1, Ordering::Relaxed) % self.clients.len();
        let mut client = self.clients[index].lock().map_err(|_| StoreError)?;
        if client.is_closed() {
            let reconnect = self.reconnect.as_ref().ok_or(StoreError)?;
            *client = reconnect().map_err(|_| StoreError)?;
        }
        Ok(client)
    }

    fn check_health(&self) -> Result<(), StoreError> {
        let mut client = self.connection()?;
        if client.simple_query("SELECT 1").is_ok() {
            return Ok(());
        }
        // Do not turn the failed probe into a success: like mutations, its
        // outcome belongs to the request that used the old connection. Prepare
        // a replacement so the next independent readiness or protocol request
        // can recover without restarting the process.
        if let Some(reconnect) = &self.reconnect
            && let Ok(replacement) = reconnect()
        {
            *client = replacement;
        }
        Err(StoreError)
    }

    pub fn set_policy(
        &self,
        tenant: &str,
        site_key: &str,
        action: &str,
        policy: &WorkPolicy,
    ) -> Result<(), StoreError> {
        let rounds = i32::try_from(policy.base_render_rounds).map_err(|_| StoreError)?;
        let quiet = i64::try_from(policy.quiet_window_seconds).map_err(|_| StoreError)?;
        let lifetime = i64::try_from(policy.base_lifetime_seconds).map_err(|_| StoreError)?;
        let round_allowance =
            i64::try_from(policy.round_allowance_seconds).map_err(|_| StoreError)?;
        let max_lifetime = i64::try_from(policy.max_lifetime_seconds).map_err(|_| StoreError)?;
        self.connection()?
            .execute(
                "INSERT INTO shar_policies(tenant,site_key,action,version,base_iterations,base_render_rounds,quiet_window_seconds,base_lifetime_seconds,iteration_allowance,round_allowance_seconds,max_lifetime_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(tenant,site_key,action) DO UPDATE SET version=EXCLUDED.version,base_iterations=EXCLUDED.base_iterations,base_render_rounds=EXCLUDED.base_render_rounds,quiet_window_seconds=EXCLUDED.quiet_window_seconds,base_lifetime_seconds=EXCLUDED.base_lifetime_seconds,iteration_allowance=EXCLUDED.iteration_allowance,round_allowance_seconds=EXCLUDED.round_allowance_seconds,max_lifetime_seconds=EXCLUDED.max_lifetime_seconds",
                &[&tenant, &site_key, &action, &policy.version, &policy.base_iterations.to_string(), &rounds, &quiet, &lifetime, &policy.iteration_allowance.to_string(), &round_allowance, &max_lifetime],
            )
            .map_err(|_| StoreError)?;
        Ok(())
    }

    fn base_scope(input: &ChallengeRequest) -> String {
        format!(
            "v1:{}:{}:{}",
            scope_part(&input.tenant),
            scope_part(&input.site_key),
            scope_part(&input.action)
        )
    }
    fn action_scope(input: &ChallengeRequest) -> String {
        format!("action:{}", Self::base_scope(input))
    }
    fn client_scope(input: &ChallengeRequest) -> String {
        format!(
            "client:{}:{}",
            Self::base_scope(input),
            scope_part(input.session_binding.as_deref().unwrap_or(""))
        )
    }
    fn network_scope(input: &ChallengeRequest) -> Option<String> {
        input.network_pseudonym.as_ref().map(|network| {
            format!(
                "network:{}:{}",
                Self::base_scope(input),
                scope_part(network)
            )
        })
    }
    fn failure_scope(input: &ChallengeRequest) -> String {
        if input.session_binding.is_some() || input.network_pseudonym.is_none() {
            Self::client_scope(input)
        } else {
            Self::network_scope(input).expect("network pseudonym present")
        }
    }
}

fn scope_part(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

impl NonceStore for PostgresStore {
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
        let mut client = self.connection()?;
        let mut tx = client.transaction().map_err(|_| StoreError)?;
        tx.execute(
            "DELETE FROM shar_nonce_consumptions WHERE expires_at < $1",
            &[&now],
        )
        .map_err(|_| StoreError)?;
        let changed = tx
            .execute(
                "INSERT INTO shar_nonce_consumptions(namespace,nonce,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
                &[&namespace, &nonce, &expires],
            )
            .map_err(|_| StoreError)?;
        tx.commit().map_err(|_| StoreError)?;
        Ok(changed == 1)
    }
}

impl PressureStore for PostgresStore {
    fn health(&self) -> Result<(), StoreError> {
        self.check_health()
    }

    fn read(
        &self,
        input: &ChallengeRequest,
        now: u64,
        quiet_window_seconds: u64,
    ) -> Result<PressureInput, StoreError> {
        let now = i64::try_from(now).map_err(|_| StoreError)?;
        let quiet = i64::try_from(quiet_window_seconds).map_err(|_| StoreError)?;
        if quiet <= 0 {
            return Err(StoreError);
        }
        let action_scope = Self::action_scope(input);
        let client_scope = Self::client_scope(input);
        let network_scope = Self::network_scope(input);
        let mut client = self.connection()?;
        let mut tx = client.transaction().map_err(|_| StoreError)?;
        ensure_pressure(&mut tx, &action_scope, now)?;
        ensure_pressure(&mut tx, &client_scope, now)?;
        if let Some(scope) = network_scope.as_deref() {
            ensure_pressure(&mut tx, scope, now)?;
        }
        tx.execute(
            "DELETE FROM shar_outstanding WHERE scope=$1 AND expires_at<$2",
            &[&action_scope, &now],
        )
        .map_err(|_| StoreError)?;

        let row = tx
            .query_one(
                "SELECT window_start,request_count FROM shar_pressure WHERE scope=$1 FOR UPDATE",
                &[&action_scope],
            )
            .map_err(|_| StoreError)?;
        let mut action_window: i64 = row.get(0);
        let mut action_count: i64 = row.get(1);
        if now.saturating_sub(action_window) >= quiet {
            action_window = now;
            action_count = 0;
        }
        action_count = action_count.checked_add(1).ok_or(StoreError)?;
        tx.execute(
            "UPDATE shar_pressure SET last_activity=$1,window_start=$2,request_count=$3 WHERE scope=$4",
            &[&now, &action_window, &action_count, &action_scope],
        )
        .map_err(|_| StoreError)?;

        let row = tx
            .query_one(
                "SELECT base_tier,failure_debt,assurance_debt,trust_credits,last_activity FROM shar_pressure WHERE scope=$1 FOR UPDATE",
                &[&client_scope],
            )
            .map_err(|_| StoreError)?;
        let base: i32 = row.get(0);
        let mut failure: i32 = row.get(1);
        let mut stored_assurance: i32 = row.get(2);
        let trust: i32 = row.get(3);
        let client_last: i64 = row.get(4);
        let client_decay =
            i32::try_from(now.saturating_sub(client_last) / quiet).unwrap_or(i32::MAX);
        failure = failure.saturating_sub(client_decay).max(0);
        stored_assurance = stored_assurance.saturating_sub(client_decay).max(0);
        let assurance = stored_assurance.max(i32::from(input.assurance_tier.unwrap_or(0)));
        let persisted_assurance = if input.session_binding.is_some() {
            assurance
        } else {
            stored_assurance
        };
        tx.execute(
            "UPDATE shar_pressure SET failure_debt=$1,assurance_debt=$2,last_activity=$3 WHERE scope=$4",
            &[&failure, &persisted_assurance, &now, &client_scope],
        )
        .map_err(|_| StoreError)?;

        let mut network_tier = 0_i32;
        if let Some(scope) = network_scope.as_deref() {
            let row = tx
                .query_one(
                    "SELECT network_tier,failure_debt,last_activity,window_start,request_count FROM shar_pressure WHERE scope=$1 FOR UPDATE",
                    &[&scope],
                )
                .map_err(|_| StoreError)?;
            let configured: i32 = row.get(0);
            let mut network_failure: i32 = row.get(1);
            let network_last: i64 = row.get(2);
            let mut window: i64 = row.get(3);
            let mut count: i64 = row.get(4);
            let decay = i32::try_from(now.saturating_sub(network_last) / quiet).unwrap_or(i32::MAX);
            network_failure = network_failure.saturating_sub(decay).max(0);
            if now.saturating_sub(window) >= quiet {
                window = now;
                count = 0;
            }
            count = count.checked_add(1).ok_or(StoreError)?;
            network_tier = configured
                .max(network_failure)
                .max(i32::from(logarithmic_tier(
                    u64::try_from(count).map_err(|_| StoreError)?,
                )));
            tx.execute(
                "UPDATE shar_pressure SET failure_debt=$1,last_activity=$2,window_start=$3,request_count=$4 WHERE scope=$5",
                &[&network_failure, &now, &window, &count, &scope],
            )
            .map_err(|_| StoreError)?;
        }
        let outstanding: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM shar_outstanding WHERE scope=$1",
                &[&action_scope],
            )
            .map_err(|_| StoreError)?
            .get(0);
        tx.commit().map_err(|_| StoreError)?;
        Ok(PressureInput {
            base_tier: to_u8(base)?,
            velocity_tier: logarithmic_tier(u64::try_from(action_count).map_err(|_| StoreError)?),
            outstanding_tier: logarithmic_tier(
                u64::try_from(outstanding)
                    .map_err(|_| StoreError)?
                    .checked_add(1)
                    .ok_or(StoreError)?,
            ),
            network_tier: to_u8(network_tier)?,
            failure_debt: to_u8(failure)?,
            assurance_debt: to_u8(assurance)?,
            trust_credits: to_u8(trust)?,
        })
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
        let mut client = self.connection()?;
        let mut tx = client.transaction().map_err(|_| StoreError)?;
        ensure_pressure(&mut tx, &scope, now)?;
        tx.execute(
            "INSERT INTO shar_outstanding(scope,expires_at) VALUES($1,$2)",
            &[&scope, &expires],
        )
        .map_err(|_| StoreError)?;
        tx.execute(
            "UPDATE shar_pressure SET last_activity=$1 WHERE scope=$2",
            &[&now, &scope],
        )
        .map_err(|_| StoreError)?;
        tx.commit().map_err(|_| StoreError)
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
        let mut client = self.connection()?;
        let mut transaction = client.transaction().map_err(|_| StoreError)?;
        let pressure = read_pressure_transaction(&mut transaction, input, stored_now, quiet)?;
        let quote = price_work(&pressure, policy, now).map_err(|_| StoreError)?;
        let expires = i64::try_from(quote.expires_at).map_err(|_| StoreError)?;
        let scope = Self::action_scope(input);
        transaction
            .execute(
                "INSERT INTO shar_outstanding(scope,expires_at) VALUES($1,$2)",
                &[&scope, &expires],
            )
            .map_err(|_| StoreError)?;
        transaction
            .execute(
                "UPDATE shar_pressure SET last_activity=$1 WHERE scope=$2",
                &[&stored_now, &scope],
            )
            .map_err(|_| StoreError)?;
        transaction.commit().map_err(|_| StoreError)?;
        Ok(quote)
    }

    fn record_success(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        self.record_outcome(input, expires_at, now, -1, true)
    }

    fn record_failure(
        &self,
        input: &ChallengeRequest,
        kind: FailureKind,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        self.record_outcome(input, expires_at, now, 1, kind == FailureKind::Expired)
    }

    fn record_trust(&self, input: &ChallengeRequest, now: u64) -> Result<(), StoreError> {
        // Trust credits never reduce the rotating network-pressure bucket.
        let failure_scope = Self::client_scope(input);
        let now = i64::try_from(now).map_err(|_| StoreError)?;
        let mut client = self.connection()?;
        let mut tx = client.transaction().map_err(|_| StoreError)?;
        ensure_pressure(&mut tx, &failure_scope, now)?;
        tx.execute(
            "UPDATE shar_pressure SET failure_debt=GREATEST(0,failure_debt-1), assurance_debt=CASE WHEN failure_debt=0 THEN GREATEST(0,assurance_debt-1) ELSE assurance_debt END,last_activity=$1 WHERE scope=$2",
            &[&now, &failure_scope],
        )
        .map_err(|_| StoreError)?;
        tx.commit().map_err(|_| StoreError)
    }
}

impl PostgresStore {
    fn record_outcome(
        &self,
        input: &ChallengeRequest,
        expires_at: u64,
        now: u64,
        debt_change: i8,
        remove_outstanding: bool,
    ) -> Result<(), StoreError> {
        let failure_scope = Self::failure_scope(input);
        let action_scope = Self::action_scope(input);
        let expires_at = i64::try_from(expires_at).map_err(|_| StoreError)?;
        let now = i64::try_from(now).map_err(|_| StoreError)?;
        let mut client = self.connection()?;
        let mut tx = client.transaction().map_err(|_| StoreError)?;
        ensure_pressure(&mut tx, &failure_scope, now)?;
        let statement = if debt_change > 0 {
            "UPDATE shar_pressure SET failure_debt=LEAST(32,failure_debt+1),last_activity=$1 WHERE scope=$2"
        } else {
            "UPDATE shar_pressure SET failure_debt=GREATEST(0,failure_debt-1),last_activity=$1 WHERE scope=$2"
        };
        tx.execute(statement, &[&now, &failure_scope])
            .map_err(|_| StoreError)?;
        if remove_outstanding {
            tx.execute(DELETE_EXACT_OUTSTANDING, &[&action_scope, &expires_at])
                .map_err(|_| StoreError)?;
        }
        tx.commit().map_err(|_| StoreError)
    }
}

impl ConfigStore for PostgresStore {
    fn health(&self) -> Result<(), StoreError> {
        self.check_health()
    }

    fn policy(&self, tenant: &str, site_key: &str, action: &str) -> Result<WorkPolicy, StoreError> {
        let mut client = self.connection()?;
        let row = client
            .query_opt(
                "SELECT version,base_iterations,base_render_rounds,quiet_window_seconds,base_lifetime_seconds,iteration_allowance,round_allowance_seconds,max_lifetime_seconds FROM shar_policies WHERE tenant=$1 AND site_key=$2 AND action=$3",
                &[&tenant, &site_key, &action],
            )
            .map_err(|_| StoreError)?;
        let Some(row) = row else {
            return Ok(self.default_policy.clone());
        };
        let values: PolicyRow = (
            row.get(0),
            row.get(1),
            row.get(2),
            row.get(3),
            row.get(4),
            row.get(5),
            row.get(6),
            row.get(7),
        );
        Ok(WorkPolicy {
            version: values.0,
            base_iterations: values.1.parse().map_err(|_| StoreError)?,
            base_render_rounds: u32::try_from(values.2).map_err(|_| StoreError)?,
            quiet_window_seconds: u64::try_from(values.3).map_err(|_| StoreError)?,
            base_lifetime_seconds: u64::try_from(values.4).map_err(|_| StoreError)?,
            iteration_allowance: values.5.parse().map_err(|_| StoreError)?,
            round_allowance_seconds: u64::try_from(values.6).map_err(|_| StoreError)?,
            max_lifetime_seconds: u64::try_from(values.7).map_err(|_| StoreError)?,
        })
    }

    fn set_policy(
        &self,
        tenant: &str,
        site_key: &str,
        action: &str,
        policy: &WorkPolicy,
    ) -> Result<(), StoreError> {
        PostgresStore::set_policy(self, tenant, site_key, action, policy)
    }
}

impl AuditStore for PostgresStore {
    fn record(&self, event: &AuditEvent) -> Result<(), StoreError> {
        validate_audit_event(event)?;
        let occurred_at = i64::try_from(event.occurred_at).map_err(|_| StoreError)?;
        let cutoff = occurred_at.saturating_sub(86_400);
        let mut client = self.connection()?;
        let mut tx = client.transaction().map_err(|_| StoreError)?;
        tx.execute(
            "INSERT INTO shar_audit_events(version,kind,occurred_at,tenant,site_key,action,tier,backend,code) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &event.version,
                &event.kind,
                &occurred_at,
                &event.tenant,
                &event.site_key,
                &event.action,
                &event.tier.map(i32::from),
                &event.backend,
                &event.code,
            ],
        )
        .map_err(|_| StoreError)?;
        tx.execute(
            "DELETE FROM shar_audit_events WHERE occurred_at < $1",
            &[&cutoff],
        )
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
        let mut client = self.connection()?;
        let rows = client
            .query(
                "SELECT version,kind,occurred_at,tenant,site_key,action,tier,backend,code FROM shar_audit_events WHERE tenant=$1 AND site_key=$2 AND action=$3 ORDER BY id DESC LIMIT $4",
                &[&tenant, &site_key, &action, &i64::from(limit)],
            )
            .map_err(|_| StoreError)?;
        rows.into_iter()
            .map(|row| {
                let tier = row
                    .try_get::<_, Option<i32>>(6)
                    .map_err(|_| StoreError)?
                    .map(|value| u8::try_from(value).map_err(|_| StoreError))
                    .transpose()?;
                Ok(AuditEvent {
                    version: row.try_get(0).map_err(|_| StoreError)?,
                    kind: row.try_get(1).map_err(|_| StoreError)?,
                    occurred_at: u64::try_from(row.try_get::<_, i64>(2).map_err(|_| StoreError)?)
                        .map_err(|_| StoreError)?,
                    tenant: row.try_get(3).map_err(|_| StoreError)?,
                    site_key: row.try_get(4).map_err(|_| StoreError)?,
                    action: row.try_get(5).map_err(|_| StoreError)?,
                    tier,
                    backend: row.try_get(7).map_err(|_| StoreError)?,
                    code: row.try_get(8).map_err(|_| StoreError)?,
                })
            })
            .map(|result| {
                let event = result?;
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

fn read_pressure_transaction(
    tx: &mut Transaction<'_>,
    input: &ChallengeRequest,
    now: i64,
    quiet: i64,
) -> Result<PressureInput, StoreError> {
    let action_scope = PostgresStore::action_scope(input);
    let client_scope = PostgresStore::client_scope(input);
    let network_scope = PostgresStore::network_scope(input);
    ensure_pressure(tx, &action_scope, now)?;
    ensure_pressure(tx, &client_scope, now)?;
    if let Some(scope) = network_scope.as_deref() {
        ensure_pressure(tx, scope, now)?;
    }
    tx.execute(
        "DELETE FROM shar_outstanding WHERE scope=$1 AND expires_at<$2",
        &[&action_scope, &now],
    )
    .map_err(|_| StoreError)?;
    let row = tx
        .query_one(
            "SELECT window_start,request_count FROM shar_pressure WHERE scope=$1 FOR UPDATE",
            &[&action_scope],
        )
        .map_err(|_| StoreError)?;
    let mut action_window: i64 = row.get(0);
    let mut action_count: i64 = row.get(1);
    if now.saturating_sub(action_window) >= quiet {
        action_window = now;
        action_count = 0;
    }
    action_count = action_count.checked_add(1).ok_or(StoreError)?;
    tx.execute(
        "UPDATE shar_pressure SET last_activity=$1,window_start=$2,request_count=$3 WHERE scope=$4",
        &[&now, &action_window, &action_count, &action_scope],
    )
    .map_err(|_| StoreError)?;
    let row = tx
        .query_one(
            "SELECT base_tier,failure_debt,assurance_debt,trust_credits,last_activity FROM shar_pressure WHERE scope=$1 FOR UPDATE",
            &[&client_scope],
        )
        .map_err(|_| StoreError)?;
    let base: i32 = row.get(0);
    let mut failure: i32 = row.get(1);
    let mut stored_assurance: i32 = row.get(2);
    let trust: i32 = row.get(3);
    let client_last: i64 = row.get(4);
    let client_decay = i32::try_from(now.saturating_sub(client_last) / quiet).unwrap_or(i32::MAX);
    failure = failure.saturating_sub(client_decay).max(0);
    stored_assurance = stored_assurance.saturating_sub(client_decay).max(0);
    let assurance = stored_assurance.max(i32::from(input.assurance_tier.unwrap_or(0)));
    let persisted_assurance = if input.session_binding.is_some() {
        assurance
    } else {
        stored_assurance
    };
    tx.execute(
        "UPDATE shar_pressure SET failure_debt=$1,assurance_debt=$2,last_activity=$3 WHERE scope=$4",
        &[&failure, &persisted_assurance, &now, &client_scope],
    )
    .map_err(|_| StoreError)?;
    let mut network_tier = 0_i32;
    if let Some(scope) = network_scope.as_deref() {
        let row = tx
            .query_one(
                "SELECT network_tier,failure_debt,last_activity,window_start,request_count FROM shar_pressure WHERE scope=$1 FOR UPDATE",
                &[&scope],
            )
            .map_err(|_| StoreError)?;
        let configured: i32 = row.get(0);
        let mut network_failure: i32 = row.get(1);
        let network_last: i64 = row.get(2);
        let mut window: i64 = row.get(3);
        let mut count: i64 = row.get(4);
        let decay = i32::try_from(now.saturating_sub(network_last) / quiet).unwrap_or(i32::MAX);
        network_failure = network_failure.saturating_sub(decay).max(0);
        if now.saturating_sub(window) >= quiet {
            window = now;
            count = 0;
        }
        count = count.checked_add(1).ok_or(StoreError)?;
        network_tier = configured
            .max(network_failure)
            .max(i32::from(logarithmic_tier(
                u64::try_from(count).map_err(|_| StoreError)?,
            )));
        tx.execute(
            "UPDATE shar_pressure SET failure_debt=$1,last_activity=$2,window_start=$3,request_count=$4 WHERE scope=$5",
            &[&network_failure, &now, &window, &count, &scope],
        )
        .map_err(|_| StoreError)?;
    }
    let outstanding: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM shar_outstanding WHERE scope=$1",
            &[&action_scope],
        )
        .map_err(|_| StoreError)?
        .get(0);
    Ok(PressureInput {
        base_tier: to_u8(base)?,
        velocity_tier: logarithmic_tier(u64::try_from(action_count).map_err(|_| StoreError)?),
        outstanding_tier: logarithmic_tier(
            u64::try_from(outstanding)
                .map_err(|_| StoreError)?
                .checked_add(1)
                .ok_or(StoreError)?,
        ),
        network_tier: to_u8(network_tier)?,
        failure_debt: to_u8(failure)?,
        assurance_debt: to_u8(assurance)?,
        trust_credits: to_u8(trust)?,
    })
}

fn ensure_pressure(tx: &mut Transaction<'_>, scope: &str, now: i64) -> Result<(), StoreError> {
    let values: &[&(dyn ToSql + Sync)] = &[&scope, &now];
    tx.execute(
        "INSERT INTO shar_pressure(scope,last_activity,window_start) VALUES($1,$2,$2) ON CONFLICT DO NOTHING",
        values,
    )
    .map_err(|_| StoreError)?;
    Ok(())
}

fn to_u8(value: i32) -> Result<u8, StoreError> {
    let value = u8::try_from(value).map_err(|_| StoreError)?;
    if value > 32 {
        return Err(StoreError);
    }
    Ok(value)
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

    #[test]
    #[ignore = "requires SHAR_TEST_POSTGRES_URL; CI runs this test explicitly"]
    fn terminated_client_is_not_retried_and_the_next_request_reconnects() {
        let url = std::env::var("SHAR_TEST_POSTGRES_URL").expect("PostgreSQL test URL");
        let configuration: postgres::Config = url.parse().expect("parse PostgreSQL test URL");
        let mut first = configuration
            .connect(postgres::NoTls)
            .expect("first PostgreSQL connection");
        let mut administrator = configuration
            .connect(postgres::NoTls)
            .expect("administrator PostgreSQL connection");
        let backend: i32 = first
            .query_one("SELECT pg_backend_pid()", &[])
            .expect("backend id")
            .get(0);
        let reconnect_configuration = configuration.clone();
        let reconnect: PostgresConnector =
            Arc::new(move || reconnect_configuration.connect(postgres::NoTls));
        let store = PostgresStore::from_clients_with_reconnect(
            first,
            Vec::new(),
            shar_core::default_work_policy(),
            reconnect,
        )
        .expect("construct PostgreSQL store");
        let terminated: bool = administrator
            .query_one("SELECT pg_terminate_backend($1)", &[&backend])
            .expect("terminate pooled backend")
            .get(0);
        assert!(terminated);

        // The request that observes termination fails and is never replayed.
        assert!(store.check_health().is_err());
        // The next independent request replaces the closed pool entry.
        assert!(store.check_health().is_ok());
    }

    #[test]
    fn schema_has_atomic_and_bounded_constraints() {
        assert!(POSTGRES_SCHEMA_V1.contains("PRIMARY KEY (namespace, nonce)"));
        assert!(POSTGRES_SCHEMA_V1.contains("failure_debt BETWEEN 0 AND 32"));
        assert!(POSTGRES_SCHEMA_V1.contains("PRIMARY KEY (tenant, site_key, action)"));
        assert!(POSTGRES_SCHEMA_V1.contains("shar_audit_events"));
        assert!(POSTGRES_SCHEMA_V1.contains("backend IN ('webgpu', 'webgl2', 'css')"));
        assert!(DELETE_EXACT_OUTSTANDING.contains("scope=$1 AND expires_at=$2"));
        assert!(DELETE_EXACT_OUTSTANDING.contains("FOR UPDATE SKIP LOCKED"));
    }

    #[test]
    fn pressure_scope_keys_are_postgres_safe_and_deterministic() {
        let input = ChallengeRequest {
            tenant: "tenant-a".into(),
            site_key: "site-a".into(),
            action: "signup".into(),
            origin: "https://app.example".into(),
            region: None,
            session_binding: Some("session-a".into()),
            network_pseudonym: Some("daily-network-a".into()),
            assurance_tier: None,
            trust_token: None,
        };
        assert_eq!(
            PostgresStore::action_scope(&input),
            "action:v1:dGVuYW50LWE:c2l0ZS1h:c2lnbnVw"
        );
        assert_eq!(
            PostgresStore::client_scope(&input),
            "client:v1:dGVuYW50LWE:c2l0ZS1h:c2lnbnVw:c2Vzc2lvbi1h"
        );
        assert_eq!(
            PostgresStore::network_scope(&input).unwrap(),
            "network:v1:dGVuYW50LWE:c2l0ZS1h:c2lnbnVw:ZGFpbHktbmV0d29yay1h"
        );
        assert!(!PostgresStore::action_scope(&input).contains('\0'));
    }
}
