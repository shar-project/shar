import { base64url, utf8 } from "./bytes.js";
import { priceWork } from "./pricing.js";
import { DEFAULT_POLICY } from "./stores.js";
import type {
  AuditEvent,
  AuditStore,
  ChallengeRequest,
  ConfigStore,
  NonceStore,
  PressureInput,
  PressureStore,
  WorkPolicy,
  WorkQuote,
} from "./types.js";

export interface PostgresResult<
  Row extends Record<string, unknown> = Record<string, unknown>,
> {
  rows: Row[];
  rowCount: number | null;
}

export interface PostgresConnection {
  query<Row extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: readonly unknown[],
  ): Promise<PostgresResult<Row>>;
  release(): void;
}

export interface PostgresPool {
  query<Row extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: readonly unknown[],
  ): Promise<PostgresResult<Row>>;
  connect(): Promise<PostgresConnection>;
}

export const POSTGRES_SCHEMA_V1 = `
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
CREATE INDEX IF NOT EXISTS shar_audit_events_expiry ON shar_audit_events (occurred_at);`;

interface PressureRow extends Record<string, unknown> {
  base_tier: unknown;
  network_tier: unknown;
  failure_debt: unknown;
  assurance_debt: unknown;
  trust_credits: unknown;
  last_activity: unknown;
  window_start: unknown;
  request_count: unknown;
}

export class PostgresStore
  implements NonceStore, PressureStore, ConfigStore, AuditStore
{
  constructor(
    private readonly pool: PostgresPool,
    private readonly defaultPolicy: WorkPolicy = DEFAULT_POLICY,
  ) {}

  async migrate(): Promise<void> {
    await this.pool.query(POSTGRES_SCHEMA_V1);
  }

  async health(): Promise<void> {
    await this.pool.query("SELECT 1");
  }

  async consume(
    namespace: "challenge" | "verification" | "fallback" | "trust",
    nonce: Uint8Array,
    expiresAt: number,
  ): Promise<boolean> {
    nonNegativeInteger(expiresAt, "invalid_expiry");
    return this.transaction(async (connection) => {
      const now = Math.floor(Date.now() / 1000);
      await connection.query(
        "DELETE FROM shar_nonce_consumptions WHERE expires_at < $1",
        [now],
      );
      const result = await connection.query(
        "INSERT INTO shar_nonce_consumptions(namespace, nonce, expires_at) VALUES($1, $2, $3) ON CONFLICT DO NOTHING",
        [namespace, base64url(nonce), expiresAt],
      );
      return result.rowCount === 1;
    });
  }

  async read(
    input: ChallengeRequest,
    now: number,
    quietWindowSeconds: number,
  ): Promise<PressureInput> {
    nonNegativeInteger(now, "invalid_time");
    integer(quietWindowSeconds, "invalid_quiet_window", true);
    return this.transaction(async (connection) => {
      const actionScope = actionKey(input);
      const clientScope = clientKey(input);
      const networkScope = networkKey(input);
      await ensurePressure(connection, actionScope, now);
      await ensurePressure(connection, clientScope, now);
      if (networkScope) await ensurePressure(connection, networkScope, now);
      await connection.query(
        "DELETE FROM shar_outstanding WHERE scope = $1 AND expires_at < $2",
        [actionScope, now],
      );

      const action = await lockedPressure(connection, actionScope);
      let actionWindow = number(action.window_start);
      let actionCount = number(action.request_count);
      if (now - actionWindow >= quietWindowSeconds) {
        actionWindow = now;
        actionCount = 0;
      }
      actionCount = checkedIncrement(actionCount);
      await connection.query(
        "UPDATE shar_pressure SET last_activity=$1, window_start=$2, request_count=$3 WHERE scope=$4",
        [now, actionWindow, actionCount, actionScope],
      );

      const client = await lockedPressure(connection, clientScope);
      const clientDecay = Math.floor(
        Math.max(0, now - number(client.last_activity)) / quietWindowSeconds,
      );
      const failureDebt = Math.max(
        0,
        number(client.failure_debt) - clientDecay,
      );
      const storedAssurance = Math.max(
        0,
        number(client.assurance_debt) - clientDecay,
      );
      const assuranceDebt = Math.max(
        storedAssurance,
        input.assurance_tier ?? 0,
      );
      await connection.query(
        "UPDATE shar_pressure SET failure_debt=$1, assurance_debt=$2, last_activity=$3 WHERE scope=$4",
        [
          failureDebt,
          input.session_binding ? assuranceDebt : storedAssurance,
          now,
          clientScope,
        ],
      );

      let networkTier = 0;
      if (networkScope) {
        const network = await lockedPressure(connection, networkScope);
        const decay = Math.floor(
          Math.max(0, now - number(network.last_activity)) / quietWindowSeconds,
        );
        const networkFailure = Math.max(
          0,
          number(network.failure_debt) - decay,
        );
        let windowStart = number(network.window_start);
        let requestCount = number(network.request_count);
        if (now - windowStart >= quietWindowSeconds) {
          windowStart = now;
          requestCount = 0;
        }
        requestCount = checkedIncrement(requestCount);
        networkTier = Math.max(
          number(network.network_tier),
          networkFailure,
          logarithmicTier(requestCount),
        );
        await connection.query(
          "UPDATE shar_pressure SET failure_debt=$1, last_activity=$2, window_start=$3, request_count=$4 WHERE scope=$5",
          [networkFailure, now, windowStart, requestCount, networkScope],
        );
      }

      const countResult = await connection.query<{ count: unknown }>(
        "SELECT COUNT(*) AS count FROM shar_outstanding WHERE scope=$1",
        [actionScope],
      );
      const outstanding = number(requiredRow(countResult).count);
      return {
        baseTier: tier(client.base_tier),
        velocityTier: logarithmicTier(actionCount),
        outstandingTier: logarithmicTier(checkedIncrement(outstanding)),
        networkTier: tier(networkTier),
        failureDebt: tier(failureDebt),
        assuranceDebt: tier(assuranceDebt),
        trustCredits: tier(client.trust_credits),
      };
    });
  }

  async recordIssued(
    input: ChallengeRequest,
    expiresAt: number,
    now: number,
  ): Promise<void> {
    nonNegativeInteger(expiresAt, "invalid_expiry");
    nonNegativeInteger(now, "invalid_time");
    await this.transaction(async (connection) => {
      const scope = actionKey(input);
      await ensurePressure(connection, scope, now);
      await connection.query(
        "INSERT INTO shar_outstanding(scope, expires_at) VALUES($1, $2)",
        [scope, expiresAt],
      );
      await connection.query(
        "UPDATE shar_pressure SET last_activity=$1 WHERE scope=$2",
        [now, scope],
      );
    });
  }

  async priceAndRecord(
    input: ChallengeRequest,
    policy: WorkPolicy,
    now: number,
  ): Promise<WorkQuote> {
    nonNegativeInteger(now, "invalid_time");
    integer(policy.quietWindowSeconds, "invalid_quiet_window", true);
    return this.transaction(async (connection) => {
      const pressure = await readPressureTransaction(
        connection,
        input,
        now,
        policy.quietWindowSeconds,
      );
      const quote = priceWork(pressure, policy, now);
      const scope = actionKey(input);
      await connection.query(
        "INSERT INTO shar_outstanding(scope, expires_at) VALUES($1, $2)",
        [scope, quote.expires_at],
      );
      await connection.query(
        "UPDATE shar_pressure SET last_activity=$1 WHERE scope=$2",
        [now, scope],
      );
      return quote;
    });
  }

  async recordSuccess(
    input: ChallengeRequest,
    expiresAt: number,
    now: number,
  ): Promise<void> {
    nonNegativeInteger(now, "invalid_time");
    nonNegativeInteger(expiresAt, "invalid_expiry");
    await this.recordOutcome(input, expiresAt, now, false, -1);
  }

  async recordFailure(
    input: ChallengeRequest,
    kind: "invalid" | "replay" | "expired",
    expiresAt: number,
    now: number,
  ): Promise<void> {
    nonNegativeInteger(now, "invalid_time");
    nonNegativeInteger(expiresAt, "invalid_expiry");
    await this.recordOutcome(input, expiresAt, now, kind === "expired", 1);
  }

  async recordTrust(input: ChallengeRequest, now: number): Promise<void> {
    nonNegativeInteger(now, "invalid_time");
    await this.transaction(async (connection) => {
      // Keep trust reductions out of the network-pressure scope.
      const scope = clientKey(input);
      await ensurePressure(connection, scope, now);
      await connection.query(
        "UPDATE shar_pressure SET failure_debt=GREATEST(0, failure_debt-1), assurance_debt=CASE WHEN failure_debt=0 THEN GREATEST(0, assurance_debt-1) ELSE assurance_debt END, last_activity=$1 WHERE scope=$2",
        [now, scope],
      );
    });
  }

  async record(event: AuditEvent): Promise<void> {
    validateAuditEvent(event);
    await this.transaction(async (connection) => {
      await connection.query(
        "INSERT INTO shar_audit_events(version,kind,occurred_at,tenant,site_key,action,tier,backend,code) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        [
          event.version,
          event.kind,
          event.occurred_at,
          event.tenant,
          event.site_key,
          event.action,
          event.tier ?? null,
          event.backend ?? null,
          event.code ?? null,
        ],
      );
      await connection.query(
        "DELETE FROM shar_audit_events WHERE occurred_at < $1",
        [event.occurred_at - 86_400],
      );
    });
  }

  async purge(before: number): Promise<void> {
    nonNegativeInteger(before, "invalid_audit_cutoff");
    await this.pool.query(
      "DELETE FROM shar_audit_events WHERE occurred_at < $1",
      [before],
    );
  }

  async listAudit(limit = 100): Promise<AuditEvent[]> {
    integer(limit, "invalid_audit_limit");
    if (limit < 1 || limit > 1000) throw new Error("invalid_audit_limit");
    const result = await this.pool.query<Record<string, unknown>>(
      "SELECT version,kind,occurred_at,tenant,site_key,action,tier,backend,code FROM shar_audit_events ORDER BY id LIMIT $1",
      [limit],
    );
    return result.rows.map((row) => {
      const event: AuditEvent = {
        version: String(row.version) as "audit-v1",
        kind: String(row.kind) as AuditEvent["kind"],
        occurred_at: number(row.occurred_at),
        tenant: String(row.tenant),
        site_key: String(row.site_key),
        action: String(row.action),
      };
      if (row.tier !== null && row.tier !== undefined)
        event.tier = number(row.tier);
      if (row.backend !== null && row.backend !== undefined)
        event.backend = String(row.backend) as NonNullable<
          AuditEvent["backend"]
        >;
      if (row.code !== null && row.code !== undefined)
        event.code = String(row.code);
      validateAuditEvent(event);
      return event;
    });
  }

  async list(
    tenant: string,
    siteKey: string,
    action: string,
    limit = 100,
  ): Promise<AuditEvent[]> {
    integer(limit, "invalid_audit_limit");
    if (limit < 1 || limit > 100) throw new Error("invalid_audit_limit");
    const result = await this.pool.query<Record<string, unknown>>(
      "SELECT version,kind,occurred_at,tenant,site_key,action,tier,backend,code FROM shar_audit_events WHERE tenant=$1 AND site_key=$2 AND action=$3 ORDER BY id DESC LIMIT $4",
      [tenant, siteKey, action, limit],
    );
    return result.rows.map((row) => {
      const event: AuditEvent = {
        version: String(row.version) as "audit-v1",
        kind: String(row.kind) as AuditEvent["kind"],
        occurred_at: number(row.occurred_at),
        tenant: String(row.tenant),
        site_key: String(row.site_key),
        action: String(row.action),
      };
      if (row.tier !== null && row.tier !== undefined)
        event.tier = number(row.tier);
      if (row.backend !== null && row.backend !== undefined)
        event.backend = String(row.backend) as NonNullable<
          AuditEvent["backend"]
        >;
      if (row.code !== null && row.code !== undefined)
        event.code = String(row.code);
      validateAuditEvent(event);
      return event;
    });
  }

  async policy(
    tenant: string,
    siteKey: string,
    action: string,
  ): Promise<WorkPolicy> {
    const result = await this.pool.query<Record<string, unknown>>(
      "SELECT version, base_iterations, base_render_rounds, quiet_window_seconds, base_lifetime_seconds, iteration_allowance, round_allowance_seconds, max_lifetime_seconds FROM shar_policies WHERE tenant=$1 AND site_key=$2 AND action=$3",
      [tenant, siteKey, action],
    );
    const row = result.rows[0];
    if (!row) return { ...this.defaultPolicy };
    return policyFromRow(row);
  }

  async setPolicy(
    tenant: string,
    siteKey: string,
    action: string,
    policy: WorkPolicy,
  ): Promise<void> {
    await this.pool.query(
      "INSERT INTO shar_policies(tenant,site_key,action,version,base_iterations,base_render_rounds,quiet_window_seconds,base_lifetime_seconds,iteration_allowance,round_allowance_seconds,max_lifetime_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(tenant,site_key,action) DO UPDATE SET version=EXCLUDED.version,base_iterations=EXCLUDED.base_iterations,base_render_rounds=EXCLUDED.base_render_rounds,quiet_window_seconds=EXCLUDED.quiet_window_seconds,base_lifetime_seconds=EXCLUDED.base_lifetime_seconds,iteration_allowance=EXCLUDED.iteration_allowance,round_allowance_seconds=EXCLUDED.round_allowance_seconds,max_lifetime_seconds=EXCLUDED.max_lifetime_seconds",
      [
        tenant,
        siteKey,
        action,
        policy.version,
        policy.baseIterations.toString(),
        policy.baseRenderRounds,
        policy.quietWindowSeconds,
        policy.baseLifetimeSeconds,
        policy.iterationAllowance.toString(),
        policy.roundAllowanceSeconds,
        policy.maxLifetimeSeconds,
      ],
    );
  }

  private async recordOutcome(
    input: ChallengeRequest,
    expiresAt: number,
    now: number,
    removeOutstanding: boolean,
    debtChange: -1 | 1,
  ): Promise<void> {
    await this.transaction(async (connection) => {
      const failureScope = failureKey(input);
      const actionScope = actionKey(input);
      await ensurePressure(connection, failureScope, now);
      const debtExpression =
        debtChange > 0
          ? "LEAST(32, failure_debt + 1)"
          : "GREATEST(0, failure_debt - 1)";
      await connection.query(
        `UPDATE shar_pressure SET failure_debt=${debtExpression}, last_activity=$1 WHERE scope=$2`,
        [now, failureScope],
      );
      if (removeOutstanding || debtChange < 0) {
        await connection.query(
          "DELETE FROM shar_outstanding WHERE id=(SELECT id FROM shar_outstanding WHERE scope=$1 AND expires_at=$2 ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)",
          [actionScope, expiresAt],
        );
      }
    });
  }

  private async transaction<T>(
    operation: (connection: PostgresConnection) => Promise<T>,
  ): Promise<T> {
    const connection = await this.pool.connect();
    try {
      await connection.query("BEGIN");
      const result = await operation(connection);
      await connection.query("COMMIT");
      return result;
    } catch (error) {
      try {
        await connection.query("ROLLBACK");
      } catch {}
      throw error;
    } finally {
      connection.release();
    }
  }
}

async function readPressureTransaction(
  connection: PostgresConnection,
  input: ChallengeRequest,
  now: number,
  quietWindowSeconds: number,
): Promise<PressureInput> {
  const actionScope = actionKey(input);
  const clientScope = clientKey(input);
  const networkScope = networkKey(input);
  await ensurePressure(connection, actionScope, now);
  await ensurePressure(connection, clientScope, now);
  if (networkScope) await ensurePressure(connection, networkScope, now);
  await connection.query(
    "DELETE FROM shar_outstanding WHERE scope = $1 AND expires_at < $2",
    [actionScope, now],
  );
  const action = await lockedPressure(connection, actionScope);
  let actionWindow = number(action.window_start);
  let actionCount = number(action.request_count);
  if (now - actionWindow >= quietWindowSeconds) {
    actionWindow = now;
    actionCount = 0;
  }
  actionCount = checkedIncrement(actionCount);
  await connection.query(
    "UPDATE shar_pressure SET last_activity=$1, window_start=$2, request_count=$3 WHERE scope=$4",
    [now, actionWindow, actionCount, actionScope],
  );
  const client = await lockedPressure(connection, clientScope);
  const clientDecay = Math.floor(
    Math.max(0, now - number(client.last_activity)) / quietWindowSeconds,
  );
  const failureDebt = Math.max(0, number(client.failure_debt) - clientDecay);
  const storedAssurance = Math.max(
    0,
    number(client.assurance_debt) - clientDecay,
  );
  const assuranceDebt = Math.max(storedAssurance, input.assurance_tier ?? 0);
  await connection.query(
    "UPDATE shar_pressure SET failure_debt=$1, assurance_debt=$2, last_activity=$3 WHERE scope=$4",
    [
      failureDebt,
      input.session_binding ? assuranceDebt : storedAssurance,
      now,
      clientScope,
    ],
  );
  let networkTier = 0;
  if (networkScope) {
    const network = await lockedPressure(connection, networkScope);
    const decay = Math.floor(
      Math.max(0, now - number(network.last_activity)) / quietWindowSeconds,
    );
    const networkFailure = Math.max(0, number(network.failure_debt) - decay);
    let windowStart = number(network.window_start);
    let requestCount = number(network.request_count);
    if (now - windowStart >= quietWindowSeconds) {
      windowStart = now;
      requestCount = 0;
    }
    requestCount = checkedIncrement(requestCount);
    networkTier = Math.max(
      number(network.network_tier),
      networkFailure,
      logarithmicTier(requestCount),
    );
    await connection.query(
      "UPDATE shar_pressure SET failure_debt=$1, last_activity=$2, window_start=$3, request_count=$4 WHERE scope=$5",
      [networkFailure, now, windowStart, requestCount, networkScope],
    );
  }
  const countResult = await connection.query<{ count: unknown }>(
    "SELECT COUNT(*) AS count FROM shar_outstanding WHERE scope=$1",
    [actionScope],
  );
  const outstanding = number(requiredRow(countResult).count);
  return {
    baseTier: tier(client.base_tier),
    velocityTier: logarithmicTier(actionCount),
    outstandingTier: logarithmicTier(checkedIncrement(outstanding)),
    networkTier: tier(networkTier),
    failureDebt: tier(failureDebt),
    assuranceDebt: tier(assuranceDebt),
    trustCredits: tier(client.trust_credits),
  };
}

async function ensurePressure(
  connection: PostgresConnection,
  scope: string,
  now: number,
): Promise<void> {
  await connection.query(
    "INSERT INTO shar_pressure(scope,last_activity,window_start) VALUES($1,$2,$2) ON CONFLICT DO NOTHING",
    [scope, now],
  );
}

async function lockedPressure(
  connection: PostgresConnection,
  scope: string,
): Promise<PressureRow> {
  const result = await connection.query<PressureRow>(
    "SELECT * FROM shar_pressure WHERE scope=$1 FOR UPDATE",
    [scope],
  );
  return requiredRow(result);
}

function requiredRow<Row extends Record<string, unknown>>(
  result: PostgresResult<Row>,
): Row {
  const row = result.rows[0];
  if (!row) throw new Error("postgres_missing_row");
  return row;
}

function baseKey(input: ChallengeRequest): string {
  return `v1:${base64url(utf8(input.tenant))}:${base64url(utf8(input.site_key))}:${base64url(utf8(input.action))}`;
}
function actionKey(input: ChallengeRequest): string {
  return `action:${baseKey(input)}`;
}
function clientKey(input: ChallengeRequest): string {
  return `client:${baseKey(input)}:${base64url(utf8(input.session_binding ?? ""))}`;
}
function networkKey(input: ChallengeRequest): string | undefined {
  return input.network_pseudonym
    ? `network:${baseKey(input)}:${base64url(utf8(input.network_pseudonym))}`
    : undefined;
}
function failureKey(input: ChallengeRequest): string {
  return input.session_binding || !input.network_pseudonym
    ? clientKey(input)
    : networkKey(input)!;
}
function number(value: unknown): number {
  const parsed = typeof value === "number" ? value : Number(value);
  return integer(parsed, "postgres_integer");
}
function tier(value: unknown): number {
  const parsed = number(value);
  if (parsed > 32) throw new Error("postgres_tier");
  return parsed;
}
function integer(value: number, code: string, positive = false): number {
  if (!Number.isSafeInteger(value) || value < (positive ? 1 : 0))
    throw new Error(code);
  return value;
}

function nonNegativeInteger(value: number, code: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(code);
  return value;
}
function checkedIncrement(value: number): number {
  if (value >= Number.MAX_SAFE_INTEGER) throw new Error("postgres_integer");
  return value + 1;
}
function logarithmicTier(count: number): number {
  if (!Number.isSafeInteger(count) || count < 0)
    throw new Error("invalid_pressure_count");
  let tier = 0;
  let threshold = 1;
  while (count > threshold && tier < 32) {
    threshold *= 2;
    tier += 1;
  }
  return tier;
}

function validateAuditEvent(event: AuditEvent): void {
  if (
    event.version !== "audit-v1" ||
    !Number.isSafeInteger(event.occurred_at) ||
    event.occurred_at < 0 ||
    (event.tier !== undefined &&
      (!Number.isSafeInteger(event.tier) || event.tier < 0 || event.tier > 32))
  )
    throw new Error("invalid_audit_event");
  for (const [value, maximum] of [
    [event.tenant, 128],
    [event.site_key, 256],
    [event.action, 128],
  ] as const) {
    if (
      typeof value !== "string" ||
      value.length < 1 ||
      value.length > maximum ||
      /[\0-\x1f\x7f]/.test(value)
    )
      throw new Error("invalid_audit_event");
  }
  if (
    ![
      "challenge_issued",
      "proof_redeemed",
      "site_verified",
      "fallback_completed",
      "proof_failed",
      "verification_failed",
    ].includes(event.kind) ||
    (event.backend !== undefined &&
      !["webgpu", "webgl2", "css"].includes(event.backend)) ||
    (event.code !== undefined && !/^[a-z0-9_]{1,128}$/.test(event.code))
  )
    throw new Error("invalid_audit_event");
}

function policyFromRow(row: Record<string, unknown>): WorkPolicy {
  const version = row.version;
  if (typeof version !== "string") throw new Error("postgres_policy");
  return {
    version,
    baseIterations: BigInt(String(row.base_iterations)),
    baseRenderRounds: integer(
      number(row.base_render_rounds),
      "postgres_policy",
      true,
    ),
    quietWindowSeconds: integer(
      number(row.quiet_window_seconds),
      "postgres_policy",
      true,
    ),
    baseLifetimeSeconds: integer(
      number(row.base_lifetime_seconds),
      "postgres_policy",
      true,
    ),
    iterationAllowance: BigInt(String(row.iteration_allowance)),
    roundAllowanceSeconds: number(row.round_allowance_seconds),
    maxLifetimeSeconds: integer(
      number(row.max_lifetime_seconds),
      "postgres_policy",
      true,
    ),
  };
}
