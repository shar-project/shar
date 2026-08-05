import { DatabaseSync } from "node:sqlite";
import { base64url } from "../../dist/packages/server/src/bytes.js";
import { DEFAULT_POLICY } from "../../dist/packages/server/src/stores.js";
import { priceWork } from "../../dist/packages/server/src/pricing.js";

export class SqliteStore {
  #database;
  #quietWindow;
  #statements = new Map();
  constructor(path, options = {}) {
    this.#quietWindow =
      options.quietWindowSeconds ?? DEFAULT_POLICY.quietWindowSeconds;
    if (!Number.isSafeInteger(this.#quietWindow) || this.#quietWindow <= 0)
      throw new Error("invalid_quiet_window");
    const busyTimeout = options.busyTimeoutMilliseconds ?? 5_000;
    if (
      !Number.isSafeInteger(busyTimeout) ||
      busyTimeout < 100 ||
      busyTimeout > 60_000
    )
      throw new Error("invalid_busy_timeout");
    this.#database = new DatabaseSync(path);
    this.#database.exec(
      `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=${busyTimeout};`,
    );
    this.#database.exec(`
      CREATE TABLE IF NOT EXISTS nonce_consumptions(namespace TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(namespace, nonce)) STRICT;
      CREATE TABLE IF NOT EXISTS pressure(scope TEXT PRIMARY KEY, base_tier INTEGER NOT NULL DEFAULT 0, network_tier INTEGER NOT NULL DEFAULT 0, failure_debt INTEGER NOT NULL DEFAULT 0, assurance_debt INTEGER NOT NULL DEFAULT 0, trust_credits INTEGER NOT NULL DEFAULT 0, last_activity INTEGER NOT NULL, window_start INTEGER NOT NULL, request_count INTEGER NOT NULL DEFAULT 0) STRICT;
      CREATE TABLE IF NOT EXISTS outstanding(id INTEGER PRIMARY KEY, scope TEXT NOT NULL, expires_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS outstanding_scope_expiry ON outstanding(scope, expires_at);
      CREATE TABLE IF NOT EXISTS outstanding_counts(scope TEXT PRIMARY KEY, count INTEGER NOT NULL CHECK(count>=0)) STRICT;
      CREATE TRIGGER IF NOT EXISTS outstanding_count_after_insert AFTER INSERT ON outstanding BEGIN
        INSERT INTO outstanding_counts(scope,count) VALUES(NEW.scope,1)
        ON CONFLICT(scope) DO UPDATE SET count=CASE WHEN count>=9007199254740991 THEN 9007199254740991 ELSE count+1 END;
      END;
      CREATE TRIGGER IF NOT EXISTS outstanding_count_after_delete AFTER DELETE ON outstanding BEGIN
        UPDATE outstanding_counts SET count=MAX(0,count-1) WHERE scope=OLD.scope;
      END;
      CREATE TABLE IF NOT EXISTS policies(tenant TEXT NOT NULL, site_key TEXT NOT NULL, action TEXT NOT NULL, version TEXT NOT NULL, base_iterations TEXT NOT NULL, base_render_rounds INTEGER NOT NULL, quiet_window_seconds INTEGER NOT NULL, base_lifetime_seconds INTEGER NOT NULL, iteration_allowance TEXT NOT NULL, round_allowance_seconds INTEGER NOT NULL, max_lifetime_seconds INTEGER NOT NULL, PRIMARY KEY(tenant, site_key, action)) STRICT;
      CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL CHECK(version='audit-v1'), kind TEXT NOT NULL, occurred_at INTEGER NOT NULL CHECK(occurred_at>=0), tenant TEXT NOT NULL, site_key TEXT NOT NULL, action TEXT NOT NULL, tier INTEGER CHECK(tier BETWEEN 0 AND 32), backend TEXT CHECK(backend IN ('webgpu','webgl2','css') OR backend IS NULL), code TEXT) STRICT;
      CREATE INDEX IF NOT EXISTS audit_events_expiry ON audit_events(occurred_at);
    `);
    this.#database
      .prepare(
        "INSERT OR IGNORE INTO outstanding_counts(scope,count) SELECT scope,COUNT(*) FROM outstanding GROUP BY scope",
      )
      .run();
  }
  close() {
    this.#database.close();
  }
  async health() {
    const row = this.#database.prepare("SELECT 1 AS ready").get();
    if (Number(row?.ready) !== 1) throw new Error("sqlite_health_reply");
  }
  #transaction(operation) {
    this.#database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.#database.exec("COMMIT");
      return result;
    } catch (error) {
      try {
        this.#database.exec("ROLLBACK");
      } catch {}
      throw error;
    }
  }
  #statement(sql) {
    let statement = this.#statements.get(sql);
    if (!statement) {
      statement = this.#database.prepare(sql);
      this.#statements.set(sql, statement);
    }
    return statement;
  }
  #baseScope(input) {
    return `${input.tenant}\0${input.site_key}\0${input.action}`;
  }
  #actionScope(input) {
    return `action\0${this.#baseScope(input)}`;
  }
  #clientScope(input) {
    return `client\0${this.#baseScope(input)}\0${input.session_binding ?? ""}`;
  }
  #networkScope(input) {
    return input.network_pseudonym
      ? `network\0${this.#baseScope(input)}\0${input.network_pseudonym}`
      : undefined;
  }
  #failureScope(input) {
    return input.session_binding || !input.network_pseudonym
      ? this.#clientScope(input)
      : this.#networkScope(input);
  }
  #ensurePressure(scope, now) {
    this.#statement(
      "INSERT OR IGNORE INTO pressure(scope,last_activity,window_start) VALUES(?,?,?)",
    ).run(scope, now, now);
  }
  async consume(namespace, nonce, expiresAt) {
    if (!Number.isSafeInteger(expiresAt) || expiresAt < 0)
      throw new Error("invalid_expiry");
    return this.#transaction(() => {
      const now = Math.floor(Date.now() / 1000);
      this.#database
        .prepare("DELETE FROM nonce_consumptions WHERE expires_at < ?")
        .run(now);
      const result = this.#database
        .prepare(
          "INSERT OR IGNORE INTO nonce_consumptions(namespace, nonce, expires_at) VALUES(?, ?, ?)",
        )
        .run(namespace, base64url(nonce), expiresAt);
      return Number(result.changes) === 1;
    });
  }
  #readPressure(input, now, quietWindowSeconds = this.#quietWindow) {
    nonNegativeInteger(now, "invalid_time");
    if (!Number.isSafeInteger(quietWindowSeconds) || quietWindowSeconds <= 0)
      throw new Error("invalid_quiet_window");
    const actionScope = this.#actionScope(input),
      clientScope = this.#clientScope(input),
      networkScope = this.#networkScope(input);
    this.#statement(
      "DELETE FROM outstanding WHERE scope=? AND expires_at<?",
    ).run(actionScope, now);

    const action = this.#statement(
      `INSERT INTO pressure(scope,last_activity,window_start,request_count) VALUES(?,?,?,1)
       ON CONFLICT(scope) DO UPDATE SET
         last_activity=excluded.last_activity,
         request_count=CASE WHEN MAX(0,excluded.last_activity-pressure.window_start)>=? THEN 1 WHEN pressure.request_count>=9007199254740991 THEN 9007199254740991 ELSE pressure.request_count+1 END,
         window_start=CASE WHEN MAX(0,excluded.last_activity-pressure.window_start)>=? THEN excluded.last_activity ELSE pressure.window_start END
       RETURNING request_count`,
    ).get(actionScope, now, now, quietWindowSeconds, quietWindowSeconds);
    const actionCount = Number(action.request_count);

    const requestedAssurance = Number(input.assurance_tier ?? 0);
    const persistAssurance = input.session_binding ? 1 : 0;
    const client = this.#statement(
      `INSERT INTO pressure(scope,last_activity,window_start,assurance_debt) VALUES(?,?,?,CASE WHEN ?=1 THEN ? ELSE 0 END)
       ON CONFLICT(scope) DO UPDATE SET
         failure_debt=MAX(0,pressure.failure_debt-CAST(MAX(0,excluded.last_activity-pressure.last_activity)/? AS INTEGER)),
         assurance_debt=CASE WHEN ?=1
           THEN MAX(MAX(0,pressure.assurance_debt-CAST(MAX(0,excluded.last_activity-pressure.last_activity)/? AS INTEGER)),?)
           ELSE MAX(0,pressure.assurance_debt-CAST(MAX(0,excluded.last_activity-pressure.last_activity)/? AS INTEGER)) END,
         last_activity=excluded.last_activity
       RETURNING base_tier,failure_debt,assurance_debt,trust_credits`,
    ).get(
      clientScope,
      now,
      now,
      persistAssurance,
      requestedAssurance,
      quietWindowSeconds,
      persistAssurance,
      quietWindowSeconds,
      requestedAssurance,
      quietWindowSeconds,
    );
    const failure = Number(client.failure_debt);
    const assurance = Math.max(
      Number(client.assurance_debt),
      requestedAssurance,
    );

    let networkTier = 0;
    if (networkScope) {
      const network = this.#statement(
        `INSERT INTO pressure(scope,last_activity,window_start,request_count) VALUES(?,?,?,1)
         ON CONFLICT(scope) DO UPDATE SET
           failure_debt=MAX(0,pressure.failure_debt-CAST(MAX(0,excluded.last_activity-pressure.last_activity)/? AS INTEGER)),
           last_activity=excluded.last_activity,
           request_count=CASE WHEN MAX(0,excluded.last_activity-pressure.window_start)>=? THEN 1 WHEN pressure.request_count>=9007199254740991 THEN 9007199254740991 ELSE pressure.request_count+1 END,
           window_start=CASE WHEN MAX(0,excluded.last_activity-pressure.window_start)>=? THEN excluded.last_activity ELSE pressure.window_start END
         RETURNING network_tier,failure_debt,request_count`,
      ).get(
        networkScope,
        now,
        now,
        quietWindowSeconds,
        quietWindowSeconds,
        quietWindowSeconds,
      );
      const networkFailure = Number(network.failure_debt);
      const networkCount = Number(network.request_count);
      networkTier = Math.max(
        Number(network.network_tier),
        networkFailure,
        logarithmicTier(networkCount),
      );
    }
    const outstanding = Number(
      this.#statement(
        "SELECT COALESCE((SELECT count FROM outstanding_counts WHERE scope=?),0) AS count",
      ).get(actionScope).count,
    );
    return {
      baseTier: Number(client.base_tier),
      velocityTier: logarithmicTier(actionCount),
      outstandingTier: logarithmicTier(outstanding + 1),
      networkTier,
      failureDebt: failure,
      assuranceDebt: assurance,
      trustCredits: Number(client.trust_credits),
    };
  }
  async read(input, now, quietWindowSeconds = this.#quietWindow) {
    return this.#transaction(() =>
      this.#readPressure(input, now, quietWindowSeconds),
    );
  }
  async priceAndRecord(input, policy, now) {
    return this.#transaction(() => {
      const pressure = this.#readPressure(
        input,
        now,
        policy.quietWindowSeconds,
      );
      const quote = priceWork(pressure, policy, now);
      const scope = this.#actionScope(input);
      this.#statement(
        "INSERT INTO outstanding(scope,expires_at) VALUES(?,?)",
      ).run(scope, quote.expires_at);
      return quote;
    });
  }
  async recordIssued(input, expiresAt, now) {
    nonNegativeInteger(expiresAt, "invalid_expiry");
    nonNegativeInteger(now, "invalid_time");
    this.#transaction(() => {
      const scope = this.#actionScope(input);
      this.#ensurePressure(scope, now);
      this.#database
        .prepare("INSERT INTO outstanding(scope,expires_at) VALUES(?,?)")
        .run(scope, expiresAt);
      this.#database
        .prepare("UPDATE pressure SET last_activity=? WHERE scope=?")
        .run(now, scope);
    });
  }
  async recordSuccess(input, expiresAt, now) {
    nonNegativeInteger(now, "invalid_time");
    nonNegativeInteger(expiresAt, "invalid_expiry");
    this.#transaction(() => {
      const failureScope = this.#failureScope(input),
        actionScope = this.#actionScope(input);
      this.#ensurePressure(failureScope, now);
      this.#database
        .prepare(
          "UPDATE pressure SET failure_debt=MAX(0,failure_debt-1),last_activity=? WHERE scope=?",
        )
        .run(now, failureScope);
      this.#database
        .prepare(
          "DELETE FROM outstanding WHERE id=(SELECT id FROM outstanding WHERE scope=? AND expires_at=? ORDER BY id LIMIT 1)",
        )
        .run(actionScope, expiresAt);
    });
  }
  async recordFailure(input, kind, expiresAt, now) {
    nonNegativeInteger(now, "invalid_time");
    nonNegativeInteger(expiresAt, "invalid_expiry");
    this.#transaction(() => {
      const failureScope = this.#failureScope(input),
        actionScope = this.#actionScope(input);
      this.#ensurePressure(failureScope, now);
      this.#database
        .prepare(
          "UPDATE pressure SET failure_debt=MIN(32,failure_debt+1),last_activity=? WHERE scope=?",
        )
        .run(now, failureScope);
      if (kind === "expired") {
        this.#database
          .prepare(
            "DELETE FROM outstanding WHERE id=(SELECT id FROM outstanding WHERE scope=? AND expires_at=? ORDER BY id LIMIT 1)",
          )
          .run(actionScope, expiresAt);
      }
    });
  }
  async recordTrust(input, now) {
    nonNegativeInteger(now, "invalid_time");
    this.#transaction(() => {
      // Trust credits never reduce the rotating network-pressure bucket.
      const failureScope = this.#clientScope(input);
      this.#ensurePressure(failureScope, now);
      this.#database
        .prepare(
          "UPDATE pressure SET failure_debt=CASE WHEN failure_debt>0 THEN failure_debt-1 ELSE failure_debt END,assurance_debt=CASE WHEN failure_debt=0 THEN MAX(0,assurance_debt-1) ELSE assurance_debt END,last_activity=? WHERE scope=?",
        )
        .run(now, failureScope);
    });
  }
  async recordAudit(event) {
    validateAuditEvent(event);
    this.#transaction(() => {
      this.#database
        .prepare(
          "INSERT INTO audit_events(version,kind,occurred_at,tenant,site_key,action,tier,backend,code) VALUES(?,?,?,?,?,?,?,?,?)",
        )
        .run(
          event.version,
          event.kind,
          event.occurred_at,
          event.tenant,
          event.site_key,
          event.action,
          event.tier ?? null,
          event.backend ?? null,
          event.code ?? null,
        );
      this.#database
        .prepare("DELETE FROM audit_events WHERE occurred_at < ?")
        .run(event.occurred_at - 86_400);
    });
  }
  async record(event) {
    return this.recordAudit(event);
  }
  async recordBatch(events) {
    if (!Array.isArray(events)) throw new Error("invalid_audit_batch");
    if (events.length === 0) return;
    for (const event of events) validateAuditEvent(event);
    const cutoff =
      Math.max(...events.map((event) => event.occurred_at)) - 86_400;
    this.#transaction(() => {
      const insert = this.#statement(
        "INSERT INTO audit_events(version,kind,occurred_at,tenant,site_key,action,tier,backend,code) VALUES(?,?,?,?,?,?,?,?,?)",
      );
      for (const event of events) {
        insert.run(
          event.version,
          event.kind,
          event.occurred_at,
          event.tenant,
          event.site_key,
          event.action,
          event.tier ?? null,
          event.backend ?? null,
          event.code ?? null,
        );
      }
      this.#statement("DELETE FROM audit_events WHERE occurred_at < ?").run(
        cutoff,
      );
    });
  }
  async purgeAudit(before) {
    if (!Number.isSafeInteger(before) || before < 0)
      throw new Error("invalid_audit_cutoff");
    this.#database
      .prepare("DELETE FROM audit_events WHERE occurred_at < ?")
      .run(before);
  }
  async purge(before) {
    return this.purgeAudit(before);
  }
  listAudit(limit = 100) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
      throw new Error("invalid_audit_limit");
    return this.#database
      .prepare(
        "SELECT version,kind,occurred_at,tenant,site_key,action,tier,backend,code FROM audit_events ORDER BY id LIMIT ?",
      )
      .all(limit)
      .map((row) => {
        const event = auditEventFromRow(row);
        validateAuditEvent(event);
        return event;
      });
  }
  list(tenant, siteKey, action, limit = 100) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Error("invalid_audit_limit");
    return this.#database
      .prepare(
        "SELECT version,kind,occurred_at,tenant,site_key,action,tier,backend,code FROM audit_events WHERE tenant=? AND site_key=? AND action=? ORDER BY id DESC LIMIT ?",
      )
      .all(tenant, siteKey, action, limit)
      .map((row) => {
        const event = auditEventFromRow(row);
        validateAuditEvent(event);
        return event;
      });
  }
  async policy(tenant, siteKey, action) {
    const row = this.#database
      .prepare(
        "SELECT * FROM policies WHERE tenant=? AND site_key=? AND action=?",
      )
      .get(tenant, siteKey, action);
    if (!row) return DEFAULT_POLICY;
    return {
      version: String(row.version),
      baseIterations: BigInt(row.base_iterations),
      baseRenderRounds: Number(row.base_render_rounds),
      quietWindowSeconds: Number(row.quiet_window_seconds),
      baseLifetimeSeconds: Number(row.base_lifetime_seconds),
      iterationAllowance: BigInt(row.iteration_allowance),
      roundAllowanceSeconds: Number(row.round_allowance_seconds),
      maxLifetimeSeconds: Number(row.max_lifetime_seconds),
    };
  }
  setPolicy(tenant, siteKey, action, policy) {
    this.#database
      .prepare(
        "INSERT INTO policies VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant,site_key,action) DO UPDATE SET version=excluded.version,base_iterations=excluded.base_iterations,base_render_rounds=excluded.base_render_rounds,quiet_window_seconds=excluded.quiet_window_seconds,base_lifetime_seconds=excluded.base_lifetime_seconds,iteration_allowance=excluded.iteration_allowance,round_allowance_seconds=excluded.round_allowance_seconds,max_lifetime_seconds=excluded.max_lifetime_seconds",
      )
      .run(
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
      );
  }
}
function auditEventFromRow(row) {
  return {
    version: String(row.version),
    kind: String(row.kind),
    occurred_at: Number(row.occurred_at),
    tenant: String(row.tenant),
    site_key: String(row.site_key),
    action: String(row.action),
    ...(row.tier === null ? {} : { tier: Number(row.tier) }),
    ...(row.backend === null ? {} : { backend: String(row.backend) }),
    ...(row.code === null ? {} : { code: String(row.code) }),
  };
}
function logarithmicTier(count) {
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

function nonNegativeInteger(value, code) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(code);
  return value;
}

function validateAuditEvent(event) {
  if (
    !event ||
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
  ]) {
    if (
      typeof value !== "string" ||
      value.length < 1 ||
      value.length > maximum ||
      /[\0-\x1f\x7f]/.test(value)
    )
      throw new Error("invalid_audit_event");
  }
  if (
    typeof event.kind !== "string" ||
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
