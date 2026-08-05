import assert from "node:assert/strict";
import test from "node:test";
import {
  PostgresStore,
  POSTGRES_SCHEMA_V1,
} from "../packages/server/dist/index.js";

class FakePostgresPool {
  nonces = new Set();
  statements = [];
  releases = 0;
  failInsert = false;
  policyRow;

  async query(text, values = []) {
    this.statements.push({ text, values, pooled: true });
    if (text.startsWith("SELECT version")) {
      return {
        rows: this.policyRow ? [this.policyRow] : [],
        rowCount: this.policyRow ? 1 : 0,
      };
    }
    return { rows: [], rowCount: 0 };
  }

  async connect() {
    return {
      query: async (text, values = []) => {
        this.statements.push({ text, values, pooled: false });
        if (this.failInsert && text.startsWith("INSERT INTO shar_nonce"))
          throw new Error("database unavailable");
        if (text.startsWith("INSERT INTO shar_nonce")) {
          const key = `${values[0]}:${values[1]}`;
          if (this.nonces.has(key)) return { rows: [], rowCount: 0 };
          this.nonces.add(key);
          return { rows: [], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      },
      release: () => {
        this.releases++;
      },
    };
  }
}

class ScopeCapturePool extends FakePostgresPool {
  async connect() {
    const connection = await super.connect();
    const query = connection.query;
    connection.query = async (text, values = []) => {
      if (text.startsWith("SELECT * FROM shar_pressure"))
        throw new Error("stop_after_scope_capture");
      return query(text, values);
    };
    return connection;
  }
}

test("PostgreSQL schema enforces durable uniqueness and bounded pressure", () => {
  assert.match(POSTGRES_SCHEMA_V1, /PRIMARY KEY \(namespace, nonce\)/);
  assert.match(POSTGRES_SCHEMA_V1, /failure_debt BETWEEN 0 AND 32/);
  assert.match(POSTGRES_SCHEMA_V1, /PRIMARY KEY \(tenant, site_key, action\)/);
  assert.match(POSTGRES_SCHEMA_V1, /shar_audit_events/);
  assert.match(POSTGRES_SCHEMA_V1, /backend IN \('webgpu', 'webgl2', 'css'\)/);
});

test("PostgresStore readiness uses a read-only database probe", async () => {
  const pool = new FakePostgresPool();
  const store = new PostgresStore(pool);
  await store.health();
  assert.deepEqual(pool.statements.at(-1), {
    text: "SELECT 1",
    values: [],
    pooled: true,
  });
});

test("PostgresStore consumes a nonce exactly once under concurrent callers", async () => {
  const pool = new FakePostgresPool();
  const store = new PostgresStore(pool);
  const outcomes = await Promise.all(
    Array.from({ length: 16 }, () =>
      store.consume("challenge", new Uint8Array([1, 2, 3]), 1_900_000_000),
    ),
  );
  assert.equal(outcomes.filter(Boolean).length, 1);
  assert.equal(pool.releases, 16);
  assert.equal(
    pool.statements.filter(({ text }) => text === "BEGIN").length,
    16,
  );
  assert.equal(
    pool.statements.filter(({ text }) => text === "COMMIT").length,
    16,
  );
  assert.equal(
    pool.statements.filter(({ text }) => text === "ROLLBACK").length,
    0,
  );
});

test("PostgresStore rejects negative nonce expiry before opening a transaction", async () => {
  const pool = new FakePostgresPool();
  const store = new PostgresStore(pool);
  await assert.rejects(
    () => store.consume("challenge", new Uint8Array([1]), -1),
    /invalid_expiry/,
  );
  assert.equal(pool.releases, 0);
});

test("PostgresStore rejects negative pressure timestamps before opening a transaction", async () => {
  const pool = new FakePostgresPool();
  const store = new PostgresStore(pool);
  await assert.rejects(
    () =>
      store.read(
        {
          tenant: "t",
          site_key: "s",
          action: "a",
          origin: "https://app.example",
        },
        -1,
        60,
      ),
    /invalid_time/,
  );
  assert.equal(pool.releases, 0);
});

test("PostgresStore removes one outstanding quote by exact expiry", async () => {
  const pool = new FakePostgresPool();
  const store = new PostgresStore(pool);
  await store.recordSuccess(
    {
      tenant: "tenant",
      site_key: "site",
      action: "submit",
      origin: "https://app.example",
    },
    300,
    110,
  );
  const statement = pool.statements.find(({ text }) =>
    text.startsWith("DELETE FROM shar_outstanding"),
  );
  assert.match(statement.text, /scope=\$1 AND expires_at=\$2/);
  assert.equal(statement.values[1], 300);
});

test("PostgresStore rolls back and releases failed transactions", async () => {
  const pool = new FakePostgresPool();
  pool.failInsert = true;
  const store = new PostgresStore(pool);
  await assert.rejects(
    () => store.consume("verification", new Uint8Array([9]), 1_900_000_000),
    /unavailable/,
  );
  assert.equal(pool.releases, 1);
  assert.equal(
    pool.statements.filter(({ text }) => text === "ROLLBACK").length,
    1,
  );
  assert.equal(
    pool.statements.filter(({ text }) => text === "COMMIT").length,
    0,
  );
});

test("PostgresStore reads and writes policy values without numeric truncation", async () => {
  const pool = new FakePostgresPool();
  pool.policyRow = {
    version: "policy-pg-v1",
    base_iterations: "18446744073709551615",
    base_render_rounds: 2,
    quiet_window_seconds: "60",
    base_lifetime_seconds: "120",
    iteration_allowance: "100000",
    round_allowance_seconds: "2",
    max_lifetime_seconds: "86400",
  };
  const store = new PostgresStore(pool);
  const policy = await store.policy("tenant", "site", "action");
  assert.equal(policy.baseIterations, 18_446_744_073_709_551_615n);
  await store.setPolicy("tenant", "site", "action", policy);
  const insert = pool.statements.find(({ text }) =>
    text.startsWith("INSERT INTO shar_policies"),
  );
  assert.equal(insert.values[4], "18446744073709551615");
});

test("PostgresStore scopes bounded audit reads", async () => {
  const pool = new FakePostgresPool();
  const store = new PostgresStore(pool);
  assert.deepEqual(await store.list("tenant", "site", "action", 7), []);
  const query = pool.statements.find(({ text }) =>
    text.includes("FROM shar_audit_events WHERE tenant=$1"),
  );
  assert.deepEqual(query.values, ["tenant", "site", "action", 7]);
  await assert.rejects(
    () => store.list("tenant", "site", "action", 101),
    /invalid_audit_limit/,
  );
});

test("Postgres pressure scopes use the cross-language safe encoding", async () => {
  const pool = new ScopeCapturePool();
  const store = new PostgresStore(pool);
  await assert.rejects(
    () =>
      store.read(
        {
          tenant: "tenant-a",
          site_key: "site-a",
          action: "signup",
          origin: "https://app.example",
          session_binding: "session-a",
          network_pseudonym: "daily-network-a",
        },
        1_800_000_000,
        60,
      ),
    /stop_after_scope_capture/,
  );
  const scopes = pool.statements
    .filter(({ text }) => text.startsWith("INSERT INTO shar_pressure"))
    .map(({ values }) => values[0]);
  assert.deepEqual(scopes, [
    "action:v1:dGVuYW50LWE:c2l0ZS1h:c2lnbnVw",
    "client:v1:dGVuYW50LWE:c2l0ZS1h:c2lnbnVw:c2Vzc2lvbi1h",
    "network:v1:dGVuYW50LWE:c2l0ZS1h:c2lnbnVw:ZGFpbHktbmV0d29yay1h",
  ]);
  assert.ok(scopes.every((scope) => !scope.includes("\0")));
});
