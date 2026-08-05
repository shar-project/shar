import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { SqliteStore } from "../standalone/js/sqlite.mjs";
import {
  SharService,
  solveRendering,
  solveTimeLock,
} from "../dist/packages/server/src/index.js";

const policy = {
  version: "sqlite-policy-v1",
  baseIterations: 16n,
  baseRenderRounds: 1,
  quietWindowSeconds: 10,
  baseLifetimeSeconds: 120,
  iterationAllowance: 1000n,
  roundAllowanceSeconds: 1,
  maxLifetimeSeconds: 86400,
};
const request = {
  tenant: "tenant",
  site_key: "site",
  action: "submit",
  origin: "https://app.example",
};

test("SQLite atomically persists nonce consumption, policies, and pressure decay", async () => {
  const directory = mkdtempSync(join(tmpdir(), "shar-sqlite-test-"));
  const path = join(directory, "state.sqlite");
  try {
    let store = new SqliteStore(path, { quietWindowSeconds: 10 });
    await store.health();
    const nonce = new Uint8Array(16).fill(4);
    assert.equal(await store.consume("challenge", nonce, 10_000_000_000), true);
    assert.equal(
      await store.consume("challenge", nonce, 10_000_000_000),
      false,
    );
    store.setPolicy("tenant", "site", "submit", policy);
    assert.equal(
      (await store.policy("tenant", "site", "submit")).baseIterations,
      16n,
    );
    assert.equal((await store.read(request, 100)).velocityTier, 0);
    await store.recordIssued(request, 200, 100);
    assert.equal((await store.read(request, 101)).outstandingTier, 1);
    await store.recordFailure(request, "invalid", 200, 101);
    assert.equal((await store.read(request, 102)).failureDebt, 1);
    assert.equal((await store.read(request, 123)).failureDebt, 0);
    store.close();
    store = new SqliteStore(path, { quietWindowSeconds: 10 });
    assert.equal(
      await store.consume("challenge", nonce, 10_000_000_000),
      false,
    );
    assert.equal(
      (await store.policy("tenant", "site", "submit")).version,
      "sqlite-policy-v1",
    );
    await store.health();
    store.close();
    await assert.rejects(() => store.health());
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("SQLite pressure operations reject negative timestamps", async () => {
  const directory = mkdtempSync(join(tmpdir(), "shar-sqlite-time-test-"));
  const path = join(directory, "state.sqlite");
  try {
    const store = new SqliteStore(path, { quietWindowSeconds: 10 });
    await assert.rejects(() => store.read(request, -1), /invalid_time/);
    await assert.rejects(
      () => store.recordIssued(request, 100, -1),
      /invalid_time/,
    );
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("SQLite prices and reserves concurrent quotes in one transaction", async () => {
  const directory = mkdtempSync(join(tmpdir(), "shar-sqlite-atomic-test-"));
  try {
    const store = new SqliteStore(join(directory, "state.sqlite"));
    const atomicPolicy = {
      ...policy,
      baseIterations: 1n,
      baseLifetimeSeconds: 120,
      iterationAllowance: 1_000_000n,
      roundAllowanceSeconds: 0,
    };
    const quotes = await Promise.all(
      Array.from({ length: 64 }, () =>
        store.priceAndRecord(request, atomicPolicy, 1_800_000_000),
      ),
    );
    assert.deepEqual(
      quotes.map(({ tier }) => tier),
      Array.from({ length: 64 }, (_, index) => {
        const count = index + 1;
        const component = count <= 1 ? 0 : Math.ceil(Math.log2(count));
        return component * 2;
      }),
    );
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("SQLite validates its configured state deadline", () => {
  const directory = mkdtempSync(join(tmpdir(), "shar-sqlite-timeout-test-"));
  try {
    assert.throws(
      () =>
        new SqliteStore(join(directory, "low.sqlite"), {
          busyTimeoutMilliseconds: 99,
        }),
      /invalid_busy_timeout/,
    );
    const store = new SqliteStore(join(directory, "valid.sqlite"), {
      busyTimeoutMilliseconds: 750,
    });
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("network-only failures remain network pressure while session debt is uncapped", async () => {
  const directory = mkdtempSync(join(tmpdir(), "shar-network-pressure-test-"));
  const path = join(directory, "state.sqlite");
  try {
    const store = new SqliteStore(path, { quietWindowSeconds: 10 });
    const networkRequest = { ...request, network_pseudonym: "daily-network-a" };
    await store.read(networkRequest, 100);
    for (let index = 0; index < 32; index++)
      await store.recordFailure(networkRequest, "invalid", 200, 101);
    const network = await store.read(networkRequest, 102);
    assert.equal(network.failureDebt, 0);
    assert.equal(network.networkTier, 32);
    await store.recordTrust(networkRequest, 103);
    assert.equal((await store.read(networkRequest, 103)).networkTier, 32);
    const otherNetwork = await store.read(
      { ...request, network_pseudonym: "daily-network-b" },
      102,
    );
    assert.equal(otherNetwork.networkTier, 0);
    const sessionRequest = {
      ...networkRequest,
      session_binding: "host-session",
    };
    await store.recordFailure(sessionRequest, "invalid", 200, 103);
    const session = await store.read(sessionRequest, 104);
    assert.equal(session.failureDebt, 1);
    assert.equal(
      (await store.read({ ...request, assurance_tier: 8 }, 105)).assuranceDebt,
      8,
    );
    assert.equal((await store.read(request, 106)).assuranceDebt, 0);
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("SQLite keeps outstanding quotes through the inclusive expiry second", async () => {
  const directory = mkdtempSync(
    join(tmpdir(), "shar-inclusive-outstanding-test-"),
  );
  const path = join(directory, "state.sqlite");
  try {
    const store = new SqliteStore(path, { quietWindowSeconds: 60 });
    await store.recordIssued(request, 100, 99);
    assert.equal((await store.read(request, 100, 60)).outstandingTier, 1);
    assert.equal((await store.read(request, 101, 60)).outstandingTier, 0);
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("SQLite removes the completed quote by exact expiry", async () => {
  const directory = mkdtempSync(join(tmpdir(), "shar-exact-outstanding-test-"));
  const path = join(directory, "state.sqlite");
  try {
    const store = new SqliteStore(path, { quietWindowSeconds: 60 });
    await store.recordIssued(request, 150, 100);
    await store.recordIssued(request, 300, 101);
    await store.recordSuccess(request, 300, 110);
    assert.equal((await store.read(request, 151, 60)).outstandingTier, 0);

    await store.recordIssued(request, 300, 200);
    await store.recordIssued(request, 250, 201);
    await store.recordFailure(request, "expired", 250, 251);
    assert.equal((await store.read(request, 251, 60)).outstandingTier, 1);
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("SQLite audit events are scoped, retained for one day, and omit request fingerprints", async () => {
  const directory = mkdtempSync(join(tmpdir(), "shar-audit-test-"));
  const path = join(directory, "state.sqlite");
  try {
    const store = new SqliteStore(path, { quietWindowSeconds: 10 });
    await store.record({
      version: "audit-v1",
      kind: "proof_redeemed",
      occurred_at: 100_000,
      tenant: "tenant",
      site_key: "site",
      action: "submit",
      tier: 3,
      backend: "css",
    });
    await store.record({
      version: "audit-v1",
      kind: "site_verified",
      occurred_at: 186_401,
      tenant: "tenant",
      site_key: "site",
      action: "submit",
    });
    const events = store.listAudit();
    assert.equal(events.length, 1);
    assert.equal(events[0].kind, "site_verified");
    assert.equal("origin" in events[0], false);
    assert.equal("session_binding" in events[0], false);
    assert.equal("network_pseudonym" in events[0], false);
    const scoped = store.list("tenant", "site", "submit", 1);
    assert.deepEqual(scoped, [events[0]]);
    assert.deepEqual(store.list("other", "site", "submit"), []);
    await assert.rejects(
      () =>
        store.record({
          version: "audit-v1",
          kind: "proof_redeemed",
          occurred_at: 186_402,
          tenant: "tenant",
          site_key: "site",
          action: "submit",
          code: "raw ip",
        }),
      /invalid_audit_event/,
    );
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("SQLite audit batches commit together and prune once", async () => {
  const directory = mkdtempSync(join(tmpdir(), "shar-audit-batch-test-"));
  const path = join(directory, "state.sqlite");
  const event = (kind, occurred_at) => ({
    version: "audit-v1",
    kind,
    occurred_at,
    tenant: "tenant",
    site_key: "site",
    action: "submit",
  });
  try {
    const store = new SqliteStore(path, { quietWindowSeconds: 10 });
    await store.recordBatch([
      event("proof_redeemed", 100_000),
      event("site_verified", 186_401),
      event("challenge_issued", 186_402),
    ]);
    assert.deepEqual(
      store.list("tenant", "site", "submit", 10).map(({ kind }) => kind),
      ["challenge_issued", "site_verified"],
    );
    await assert.rejects(
      () =>
        store.recordBatch([
          event("proof_redeemed", 186_403),
          { ...event("proof_redeemed", 186_403), code: "raw ip" },
        ]),
      /invalid_audit_event/,
    );
    assert.equal(store.list("tenant", "site", "submit", 10).length, 2);
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("SQLite initializes counters for outstanding rows created before migration", async () => {
  const directory = mkdtempSync(join(tmpdir(), "shar-counter-migration-test-"));
  const path = join(directory, "state.sqlite");
  try {
    const legacy = new DatabaseSync(path);
    legacy.exec(
      "CREATE TABLE outstanding(id INTEGER PRIMARY KEY,scope TEXT NOT NULL,expires_at INTEGER NOT NULL) STRICT;",
    );
    legacy
      .prepare("INSERT INTO outstanding(scope,expires_at) VALUES(?,200)")
      .run("action\0tenant\0site\0submit");
    legacy.close();

    const store = new SqliteStore(path, { quietWindowSeconds: 10 });
    assert.equal((await store.read(request, 100, 10)).outstandingTier, 1);
    await store.recordSuccess(request, 200, 101);
    assert.equal((await store.read(request, 112, 10)).outstandingTier, 0);
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("verification replay protection survives a JavaScript server restart", async () => {
  const directory = mkdtempSync(join(tmpdir(), "shar-restart-test-"));
  const path = join(directory, "state.sqlite");
  try {
    let counter = 0;
    const random = {
      bytes(length) {
        const value = new Uint8Array(length).fill(counter++);
        return value;
      },
    };
    const keys = {
      signing: {
        keyId: new Uint8Array([1]),
        privateSeed: new Uint8Array(32).fill(7),
      },
      timeLock: {
        id: "test",
        modulus: 1_000_036_000_099n,
        lambda: 166_672_333_344n,
      },
    };
    let store = new SqliteStore(path, { quietWindowSeconds: 10 });
    store.setPolicy("tenant", "site", "submit", policy);
    let service = new SharService({
      ...keys,
      nonces: store,
      pressure: store,
      config: store,
      clock: { now: () => 1_800_000_000 },
      random,
      renderTriangles: 8,
      renderSamples: 16,
    });
    const challenge = await service.challenge(request);
    const redeemed = await service.redeem({
      token: challenge.token,
      time_lock: solveTimeLock(challenge.time_lock),
      rendering: {
        backend: "css",
        digest: await solveRendering(challenge.render),
      },
    });
    assert.equal(
      (await service.siteverify({ token: redeemed.token })).success,
      true,
    );
    store.close();
    store = new SqliteStore(path, { quietWindowSeconds: 10 });
    service = new SharService({
      ...keys,
      nonces: store,
      pressure: store,
      config: store,
      clock: { now: () => 1_800_000_001 },
      random,
      renderTriangles: 8,
      renderSamples: 16,
    });
    await assert.rejects(
      () => service.siteverify({ token: redeemed.token }),
      (error) => error.code === "replayed_verification",
    );
    assert.ok((await service.challenge(request)).token.startsWith("shr1_"));
    store.close();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
