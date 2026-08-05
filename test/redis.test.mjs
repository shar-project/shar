import assert from "node:assert/strict";
import test from "node:test";
import { RedisStore } from "../packages/server/dist/index.js";

class FakeRedis {
  values = new Set();
  commands = [];
  auditMembers = [];
  async sendCommand(arguments_) {
    this.commands.push([...arguments_]);
    if (arguments_[0] === "PING") return "PONG";
    if (arguments_[0] === "SET") {
      if (this.values.has(arguments_[1])) return null;
      this.values.add(arguments_[1]);
      return "OK";
    }
    if (arguments_[0] === "EVAL" && arguments_[1].includes("return {"))
      return [1, 2, 3, 4, 5, 6, 7];
    if (arguments_[0] === "ZREVRANGEBYSCORE") return this.auditMembers;
    return 1;
  }
}

test("RedisStore readiness requires a PONG response", async () => {
  const client = new FakeRedis();
  const store = new RedisStore(client);
  await store.health();
  assert.deepEqual(client.commands.at(-1), ["PING"]);

  const invalid = new FakeRedis();
  invalid.sendCommand = async () => "NOT_PONG";
  await assert.rejects(
    () => new RedisStore(invalid).health(),
    /redis_health_reply/,
  );
});

test("RedisStore does not replay a failed command and accepts a later recovered request", async () => {
  let commands = 0;
  const client = {
    async sendCommand(arguments_) {
      commands++;
      assert.deepEqual(arguments_, ["PING"]);
      if (commands === 1) throw new Error("connection_lost");
      return "PONG";
    },
  };
  const store = new RedisStore(client);
  await assert.rejects(() => store.health(), /connection_lost/);
  assert.equal(commands, 1);
  await store.health();
  assert.equal(commands, 2);
});

const request = {
  tenant: "tenant-a",
  site_key: "site-a",
  action: "signup",
  origin: "https://app.example",
  session_binding: "private-session",
  network_pseudonym: "daily-network",
  assurance_tier: 6,
};

test("RedisStore consumes each nonce once and retains its inclusive expiry", async () => {
  const client = new FakeRedis();
  const store = new RedisStore(client);
  const results = await Promise.all(
    Array.from({ length: 16 }, () =>
      store.consume("challenge", new Uint8Array([1, 2, 3]), 1_900_000_000),
    ),
  );
  assert.equal(results.filter(Boolean).length, 1);
  assert.deepEqual(client.commands[0].slice(0, 2), [
    "SET",
    "shar:nonce:challenge:AQID",
  ]);
  assert.deepEqual(client.commands[0].slice(-3), ["EXAT", "1900000001", "NX"]);
});

test("RedisStore refuses an expiry that cannot retain the inclusive boundary", async () => {
  const store = new RedisStore(new FakeRedis());
  await assert.rejects(
    () => store.consume("challenge", new Uint8Array([1]), -1),
    /invalid_expiry/,
  );
  await assert.rejects(
    () =>
      store.consume("challenge", new Uint8Array([1]), Number.MAX_SAFE_INTEGER),
    /invalid_expiry/,
  );
});

test("RedisStore rejects Lua deadline arithmetic outside exact integer range", async () => {
  const store = new RedisStore(new FakeRedis());
  await assert.rejects(
    () => store.recordIssued(request, Number.MAX_SAFE_INTEGER - 1, 100),
    /invalid_expiry/,
  );
  await assert.rejects(
    () =>
      store.recordIssued(request, 1_900_000_000, Number.MAX_SAFE_INTEGER - 100),
    /invalid_time/,
  );
});

test("RedisStore pressure scripts use one action hash slot and hide raw bindings", async () => {
  const client = new FakeRedis();
  const store = new RedisStore(client);
  assert.deepEqual(await store.read(request, 100, 60), {
    baseTier: 1,
    velocityTier: 2,
    outstandingTier: 3,
    networkTier: 4,
    failureDebt: 5,
    assuranceDebt: 6,
    trustCredits: 7,
  });
  await store.recordIssued(request, 220, 100);
  await store.recordSuccess(request, 220, 101);
  await store.recordFailure(request, "expired", 220, 102);
  const outcomes = client.commands.filter(
    ([name, script]) =>
      name === "EVAL" && script.includes("local matching=redis.call"),
  );
  assert.equal(outcomes.length, 2);
  assert.ok(
    outcomes.every(
      (command) =>
        command[1].includes("ZRANGEBYSCORE") &&
        !command[1].includes("local oldest"),
    ),
  );
  assert.ok(outcomes.every((command) => command.at(-1) === "220"));
  const cachedKeys = [...store.pressureKeyCache.values()][0];
  await store.read({ ...request }, 103, 60);
  assert.equal(store.pressureKeyCache.size, 1);
  assert.strictEqual([...store.pressureKeyCache.values()][0], cachedKeys);
  await store.read(
    { ...request, network_pseudonym: "different-daily-network" },
    104,
    60,
  );
  assert.equal(store.pressureKeyCache.size, 2);
  const changedKeys = [...store.pressureKeyCache.values()][1];
  assert.notStrictEqual(changedKeys, cachedKeys);
  assert.equal(changedKeys.action, cachedKeys.action);
  assert.equal(changedKeys.client, cachedKeys.client);
  assert.notEqual(changedKeys.network, cachedKeys.network);
  const read = client.commands.find(
    ([name, script]) => name === "EVAL" && script.includes("return {"),
  );
  assert.ok(!read[1].includes("math.log"));
  assert.ok(!read[1].includes("local function ensure"));
  assert.ok(read[1].includes("threshold=threshold*2"));
  assert.ok(read[1].includes("local base=tonumber(cv[4]) or 0"));
  assert.ok(read[1].includes("local aw=tonumber(av[1]) or now"));
  assert.ok(
    read[1].includes("ZREMRANGEBYSCORE',KEYS[4],'-inf','('..tostring(now)"),
  );
  assert.equal(read[3], "shar:{99-im6AWtLvdOHO8SreaEg}:action");
  for (const command of client.commands.filter(([name]) => name === "EVAL")) {
    const keyCount = Number(command[2]);
    const keys = command.slice(3, 3 + keyCount);
    const tags = keys.map((key) => key.match(/\{[^}]+\}/)?.[0]).filter(Boolean);
    assert.equal(new Set(tags).size, 1);
    assert.ok(
      keys.every(
        (key) =>
          !key.includes("private-session") && !key.includes("daily-network"),
      ),
    );
  }
});

test("RedisStore atomically selects an overflow-checked expiry and reserves work", async () => {
  const client = new FakeRedis();
  const store = new RedisStore(client);
  const policy = {
    version: "atomic-test-v1",
    baseIterations: 1n,
    baseRenderRounds: 1,
    quietWindowSeconds: 60,
    baseLifetimeSeconds: 120,
    iterationAllowance: 1_000_000n,
    roundAllowanceSeconds: 0,
    maxLifetimeSeconds: 86_400,
  };
  const quote = await store.priceAndRecord(request, policy, 100);
  assert.equal(quote.tier, 14);
  const command = client.commands.at(-1);
  assert.equal(command[0], "EVAL");
  assert.equal(command[2], "5");
  assert.match(command[1], /ARGV\[8\+total\]/);
  assert.equal(command.length, 3 + 5 + 7 + 33);
  assert.equal(command[3 + 5 + 6], "1");

  const firstExpiries = store.expiryCache.expiries;
  await store.priceAndRecord(request, { ...policy }, 100);
  assert.strictEqual(store.expiryCache.expiries, firstExpiries);
  await store.priceAndRecord(
    request,
    { ...policy, baseLifetimeSeconds: 121 },
    100,
  );
  assert.notStrictEqual(store.expiryCache.expiries, firstExpiries);
  assert.equal(store.expiryCache.expiries[0], firstExpiries[0] + 1);
});

test("RedisStore does not invent an empty cross-slot network key", async () => {
  const client = new FakeRedis();
  const store = new RedisStore(client);
  await store.read(
    { tenant: "t", site_key: "s", action: "a", origin: "https://app.example" },
    100,
    60,
  );
  const command = client.commands.find(([name]) => name === "EVAL");
  assert.equal(command[5], command[4]);
});

test("RedisStore bounds the multi-scope pressure-key cache", async () => {
  const store = new RedisStore(new FakeRedis());
  for (let index = 0; index < 1_024; index++)
    store.pressureKeyCache.set(`scope-${index}`, {
      action: "action",
      client: "client",
      outstanding: "outstanding",
      sequence: "sequence",
    });
  await store.read(request, 100, 60);
  assert.equal(store.pressureKeyCache.size, 1_024);
});

test("RedisStore records timestamp-pruned privacy-filtered audit events", async () => {
  const client = new FakeRedis();
  const store = new RedisStore(client);
  await store.record({
    version: "audit-v1",
    kind: "proof_redeemed",
    occurred_at: 100,
    tenant: "tenant-a",
    site_key: "site-a",
    action: "signup",
    tier: 2,
    backend: "css",
    raw_ip: "203.0.113.9",
  });
  const command = client.commands.find(
    ([name, script]) => name === "EVAL" && script.includes("ZADD"),
  );
  assert.ok(command);
  assert.equal(command[2], "2");
  assert.ok(command[3].startsWith("shar:{"));
  assert.ok(command[4].endsWith(":audit-seq"));
  assert.ok(!command[3].includes("tenant-a"));
  assert.ok(!command[7].includes("private"));
  assert.ok(!command[7].includes("raw_ip"));
  assert.match(command[1], /ZREMRANGEBYSCORE/);
  assert.match(command[1], /EXPIRE/);
});

test("RedisStore batches audit writes by privacy-safe action hash slot", async () => {
  const client = new FakeRedis();
  const store = new RedisStore(client);
  const event = (action, occurred_at) => ({
    version: "audit-v1",
    kind: "challenge_issued",
    occurred_at,
    tenant: "tenant-a",
    site_key: "site-a",
    action,
    tier: 1,
  });
  client.sendCommand = async (arguments_) => {
    client.commands.push([...arguments_]);
    if (arguments_[0] !== "EVAL") return 1;
    return (arguments_.length - 6) / 2;
  };
  await store.recordBatch([
    event("signup", 100),
    event("signup", 101),
    event("checkout", 102),
  ]);
  const commands = client.commands.filter(([name]) => name === "EVAL");
  assert.equal(commands.length, 2);
  const signup = commands.find((command) => command.length === 10);
  assert.ok(signup);
  assert.equal(signup[2], "2");
  assert.equal(signup[5], "0");
  assert.equal(signup[6], "100");
  assert.equal(signup[8], "101");
  assert.match(signup[1], /redis\.call\('INCRBY',KEYS\[2\],count\)/);
  assert.doesNotMatch(signup[1], /redis\.call\('INCR',/);
  assert.equal(signup[1].match(/redis\.call\('ZADD'/g)?.length, 1);
  assert.equal(
    new Set(signup.slice(3, 5).map((key) => key.match(/\{[^}]+\}/)[0])).size,
    1,
  );
});

test("RedisStore scopes bounded audit reads", async () => {
  const client = new FakeRedis();
  client.auditMembers = [
    `100:2:${JSON.stringify({
      version: "audit-v1",
      kind: "site_verified",
      occurred_at: 100,
      tenant: "tenant-a",
      site_key: "site-a",
      action: "signup",
    })}`,
  ];
  const store = new RedisStore(client);
  const events = await store.list("tenant-a", "site-a", "signup", 1);
  assert.equal(events.length, 1);
  assert.equal(events[0].kind, "site_verified");
  const command = client.commands.find(([name]) => name === "ZREVRANGEBYSCORE");
  assert.deepEqual(command.slice(-3), ["LIMIT", "0", "1"]);
  await assert.rejects(
    () => store.list("tenant-a", "site-a", "signup", 101),
    /invalid_audit_limit/,
  );
});
