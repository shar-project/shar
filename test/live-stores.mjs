import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { checkServerIdentity } from "node:tls";
import {
  PostgresStore,
  RedisStore,
  base64url,
} from "../packages/server/dist/index.js";

const postgresUrl = process.env.SHAR_TEST_POSTGRES_URL;
const redisUrl = process.env.SHAR_TEST_REDIS_URL;
if (!postgresUrl && !redisUrl)
  throw new Error("set SHAR_TEST_POSTGRES_URL and/or SHAR_TEST_REDIS_URL");

function tlsVerificationHost(url) {
  const hostname = url.hostname;
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

function fixture(label) {
  return {
    nonce: randomBytes(16),
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    request: {
      tenant: `live-${label}-${base64url(randomBytes(8))}`,
      site_key: "store-test",
      action: "concurrent-race",
      origin: "https://app.example",
      session_binding: "session-a",
      network_pseudonym: "daily-network-a",
      assurance_tier: 2,
    },
  };
}

const atomicPolicy = {
  version: "atomic-test-v1",
  baseIterations: 1n,
  baseRenderRounds: 1,
  quietWindowSeconds: 60,
  baseLifetimeSeconds: 120,
  iterationAllowance: 1_000_000n,
  roundAllowanceSeconds: 0,
  maxLifetimeSeconds: 86_400,
};

function logarithmicTier(count) {
  return count <= 1 ? 0 : Math.ceil(Math.log2(count));
}

async function exercise(name, store, value, previous) {
  if (previous)
    assert.equal(
      await store.consume("challenge", previous.nonce, previous.expiresAt),
      false,
      `${name}: consumed nonce was accepted after reconnect`,
    );
  const outcomes = await Promise.all(
    Array.from({ length: 64 }, () =>
      store.consume("challenge", value.nonce, value.expiresAt),
    ),
  );
  assert.equal(
    outcomes.filter(Boolean).length,
    1,
    `${name}: nonce race did not have exactly one winner`,
  );
  const atomicRequest = {
    ...value.request,
    action: `${value.request.action}-atomic`,
    session_binding: undefined,
    network_pseudonym: undefined,
    assurance_tier: undefined,
  };
  const quotes = await Promise.all(
    Array.from({ length: 64 }, () =>
      store.priceAndRecord(atomicRequest, atomicPolicy, 1_800_000_000),
    ),
  );
  assert.deepEqual(
    quotes.map((quote) => quote.tier).sort((left, right) => left - right),
    Array.from({ length: 64 }, (_, index) => 2 * logarithmicTier(index + 1)),
    `${name}: price/reservation race underpriced concurrent quotes`,
  );
  const first = await store.read(value.request, 1_800_000_000, 60);
  assert.equal(first.assuranceDebt, 2, `${name}: assurance pressure mismatch`);
  await store.recordIssued(value.request, 1_800_000_120, 1_800_000_000);
  await store.recordFailure(
    value.request,
    "invalid",
    1_800_000_120,
    1_800_000_001,
  );
  const pressured = await store.read(value.request, 1_800_000_002, 60);
  assert.ok(
    pressured.failureDebt >= 1,
    `${name}: failure debt was not persisted`,
  );
  await store.recordSuccess(value.request, 1_800_000_120, 1_800_000_003);
  if (
    typeof store.recordBatch === "function" &&
    typeof store.list === "function"
  ) {
    const events = [-100_000, 1, 2, 3, 3].map((offset) => ({
      version: "audit-v1",
      kind: "challenge_issued",
      occurred_at: 1_800_000_000 + offset,
      tenant: value.request.tenant,
      site_key: value.request.site_key,
      action: value.request.action,
      tier: Math.max(0, offset),
    }));
    await store.recordBatch(events);
    const retained = await store.list(
      value.request.tenant,
      value.request.site_key,
      value.request.action,
      events.length,
    );
    assert.deepEqual(
      retained.map((event) => event.occurred_at),
      events
        .slice(1)
        .map((event) => event.occurred_at)
        .reverse(),
      `${name}: batched audit events were not retained in descending order`,
    );
  }
  console.log(`${name}: concurrent nonce and pressure contract passed`);
  return value;
}

if (postgresUrl) {
  const { Pool } = await import("pg");
  const postgresConnectionUrl = new URL(postgresUrl);
  const ssl =
    process.env.SHAR_TEST_POSTGRES_TLS === "0"
      ? false
      : {
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
          checkServerIdentity: (_host, certificate) =>
            checkServerIdentity(
              tlsVerificationHost(postgresConnectionUrl),
              certificate,
            ),
          ...(process.env.SHAR_TEST_POSTGRES_CA_FILE
            ? {
                ca: readFileSync(
                  process.env.SHAR_TEST_POSTGRES_CA_FILE,
                  "utf8",
                ),
              }
            : {}),
        };
  for (const parameter of ["sslmode", "sslcert", "sslkey", "sslrootcert"])
    postgresConnectionUrl.searchParams.delete(parameter);
  const options = {
    connectionString: postgresConnectionUrl.href,
    max: 10,
    ssl,
  };
  let pool = new Pool(options);
  const values = [];
  try {
    const store = new PostgresStore(pool);
    await store.migrate();
    values.push(await exercise("PostgreSQL", store, fixture("postgres")));
    await pool.end();
    pool = new Pool(options);
    const restarted = new PostgresStore(pool);
    await restarted.migrate();
    values.push(
      await exercise(
        "PostgreSQL after reconnect",
        restarted,
        fixture("postgres-reconnect"),
        values[0],
      ),
    );
    for (const value of values)
      await pool.query(
        "DELETE FROM shar_nonce_consumptions WHERE namespace=$1 AND nonce=$2",
        ["challenge", base64url(value.nonce)],
      );
  } finally {
    await pool.end();
  }
}

if (redisUrl) {
  const { createClient } = await import("redis");
  const socket = redisUrl.startsWith("rediss://")
    ? {
        rejectUnauthorized: true,
        minVersion: "TLSv1.2",
        checkServerIdentity: (_host, certificate) =>
          checkServerIdentity(
            tlsVerificationHost(new URL(redisUrl)),
            certificate,
          ),
        ...(process.env.SHAR_TEST_REDIS_CA_FILE
          ? {
              ca: readFileSync(process.env.SHAR_TEST_REDIS_CA_FILE, "utf8"),
            }
          : {}),
      }
    : undefined;
  let client = createClient({ url: redisUrl, socket });
  client.on("error", (error) =>
    console.error(`Redis test connection error: ${error.message}`),
  );
  await client.connect();
  const values = [];
  try {
    const store = new RedisStore(client);
    values.push(await exercise("Redis", store, fixture("redis")));
    await client.close();
    client = createClient({ url: redisUrl, socket });
    client.on("error", (error) =>
      console.error(`Redis reconnect error: ${error.message}`),
    );
    await client.connect();
    const restarted = new RedisStore(client);
    values.push(
      await exercise(
        "Redis after reconnect",
        restarted,
        fixture("redis-reconnect"),
        values[0],
      ),
    );
    await client.del(
      ...values.map(
        (value) => `shar:nonce:challenge:${base64url(value.nonce)}`,
      ),
    );
  } finally {
    if (client.isOpen) await client.close();
  }
}
