import { readFile } from "node:fs/promises";
import test from "node:test";
import assert from "node:assert/strict";
import {
  MemoryNonceStore,
  MemoryAuditStore,
  MemoryPressureStore,
  BufferedAuditStore,
  CoseSigner,
  DailyNetworkPseudonymizer,
  DEFAULT_POLICY,
  DEFAULT_RENDER_PREDICATES,
  DEFAULT_RENDER_SAMPLES,
  DEFAULT_RENDER_TRIANGLES,
  SharService,
  StaticConfigStore,
  StoredFallbackVerifier,
  base64url,
  coseSign,
  coseVerify,
  createSharHandler,
  cssTranscriptCommitment,
  decodeCbor,
  deriveCanonicalCssTranscript,
  encodeCbor,
  fromBase64url,
  priceWork,
  publicFromSeed,
  selectTriangles,
  triangleContains,
  solveRendering,
  solveRenderingWithExecutor,
  solveTimeLock,
  dailyNetworkPseudonym,
  deriveTimeLockInput,
  validateTimeLockKey,
  deriveSiteVerifySecret,
  verifySiteVerifySecret,
} from "../dist/packages/server/src/index.js";

const policy = {
  version: "policy-test-v1",
  baseIterations: 16n,
  baseRenderRounds: 1,
  quietWindowSeconds: 60,
  baseLifetimeSeconds: 120,
  iterationAllowance: 1000n,
  roundAllowanceSeconds: 1,
  maxLifetimeSeconds: 86400,
};

const workPriceVectors = JSON.parse(
  await readFile(
    new URL("../protocol/work-price-vectors.json", import.meta.url),
  ),
);
const malformedCborVectors = JSON.parse(
  await readFile(
    new URL("../protocol/malformed-cbor-vectors.json", import.meta.url),
  ),
);
const rswKeyValidationVectors = JSON.parse(
  await readFile(
    new URL("../protocol/rsw-key-validation-vectors.json", import.meta.url),
  ),
);
const renderVectors = JSON.parse(
  await readFile(
    new URL("../protocol/render-v1-vectors.json", import.meta.url),
  ),
);
const hostProviderVectors = JSON.parse(
  await readFile(
    new URL("../protocol/host-provider-vectors.json", import.meta.url),
  ),
);
const fallbackAssertionVectors = JSON.parse(
  await readFile(
    new URL("../protocol/fallback-assertion-vectors.json", import.meta.url),
  ),
);
const boundedTextVectors = JSON.parse(
  await readFile(
    new URL("../protocol/bounded-text-vectors.json", import.meta.url),
  ),
);
const allowedOriginVectors = JSON.parse(
  await readFile(
    new URL("../protocol/allowed-origin-vectors.json", import.meta.url),
  ),
);

function expandMalformedVector(vector) {
  const output = [];
  for (const segment of vector.segments) {
    assert.match(segment.hex, /^(?:[0-9a-f]{2})*$/);
    const bytes =
      segment.hex.match(/../g)?.map((value) => Number.parseInt(value, 16)) ??
      [];
    for (let repeat = 0; repeat < segment.repeat; repeat++)
      output.push(...bytes);
  }
  return new Uint8Array(output);
}

test("canonical CBOR sorts keys and rejects non-canonical integers", () => {
  const encoded = encodeCbor(
    new Map([
      ["b", 2],
      [1, "one"],
      ["a", 1],
    ]),
  );
  assert.equal(base64url(encoded), "owFjb25lYWEBYWIC");
  assert.equal(decodeCbor(encoded).get("a"), 1);
  assert.throws(() => decodeCbor(new Uint8Array([0x18, 0x01])), /noncanonical/);
  assert.throws(
    () => decodeCbor(new Uint8Array([0xa2, 0x02, 0x00, 0x01, 0x00])),
    /noncanonical_map/,
  );
  assert.throws(
    () => decodeCbor(new Uint8Array([0xa2, 0x01, 0x00, 0x01, 0x01])),
    /noncanonical_map/,
  );
  assert.throws(
    () =>
      encodeCbor(
        new Map([
          [1, "a"],
          [1n, "b"],
        ]),
      ),
    /duplicate_map_key/,
  );
});

test("RSW trapdoor validation matches language-neutral vectors", () => {
  for (const vector of rswKeyValidationVectors.vectors) {
    assert.equal(
      validateTimeLockKey({
        id: vector.name,
        modulus: BigInt(vector.modulus),
        lambda: BigInt(vector.lambda),
      }),
      vector.valid,
      vector.name,
    );
  }
});

test("service construction rejects corrupt and colliding RSW keys", () => {
  const timeLock = {
    id: "rsw-current",
    modulus: 1_000_036_000_099n,
    lambda: 166_672_333_344n,
  };
  const options = {
    signing: {
      keyId: new Uint8Array([1]),
      privateSeed: new Uint8Array(32).fill(7),
    },
    timeLock,
    nonces: new MemoryNonceStore(),
    pressure: new MemoryPressureStore(),
    config: new StaticConfigStore(policy),
    clock: { now: () => 100 },
    random: { bytes: (length) => new Uint8Array(length) },
  };
  assert.throws(
    () =>
      new SharService({
        ...options,
        timeLock: { ...timeLock, lambda: timeLock.lambda + 1n },
      }),
    /time_lock_key/,
  );
  assert.throws(
    () =>
      new SharService({
        ...options,
        previousTimeLocks: [{ ...timeLock, lambda: timeLock.lambda * 2n }],
      }),
    /time_lock_key_id_collision/,
  );
  const nonAtomicPressure = new MemoryPressureStore();
  nonAtomicPressure.priceAndRecord = undefined;
  assert.throws(
    () => new SharService({ ...options, pressure: nonAtomicPressure }),
    /atomic_pressure_store_required/,
  );
});

test("bounded hostile CBOR corpus rejects without state mutation", async () => {
  assert.deepEqual(malformedCborVectors.limits, {
    maximum_depth: 64,
    maximum_items: 4096,
  });
  const keyId = new Uint8Array([1]);
  const publicKey = await publicFromSeed(new Uint8Array(32).fill(7));
  let pressureMutations = 0;
  let nonceConsumptions = 0;
  const pressureProbe = {
    read: async () => ({
      baseTier: 0,
      velocityTier: 0,
      outstandingTier: 0,
      networkTier: 0,
      failureDebt: 0,
      assuranceDebt: 0,
      trustCredits: 0,
    }),
    priceAndRecord: async () => {
      pressureMutations++;
      throw new Error("unexpected pricing mutation");
    },
    recordIssued: async () => pressureMutations++,
    recordSuccess: async () => pressureMutations++,
    recordFailure: async () => pressureMutations++,
    recordTrust: async () => pressureMutations++,
  };
  const nonceProbe = {
    consume: async () => {
      nonceConsumptions++;
      return true;
    },
  };
  const state = fixture({ pressure: pressureProbe, nonces: nonceProbe });

  for (const vector of malformedCborVectors.vectors) {
    const bytes = expandMalformedVector(vector);
    if (vector.outcome === "accept")
      assert.doesNotThrow(() => decodeCbor(bytes));
    else assert.throws(() => decodeCbor(bytes), undefined, vector.name);

    const token = `shr1_${base64url(bytes)}`;
    await assert.rejects(
      () => coseVerify(token, [{ keyId, publicKey }]),
      undefined,
      vector.name,
    );
    await assert.rejects(
      () =>
        state.service.redeem({
          token,
          time_lock: { output: "AA" },
          rendering: { backend: "css", digest: "AA" },
        }),
      (error) => error?.code === "invalid_challenge",
      vector.name,
    );
  }
  assert.equal(pressureMutations, 0);
  assert.equal(nonceConsumptions, 0);
  assert.deepEqual(state.audit.snapshot(), []);
});

test("Ed25519 COSE Sign1 round-trips and detects alteration", async () => {
  const seed = new Uint8Array(32).fill(7);
  const keyId = new Uint8Array([1, 2, 3, 4]);
  const publicKey = await publicFromSeed(seed);
  assert.equal(
    base64url(publicKey),
    "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",
  );
  const token = await coseSign(new Uint8Array([1, 2, 3]), {
    keyId,
    privateSeed: seed,
  });
  assert.deepEqual(
    await coseVerify(token, [{ keyId, publicKey }]),
    new Uint8Array([1, 2, 3]),
  );
  const tail = token.at(-1);
  await assert.rejects(() =>
    coseVerify(token.slice(0, -1) + (tail === "A" ? "B" : "A"), [
      { keyId, publicKey },
    ]),
  );
});

test("pure TypeScript Ed25519 is byte-identical and auto-falls back without WebCrypto Ed25519", async () => {
  const seed = new Uint8Array(32).fill(7);
  const keyId = new Uint8Array([1, 2, 3, 4]);
  const payload = new Uint8Array([1, 2, 3]);
  const webPublic = await publicFromSeed(seed, "webcrypto");
  const tsPublic = await publicFromSeed(seed, "typescript");
  assert.deepEqual(tsPublic, webPublic);
  const webToken = await coseSign(
    payload,
    { keyId, privateSeed: seed },
    "webcrypto",
  );
  const tsToken = await coseSign(
    payload,
    { keyId, privateSeed: seed },
    "typescript",
  );
  assert.equal(tsToken, webToken);
  const reusableWebSigner = new CoseSigner(
    { keyId, privateSeed: seed },
    "webcrypto",
  );
  const reusableTypeScriptSigner = new CoseSigner(
    { keyId, privateSeed: seed },
    "typescript",
  );
  assert.equal(await reusableWebSigner.sign(payload), webToken);
  assert.equal(await reusableWebSigner.sign(payload), webToken);
  assert.equal(await reusableTypeScriptSigner.sign(payload), tsToken);
  assert.deepEqual(
    await coseVerify(webToken, [{ keyId, publicKey: tsPublic }], "typescript"),
    payload,
  );

  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: {
      subtle: {
        importKey: async () => {
          throw new DOMException("unsupported", "NotSupportedError");
        },
      },
    },
  });
  try {
    const fallbackPublic = await publicFromSeed(seed);
    const fallbackToken = await coseSign(payload, { keyId, privateSeed: seed });
    assert.deepEqual(fallbackPublic, tsPublic);
    assert.equal(fallbackToken, tsToken);
    assert.deepEqual(
      await coseVerify(fallbackToken, [{ keyId, publicKey: fallbackPublic }]),
      payload,
    );
  } finally {
    if (descriptor) Object.defineProperty(globalThis, "crypto", descriptor);
    else Reflect.deleteProperty(globalThis, "crypto");
  }
});

test("daily network pseudonym matches Rust, rotates, and supports site scoping", async () => {
  const secret = new Uint8Array(32).fill(5);
  const address = new TextEncoder().encode("203.0.113.9");
  const reusableSecret = secret.slice();
  const reusable = new DailyNetworkPseudonymizer(reusableSecret);
  assert.equal(
    await dailyNetworkPseudonym(secret, address, 1_800_000_000),
    "Ef3J3xx8_qDuqQkHDW3A_w",
  );
  assert.equal(
    await reusable.pseudonym(address, 1_800_000_000),
    "Ef3J3xx8_qDuqQkHDW3A_w",
  );
  reusableSecret.fill(6);
  assert.equal(
    await reusable.pseudonym(address, 1_800_000_000),
    "Ef3J3xx8_qDuqQkHDW3A_w",
  );
  assert.notEqual(
    await dailyNetworkPseudonym(secret, address, 1_800_000_000),
    await dailyNetworkPseudonym(secret, address, 1_800_086_400),
  );
  const scoped = new TextEncoder().encode(
    ["tenant-a", "site-a", "203.0.113.9"].join(String.fromCharCode(0)),
  );
  assert.equal(
    await dailyNetworkPseudonym(secret, scoped, 1_800_000_000),
    "HTtNSqJ2qefLMc6XeJXWgQ",
  );
});
test("site verification credentials match Rust and fail closed when altered", async () => {
  const master = new Uint8Array(32).fill(13);
  const secret = await deriveSiteVerifySecret(master, "tenant-a", "site-a");
  assert.equal(
    secret,
    "shrs1_AQAIdGVuYW50LWEABnNpdGUtYcmPEinTIUA9EfB7rzqbMNpqjSG59aMCVJECR59QLoJX",
  );
  assert.deepEqual(await verifySiteVerifySecret(master, secret), {
    tenant: "tenant-a",
    site_key: "site-a",
  });
  assert.equal(
    await verifySiteVerifySecret(master, `${secret.slice(0, -1)}A`),
    undefined,
  );
});
test("RSW input is coprime and matches Rust", async () => {
  assert.equal(
    await deriveTimeLockInput(new Uint8Array(16), 1_000_036_000_099n),
    817_057_293_964n,
  );
  // The public helper preserves rejection sampling for non-production even
  // moduli too; common powers of two must not be discarded by binary GCD.
  assert.equal(await deriveTimeLockInput(new Uint8Array(16), 6n), 5n);
  assert.equal(await deriveTimeLockInput(new Uint8Array(16), 1_000n), 609n);
});

test("work pricing caps network pressure and trust only offsets debt", () => {
  const now = 100;
  const network = priceWork(
    {
      baseTier: 0,
      velocityTier: 0,
      outstandingTier: 0,
      networkTier: 32,
      failureDebt: 0,
      assuranceDebt: 0,
      trustCredits: 32,
    },
    policy,
    now,
  );
  assert.equal(network.tier, 4);
  assert.equal(network.time_lock_iterations, 256n);
  const debt = priceWork(
    {
      baseTier: 1,
      velocityTier: 2,
      outstandingTier: 3,
      networkTier: 4,
      failureDebt: 9,
      assuranceDebt: 8,
      trustCredits: 12,
    },
    policy,
    now,
  );
  assert.equal(debt.tier, 15);
  const maximum = priceWork(
    {
      baseTier: 32,
      velocityTier: 32,
      outstandingTier: 32,
      networkTier: 32,
      failureDebt: 32,
      assuranceDebt: 32,
      trustCredits: 0,
    },
    policy,
    now,
  );
  assert.equal(maximum.tier, 32);
  assert.equal(maximum.time_lock_iterations, 68_719_476_736n);
});

test("default pricing starts at exactly two minutes and leaves tier 32 uncapped", () => {
  const now = 1_800_000_000;
  const empty = {
    baseTier: 0,
    velocityTier: 0,
    outstandingTier: 0,
    networkTier: 0,
    failureDebt: 0,
    assuranceDebt: 0,
    trustCredits: 0,
  };
  assert.equal(priceWork(empty, DEFAULT_POLICY, now).expires_at, now + 120);
  const maximum = priceWork({ ...empty, baseTier: 32 }, DEFAULT_POLICY, now);
  assert.equal(maximum.expires_at - now, 43_984_411);
  assert.ok(maximum.expires_at - now < DEFAULT_POLICY.maxLifetimeSeconds);
});

test("work pricing matches the language-neutral shared vectors", () => {
  const vectorPolicy = {
    version: workPriceVectors.policy.version,
    baseIterations: BigInt(workPriceVectors.policy.base_iterations),
    baseRenderRounds: workPriceVectors.policy.base_render_rounds,
    quietWindowSeconds: workPriceVectors.policy.quiet_window_seconds,
    baseLifetimeSeconds: workPriceVectors.policy.base_lifetime_seconds,
    iterationAllowance: BigInt(workPriceVectors.policy.iteration_allowance),
    roundAllowanceSeconds: workPriceVectors.policy.round_allowance_seconds,
    maxLifetimeSeconds: workPriceVectors.policy.max_lifetime_seconds,
  };
  for (const vector of workPriceVectors.vectors) {
    const pressure = {
      baseTier: vector.pressure.base_tier,
      velocityTier: vector.pressure.velocity_tier,
      outstandingTier: vector.pressure.outstanding_tier,
      networkTier: vector.pressure.network_tier,
      failureDebt: vector.pressure.failure_debt,
      assuranceDebt: vector.pressure.assurance_debt,
      trustCredits: vector.pressure.trust_credits,
    };
    const quote = priceWork(pressure, vectorPolicy, workPriceVectors.now);
    assert.deepEqual(
      { ...quote, time_lock_iterations: quote.time_lock_iterations.toString() },
      vector.quote,
      vector.name,
    );
  }
});

test("work pricing keeps every configured quote inside the render ceiling", () => {
  assert.throws(
    () =>
      priceWork(
        {
          baseTier: 32,
          velocityTier: 0,
          outstandingTier: 0,
          networkTier: 0,
          failureDebt: 0,
          assuranceDebt: 0,
          trustCredits: 0,
        },
        { ...policy, baseRenderRounds: 257 },
        100,
      ),
    /work_overflow/,
  );
});

test("work pricing rejects numeric overflow instead of wrapping or truncating", () => {
  assert.throws(
    () =>
      priceWork(
        {
          baseTier: 1,
          velocityTier: 0,
          outstandingTier: 0,
          networkTier: 0,
          failureDebt: 0,
          assuranceDebt: 0,
          trustCredits: 0,
        },
        { ...policy, baseIterations: 1n << 63n },
        100,
      ),
    /work_overflow/,
  );
  assert.throws(
    () =>
      priceWork(
        {
          baseTier: 0,
          velocityTier: 0,
          outstandingTier: 0,
          networkTier: 0,
          failureDebt: 0,
          assuranceDebt: 0,
          trustCredits: 0,
        },
        policy,
        Number.MAX_SAFE_INTEGER,
      ),
    /work_overflow/,
  );
});

test("work pricing rejects a zero base lifetime consistently with durable stores", () => {
  assert.throws(
    () =>
      priceWork(
        {
          baseTier: 0,
          velocityTier: 0,
          outstandingTier: 0,
          networkTier: 0,
          failureDebt: 0,
          assuranceDebt: 0,
          trustCredits: 0,
        },
        { ...policy, baseLifetimeSeconds: 0 },
        100,
      ),
    /invalid_policy/,
  );
});

test("optional pressure scopes reject empty or control-bearing values", async () => {
  const { service } = fixture();
  await assert.rejects(
    () => service.challenge({ ...challengeRequest, session_binding: "" }),
    (error) => error.code === "invalid_session_binding",
  );
  await assert.rejects(
    () => service.challenge({ ...challengeRequest, network_pseudonym: "" }),
    (error) => error.code === "invalid_network_pseudonym",
  );
  await assert.rejects(
    () =>
      service.challenge({
        ...challengeRequest,
        network_pseudonym: "daily\u0000network",
      }),
    (error) => error.code === "invalid_network_pseudonym",
  );
});

test("request text bounds match language-neutral UTF-8 vectors", async () => {
  assert.equal(boundedTextVectors.version, "bounded-text-v1");
  for (const vector of boundedTextVectors.vectors) {
    const request = {
      ...challengeRequest,
      [vector.field]: vector.unit.repeat(vector.repetitions),
    };
    const { service } = fixture();
    if (vector.valid) {
      assert.equal(
        (await service.challenge(request)).quote.tier,
        0,
        vector.name,
      );
    } else {
      await assert.rejects(
        () => service.challenge(request),
        (error) => error.code === vector.error,
        vector.name,
      );
    }
  }
});

test("memory pressure isolates daily networks from session failure debt", async () => {
  const store = new MemoryPressureStore(10);
  const network = { ...challengeRequest, network_pseudonym: "daily-a" };
  await store.read(network, 100, 10);
  for (let index = 0; index < 32; index++)
    await store.recordFailure(network, "invalid", 200, 101);
  const pressured = await store.read(network, 102, 10);
  assert.equal(pressured.failureDebt, 0);
  assert.equal(pressured.networkTier, 32);
  await store.recordTrust(network, 103);
  const afterTrust = await store.read(network, 103, 10);
  assert.equal(afterTrust.networkTier, 32);
  assert.equal(
    (
      await store.read(
        { ...challengeRequest, network_pseudonym: "daily-b" },
        103,
        10,
      )
    ).networkTier,
    0,
  );
  const session = { ...network, session_binding: "session-a" };
  await store.recordFailure(session, "invalid", 200, 103);
  assert.equal((await store.read(session, 104, 10)).failureDebt, 1);
});

test("memory pressure decays deterministic state that starts at epoch zero", async () => {
  const store = new MemoryPressureStore(10);
  await store.read(challengeRequest, 0, 10);
  await store.recordFailure(challengeRequest, "invalid", 200, 0);
  assert.equal((await store.read(challengeRequest, 10, 10)).failureDebt, 0);
});

test("memory pressure uses exact integer tier boundaries", async () => {
  const store = new MemoryPressureStore(60);
  const tiers = [];
  for (let count = 1; count <= 9; count++)
    tiers.push((await store.read(challengeRequest, 100, 60)).velocityTier);
  assert.deepEqual(tiers, [0, 1, 2, 2, 3, 3, 3, 3, 4]);
});

test("memory pressure removes the completed quote's exact expiry", async () => {
  const store = new MemoryPressureStore(60);
  await store.recordIssued(challengeRequest, 150, 100);
  await store.recordIssued(challengeRequest, 300, 101);
  await store.recordSuccess(challengeRequest, 300, 110);
  assert.equal(
    (await store.read(challengeRequest, 151, 60)).outstandingTier,
    0,
  );

  await store.recordIssued(challengeRequest, 300, 200);
  await store.recordIssued(challengeRequest, 250, 201);
  await store.recordFailure(challengeRequest, "expired", 250, 251);
  assert.equal(
    (await store.read(challengeRequest, 251, 60)).outstandingTier,
    1,
  );
});

test("memory pressure keeps an outstanding quote through its inclusive expiry", async () => {
  const store = new MemoryPressureStore(60);
  await store.recordIssued(challengeRequest, 100, 99);
  assert.equal(
    (await store.read(challengeRequest, 100, 60)).outstandingTier,
    1,
  );
  assert.equal(
    (await store.read(challengeRequest, 101, 60)).outstandingTier,
    0,
  );
});

test("memory nonce store rejects negative expiry values", async () => {
  const store = new MemoryNonceStore(() => 100);
  await assert.rejects(
    () => store.consume("challenge", new Uint8Array([1]), -1),
    /invalid_expiry/,
  );
});

test("memory nonce storage accepts an injected deterministic clock", async () => {
  let now = 0;
  const store = new MemoryNonceStore(() => now);
  const nonce = new Uint8Array([1]);
  assert.equal(await store.consume("challenge", nonce, 1), true);
  assert.equal(await store.consume("challenge", nonce, 1), false);
  now = 2;
  assert.equal(await store.consume("challenge", nonce, 3), true);
});

test("memory audit store retains only privacy-filtered events", async () => {
  const audit = new MemoryAuditStore();
  await audit.record({
    version: "audit-v1",
    kind: "challenge_issued",
    occurred_at: 1,
    tenant: "tenant",
    site_key: "site",
    action: "submit",
    tier: 0,
  });
  await audit.record({
    version: "audit-v1",
    kind: "proof_redeemed",
    occurred_at: 86_402,
    tenant: "tenant",
    site_key: "site",
    action: "submit",
    tier: 1,
    backend: "webgpu",
    raw_ip: "203.0.113.9",
  });
  assert.deepEqual(audit.snapshot(), [
    {
      version: "audit-v1",
      kind: "proof_redeemed",
      occurred_at: 86_402,
      tenant: "tenant",
      site_key: "site",
      action: "submit",
      tier: 1,
      backend: "webgpu",
    },
  ]);
  await assert.rejects(
    () =>
      audit.record({
        version: "audit-v1",
        kind: "proof_redeemed",
        occurred_at: 86_403,
        tenant: "tenant",
        site_key: "site",
        action: "submit",
        code: "user-agent",
      }),
    /invalid_audit_event/,
  );
});

test("audit outages never reject a correct proof", async () => {
  let counter = 0;
  const keys = {
    signing: {
      keyId: new Uint8Array([1]),
      privateSeed: new Uint8Array(32).fill(7),
    },
    timeLock: {
      id: "audit-test",
      modulus: 1_000_036_000_099n,
      lambda: 166_672_333_344n,
    },
  };
  const service = new SharService({
    ...keys,
    nonces: new MemoryNonceStore(),
    pressure: new MemoryPressureStore(),
    config: new StaticConfigStore(policy),
    clock: { now: () => 100 },
    random: {
      bytes(length) {
        return new Uint8Array(length).fill(counter++);
      },
    },
    audit: {
      record() {
        throw new Error("audit unavailable");
      },
    },
    renderTriangles: 8,
    renderSamples: 16,
  });
  const request = {
    tenant: "tenant",
    site_key: "site",
    action: "submit",
    origin: "https://app.example",
  };
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
});

test("bounded audit buffering never blocks proofs and counts overflow or storage loss", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const persisted = [];
  let dropped = 0;
  const event = (action) => ({
    version: "audit-v1",
    kind: "challenge_issued",
    occurred_at: 1_700_000_000,
    tenant: "tenant-a",
    site_key: "site-a",
    action,
    tier: 0,
  });
  const audit = new BufferedAuditStore(
    {
      async record(value) {
        if (value.action === "first") await gate;
        if (value.action === "storage-error") throw new Error("offline");
        persisted.push(value.action);
      },
    },
    1,
    () => dropped++,
  );

  void audit.record(event("first"));
  await Promise.resolve();
  await audit.record(event("second"));
  await audit.record(event("overflow"));
  assert.equal(dropped, 1);
  release();
  await new Promise((resolve) => setTimeout(resolve, 0));
  await audit.record(event("storage-error"));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.deepEqual(persisted, ["first", "second"]);
  assert.equal(dropped, 2);

  const { service } = fixture();
  const handler = createSharHandler(service, {
    auditEventsDropped: () => dropped,
  });
  const metrics = await handler(new Request("https://shar.example/metrics"));
  const metricText = await metrics.text();
  assert.match(metricText, /shar_audit_events_dropped_total 2\n/);
  assert.match(
    metricText,
    /shar_challenge_engine_duration_seconds_total 0\.000000\n/,
  );
  assert.match(
    metricText,
    /shar_challenge_handler_duration_seconds_total 0\.000000\n/,
  );
});

test("successful challenge metrics expose equivalent engine and handler phases", async () => {
  const { service } = fixture();
  const handler = createSharHandler(service, {
    allowedOrigins: ["https://app.example"],
  });
  const issued = await handler(
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: {
        origin: "https://app.example",
        "content-type": "application/json",
      },
      body: JSON.stringify(challengeRequest),
    }),
  );
  assert.equal(issued.status, 200);

  const metrics = await handler(new Request("https://shar.example/metrics"));
  const metricText = await metrics.text();
  const value = (name) => {
    const match = metricText.match(new RegExp(`^${name} ([0-9.]+)$`, "m"));
    assert.ok(match, `${name} must be present`);
    return Number(match[1]);
  };
  const engine = value("shar_challenge_engine_duration_seconds_total");
  const fullHandler = value("shar_challenge_handler_duration_seconds_total");
  assert.equal(value("shar_challenges_issued_total"), 1);
  assert.ok(engine > 0);
  assert.ok(fullHandler >= engine);
});

test("audit buffering coalesces batch-capable stores", async () => {
  const batches = [];
  const audit = new BufferedAuditStore(
    {
      async record() {
        assert.fail("the batch path should be used");
      },
      async recordBatch(events) {
        batches.push(events.map(({ action }) => action));
      },
    },
    32,
  );
  await Promise.all(
    ["one", "two", "three"].map((action) =>
      audit.record({
        version: "audit-v1",
        kind: "challenge_issued",
        occurred_at: 1_700_000_000,
        tenant: "tenant-a",
        site_key: "site-a",
        action,
        tier: 0,
      }),
    ),
  );
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.deepEqual(batches, [["one", "two", "three"]]);
});

test("audit flush waits for accepted work and closes the buffer", async () => {
  let release;
  let started;
  const storageStarted = new Promise((resolve) => {
    started = resolve;
  });
  const storageGate = new Promise((resolve) => {
    release = resolve;
  });
  let dropped = 0;
  const persisted = [];
  const audit = new BufferedAuditStore(
    {
      async record() {
        assert.fail("the batch path should be used");
      },
      async recordBatch(events) {
        started();
        await storageGate;
        persisted.push(...events.map(({ action }) => action));
      },
    },
    32,
    () => dropped++,
  );
  await audit.record({
    version: "audit-v1",
    kind: "challenge_issued",
    occurred_at: 1_700_000_000,
    tenant: "tenant-a",
    site_key: "site-a",
    action: "queued",
    tier: 0,
  });
  let flushed = false;
  const flushing = audit.flush().then(() => {
    flushed = true;
  });
  await storageStarted;
  await Promise.resolve();
  assert.equal(flushed, false);
  release();
  await flushing;
  await audit.flush();
  assert.deepEqual(persisted, ["queued"]);

  await audit.record({
    version: "audit-v1",
    kind: "challenge_issued",
    occurred_at: 1_700_000_001,
    tenant: "tenant-a",
    site_key: "site-a",
    action: "after-close",
    tier: 0,
  });
  assert.equal(dropped, 1);
  assert.deepEqual(persisted, ["queued"]);
});

test("audit flush counts storage failure without rejecting shutdown", async () => {
  let dropped = 0;
  const audit = new BufferedAuditStore(
    {
      async record() {
        throw new Error("offline");
      },
      async recordBatch() {
        throw new Error("offline");
      },
    },
    32,
    () => dropped++,
  );
  for (const action of ["one", "two", "three"])
    await audit.record({
      version: "audit-v1",
      kind: "challenge_issued",
      occurred_at: 1_700_000_000,
      tenant: "tenant-a",
      site_key: "site-a",
      action,
      tier: 0,
    });
  await audit.flush();
  assert.equal(dropped, 3);
});

test("render-v1 digest matches the Rust conformance vector", async () => {
  const plan = {
    version: "render-v1",
    seed: base64url(new Uint8Array(32)),
    rounds: 2,
    triangles: 8,
    samples: 16,
  };
  assert.equal(
    await solveRendering(plan),
    "XBnikgSO8AzOfMrpg1EDZH46vjjovkkGRA9MmiQv7_A",
  );
  assert.equal(
    await cssTranscriptCommitment(plan),
    "amIKy6SKVrc5Vi4HgSJBTCZCpLF_B6Z9ahgvpTRVDoA",
  );
});

test("render-v1 CSS transcript and geometry match language-neutral vectors", async () => {
  for (const vector of renderVectors.cases) {
    const seed = fromBase64url(vector.seed);
    const transcript = deriveCanonicalCssTranscript(seed);
    assert.deepEqual(
      [
        transcript.chainWidth,
        transcript.layoutHeight,
        transcript.gridFirstWidth,
        transcript.gridSecondWidth,
        transcript.flexFirstWidth,
        transcript.flexSecondWidth,
        transcript.intrinsicWidth,
        transcript.queryBranch,
        transcript.styleBranch,
        transcript.nestedBranch,
        transcript.transformX,
        transcript.transformY,
        transcript.verticalWriting,
        transcript.hitId,
        transcript.topologyDepth,
      ],
      vector.transcript_words,
      vector.name,
    );
    const plan = {
      version: "render-v1",
      seed: vector.seed,
      rounds: vector.rounds,
      triangles: vector.triangles,
      samples: vector.samples,
    };
    assert.equal(await solveRendering(plan), vector.digest, vector.name);
    assert.equal(
      await cssTranscriptCommitment(plan),
      vector.css_commitment,
      vector.name,
    );
  }
});

test("independent render executors feed one canonical checked reduction", async () => {
  const plan = {
    version: "render-v1",
    seed: base64url(new Uint8Array(32)),
    rounds: 2,
    triangles: 8,
    samples: 16,
  };
  const reference = await solveRendering(plan);
  assert.equal(
    await solveRenderingWithExecutor(plan, async (program) =>
      selectTriangles(program),
    ),
    reference,
  );
  await assert.rejects(
    () =>
      solveRenderingWithExecutor(plan, async (program) =>
        selectTriangles(program).slice(1),
      ),
    /render_selection_count/,
  );
  const altered = await solveRenderingWithExecutor(plan, async (program) => {
    const values = selectTriangles(program);
    const first = values[0];
    values[0] = [first[0] ^ 1, first[1]];
    return values;
  });
  assert.notEqual(altered, reference);
});

test("render-v1 resumes only a validated contiguous round prefix", async () => {
  const plan = {
    version: "render-v1",
    seed: base64url(new Uint8Array(32).fill(19)),
    rounds: 3,
    triangles: 8,
    samples: 16,
  };
  const completedRoundDigests = [];
  const reference = await solveRenderingWithExecutor(
    plan,
    async (program) => selectTriangles(program),
    {
      onRoundDigest: (_completed, digest) => completedRoundDigests.push(digest),
    },
  );
  assert.equal(completedRoundDigests.length, 3);

  let executions = 0;
  const resumed = await solveRenderingWithExecutor(
    plan,
    async (program, round) => {
      executions++;
      assert.equal(round, 2);
      return selectTriangles(program);
    },
    { completedRoundDigests: completedRoundDigests.slice(0, 2) },
  );
  assert.equal(resumed, reference);
  assert.equal(executions, 1);

  await assert.rejects(
    () =>
      solveRenderingWithExecutor(plan, async () => [], {
        completedRoundDigests: ["not-a-digest"],
      }),
    /render_checkpoint/,
  );
  await assert.rejects(
    () =>
      solveRenderingWithExecutor(plan, async () => [], {
        completedRoundDigests: completedRoundDigests.concat(
          completedRoundDigests[0],
        ),
      }),
    /render_checkpoint/,
  );
});

test("render-v1 Number edge arithmetic stays exact at protocol bounds", () => {
  const bigintContains = (triangle, x, y) => {
    const edge = (ax, ay, bx, by) =>
      BigInt(x - ax) * BigInt(by - ay) - BigInt(y - ay) * BigInt(bx - ax);
    const values = [
      edge(triangle.ax, triangle.ay, triangle.bx, triangle.by),
      edge(triangle.bx, triangle.by, triangle.cx, triangle.cy),
      edge(triangle.cx, triangle.cy, triangle.ax, triangle.ay),
    ];
    return (
      values.every((value) => value >= 0n) ||
      values.every((value) => value <= 0n)
    );
  };
  const triangles = [
    {
      id: 1,
      z: 1,
      ax: 64,
      ay: 64,
      bx: 1_048_512,
      by: 64,
      cx: 64,
      cy: 1_048_512,
    },
    {
      id: 2,
      z: 2,
      ax: 1_048_512,
      ay: 1_048_512,
      bx: 64,
      by: 1_048_512,
      cx: 1_048_512,
      cy: 64,
    },
  ];
  for (const triangle of triangles)
    for (const [x, y] of [
      [64, 64],
      [524_288, 524_288],
      [1_048_512, 1_048_512],
      [64, 1_048_512],
    ])
      assert.equal(
        triangleContains(triangle, x, y),
        bigintContains(triangle, x, y),
      );
});

test("complete challenge envelope matches the Rust conformance vector", async () => {
  const p = 1_000_003n,
    q = 1_000_033n;
  const gcd = (a, b) => {
    while (b) [a, b] = [b, a % b];
    return a;
  };
  const outputs = [new Uint8Array(16), new Uint8Array(32).fill(1)];
  const service = new SharService({
    signing: {
      keyId: new Uint8Array([9, 9, 9, 1]),
      privateSeed: new Uint8Array(32).fill(7),
    },
    timeLock: {
      id: "test-rsw",
      modulus: p * q,
      lambda: ((p - 1n) * (q - 1n)) / gcd(p - 1n, q - 1n),
    },
    nonces: new MemoryNonceStore(),
    pressure: new MemoryPressureStore(),
    config: new StaticConfigStore(policy),
    clock: { now: () => 1_800_000_000 },
    random: { bytes: () => outputs.shift() },
    renderTriangles: 24,
    renderSamples: 64,
  });
  const challenge = await service.challenge({
    tenant: "tenant-a",
    site_key: "site-a",
    action: "signup",
    origin: "https://app.example",
  });
  assert.equal(
    challenge.token,
    "shr1_hEmiAScERAkJCQGgWKuxAGljaGFsbGVuZ2UBZ3NoYXItdjECaHRlbmFudC1hA2ZzaXRlLWEEZnNpZ251cAVzaHR0cHM6Ly9hcHAuZXhhbXBsZQYaa0nSAAcaa0nSeAhucG9saWN5LXRlc3QtdjEJAAoQCwEMUAAAAAAAAAAAAAAAAAAAAAANWCABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ5odGVzdC1yc3cQGBgRGEBYQPDsYCzP1bKKSa_GLMn2Y2EhJpJfpVEllXqdjPgS8WFs1DqUyi3KTpt6oxEBNMfC_pO85_lY3KUY8kwxHdFP6gA",
  );
});

test("overlapping verification keys honor work issued before rotation", async () => {
  const p = 1_000_003n,
    q = 1_000_033n;
  const gcd = (a, b) => {
    while (b) [a, b] = [b, a % b];
    return a;
  };
  const timeLock = {
    id: "rotation",
    modulus: p * q,
    lambda: ((p - 1n) * (q - 1n)) / gcd(p - 1n, q - 1n),
  };
  const nonces = new MemoryNonceStore(),
    pressure = new MemoryPressureStore();
  let counter = 0;
  const random = { bytes: (length) => new Uint8Array(length).fill(counter++) };
  const oldSigning = {
    keyId: new Uint8Array([1]),
    privateSeed: new Uint8Array(32).fill(7),
  };
  const oldService = new SharService({
    signing: oldSigning,
    timeLock,
    nonces,
    pressure,
    config: new StaticConfigStore(policy),
    clock: { now: () => 1_800_000_000 },
    random,
    renderTriangles: 8,
    renderSamples: 16,
  });
  const issued = await oldService.challenge(challengeRequest);
  const newSigning = {
    keyId: new Uint8Array([2]),
    privateSeed: new Uint8Array(32).fill(8),
  };
  const verificationKeys = [
    {
      keyId: newSigning.keyId,
      publicKey: await publicFromSeed(newSigning.privateSeed),
    },
    {
      keyId: oldSigning.keyId,
      publicKey: await publicFromSeed(oldSigning.privateSeed),
    },
  ];
  const rotated = new SharService({
    signing: newSigning,
    verificationKeys,
    timeLock,
    nonces,
    pressure,
    config: new StaticConfigStore(policy),
    clock: { now: () => 1_800_000_001 },
    random,
    renderTriangles: 8,
    renderSamples: 16,
  });
  const redeemed = await rotated.redeem({
    token: issued.token,
    time_lock: solveTimeLock(issued.time_lock),
    rendering: { backend: "css", digest: await solveRendering(issued.render) },
  });
  assert.equal(redeemed.receipt.tier, 0);
  assert.equal((await rotated.wellKnown()).keys.length, 2);
  assert.equal(
    (await rotated.siteverify({ token: redeemed.token })).success,
    true,
  );
});

test("overlapping RSW trapdoors honor quotes issued before modulus rotation", async () => {
  const gcd = (a, b) => {
    while (b) [a, b] = [b, a % b];
    return a;
  };
  const make = (id, p, q) => ({
    id,
    modulus: p * q,
    lambda: ((p - 1n) * (q - 1n)) / gcd(p - 1n, q - 1n),
  });
  const oldTimeLock = make("rsw-old", 1_000_003n, 1_000_033n),
    newTimeLock = make("rsw-new", 1_000_037n, 1_000_039n);
  const nonces = new MemoryNonceStore(),
    pressure = new MemoryPressureStore();
  let counter = 0;
  const random = { bytes: (length) => new Uint8Array(length).fill(counter++) };
  const oldSigning = {
    keyId: new Uint8Array([1]),
    privateSeed: new Uint8Array(32).fill(7),
  };
  const oldService = new SharService({
    signing: oldSigning,
    timeLock: oldTimeLock,
    nonces,
    pressure,
    config: new StaticConfigStore(policy),
    clock: { now: () => 1_800_000_000 },
    random,
    renderTriangles: 8,
    renderSamples: 16,
  });
  const issued = await oldService.challenge(challengeRequest);
  const newSigning = {
    keyId: new Uint8Array([2]),
    privateSeed: new Uint8Array(32).fill(8),
  };
  const rotated = new SharService({
    signing: newSigning,
    verificationKeys: [
      {
        keyId: newSigning.keyId,
        publicKey: await publicFromSeed(newSigning.privateSeed),
      },
      {
        keyId: oldSigning.keyId,
        publicKey: await publicFromSeed(oldSigning.privateSeed),
      },
    ],
    timeLock: newTimeLock,
    previousTimeLocks: [oldTimeLock],
    nonces,
    pressure,
    config: new StaticConfigStore(policy),
    clock: { now: () => 1_800_000_001 },
    random,
    renderTriangles: 8,
    renderSamples: 16,
  });
  const redeemed = await rotated.redeem({
    token: issued.token,
    time_lock: solveTimeLock(issued.time_lock),
    rendering: { backend: "css", digest: await solveRendering(issued.render) },
  });
  assert.equal(redeemed.receipt.tier, 0);
  assert.deepEqual((await rotated.wellKnown()).modulus_ids, [
    "rsw-new",
    "rsw-old",
  ]);
});

function fixture(overrides = {}) {
  let now = 1_800_000_000;
  let counter = 0;
  const random = {
    bytes(length) {
      const out = new Uint8Array(length);
      for (let i = 0; i < length; i++) out[i] = (counter + i) & 255;
      counter += length;
      return out;
    },
  };
  const p = 1_000_003n,
    q = 1_000_033n;
  const gcd = (a, b) => {
    while (b) [a, b] = [b, a % b];
    return a;
  };
  const timeLock = {
    id: "test-rsw",
    modulus: p * q,
    lambda: ((p - 1n) * (q - 1n)) / gcd(p - 1n, q - 1n),
  };
  const pressure = new MemoryPressureStore();
  const audit = new MemoryAuditStore();
  const service = new SharService({
    signing: {
      keyId: new Uint8Array([9, 9, 9, 1]),
      privateSeed: new Uint8Array(32).fill(7),
    },
    timeLock,
    nonces: new MemoryNonceStore(),
    pressure,
    config: new StaticConfigStore(policy),
    audit,
    clock: { now: () => now },
    random,
    renderTriangles: 8,
    renderSamples: 16,
    ...overrides,
  });
  return {
    service,
    pressure,
    audit,
    setNow(value) {
      now = value;
    },
  };
}

test("liveness remains available while readiness reflects required stores", async () => {
  const healthy = createSharHandler(fixture().service);
  const live = await healthy(new Request("https://shar.example/healthz"));
  assert.equal(live.status, 200);
  assert.equal(live.headers.get("cache-control"), "no-store");
  assert.deepEqual(await live.json(), { status: "ok" });

  const ready = await healthy(new Request("https://shar.example/readyz"));
  assert.equal(ready.status, 200);
  assert.equal(ready.headers.get("cache-control"), "no-store");
  assert.deepEqual(await ready.json(), { status: "ready" });

  const wrongMethod = await healthy(
    new Request("https://shar.example/readyz", { method: "POST" }),
  );
  assert.equal(wrongMethod.status, 405);
  assert.equal((await wrongMethod.json()).code, "method_not_allowed");

  const unavailable = createSharHandler(
    fixture({
      config: {
        policy: async () => policy,
        health: async () => {
          throw new Error("database unavailable");
        },
      },
    }).service,
  );
  assert.equal(
    (await unavailable(new Request("https://shar.example/healthz"))).status,
    200,
  );
  const notReady = await unavailable(
    new Request("https://shar.example/readyz"),
  );
  assert.equal(notReady.status, 503);
  assert.equal(notReady.headers.get("retry-after"), "1");
  assert.deepEqual(await notReady.json(), {
    code: "readiness_unavailable",
    retryable: true,
    next_action: "retry",
    retry_after: 1,
  });
});

test("Fetch handler emits privacy-safe request observations without affecting responses", async () => {
  const observations = [];
  const handler = createSharHandler(fixture().service, {
    observeRequest: (observation) => observations.push(observation),
  });
  const response = await handler(
    new Request("https://shar.example/healthz?tenant=must-not-appear"),
  );
  assert.equal(response.status, 200);
  assert.match(
    response.headers.get("x-shar-request-id"),
    /^[A-Za-z0-9_-]{22}$/,
  );
  assert.deepEqual(observations, [
    {
      version: "request-observation-v1",
      request_id: response.headers.get("x-shar-request-id"),
      method: "GET",
      route: "/healthz",
      status: 200,
      duration_ms: observations[0].duration_ms,
    },
  ]);
  assert.ok(Number.isSafeInteger(observations[0].duration_ms));
  assert.ok(observations[0].duration_ms >= 0);
  assert.equal(JSON.stringify(observations).includes("tenant"), false);

  const failingObserver = createSharHandler(fixture().service, {
    observeRequest: () => {
      throw new Error("telemetry unavailable");
    },
  });
  assert.equal(
    (await failingObserver(new Request("https://shar.example/healthz"))).status,
    200,
  );

  const cryptoDescriptor = Object.getOwnPropertyDescriptor(
    globalThis,
    "crypto",
  );
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: undefined,
  });
  try {
    const entropyUnavailable = await createSharHandler(fixture().service)(
      new Request("https://shar.example/healthz"),
    );
    assert.equal(entropyUnavailable.status, 200);
    assert.match(
      entropyUnavailable.headers.get("x-shar-request-id"),
      /^[A-Za-z0-9_-]{22}$/,
    );
  } finally {
    if (cryptoDescriptor)
      Object.defineProperty(globalThis, "crypto", cryptoDescriptor);
    else Reflect.deleteProperty(globalThis, "crypto");
  }
});

test("Fetch handler returns retryable operational backpressure and recovers", async () => {
  let release;
  let entered;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const started = new Promise((resolve) => {
    entered = resolve;
  });
  const handler = createSharHandler(fixture().service, {
    allowedOrigins: ["https://app.example"],
    maxConcurrentRequests: 1,
    networkPseudonym: async () => {
      entered();
      await held;
      return undefined;
    },
  });
  const challengeRequestMessage = () =>
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: {
        origin: "https://app.example",
        "content-type": "application/json",
      },
      body: JSON.stringify(challengeRequest),
    });
  const first = handler(challengeRequestMessage());
  await started;

  const overloaded = await handler(challengeRequestMessage());
  assert.equal(overloaded.status, 503);
  assert.equal(overloaded.headers.get("retry-after"), "1");
  assert.equal(
    overloaded.headers.get("access-control-allow-origin"),
    "https://app.example",
  );
  assert.deepEqual(await overloaded.json(), {
    code: "capacity_unavailable",
    retryable: true,
    next_action: "retry",
    retry_after: 1,
  });
  assert.equal(
    (await handler(new Request("https://shar.example/healthz"))).status,
    200,
  );

  release();
  assert.equal((await first).status, 200);
  assert.equal((await handler(challengeRequestMessage())).status, 200);
  assert.throws(
    () => createSharHandler(fixture().service, { maxConcurrentRequests: 0 }),
    /invalid_concurrency_limit/,
  );
});

const challengeRequest = {
  tenant: "tenant-a",
  site_key: "site-a",
  action: "signup",
  origin: "https://app.example",
};

test("an issued correct proof is honored after pressure increases", async () => {
  const { service, pressure } = fixture();
  const challenge = await service.challenge(challengeRequest);
  assert.equal(challenge.quote.tier, 0);
  pressure.set(challengeRequest, {
    baseTier: 32,
    velocityTier: 32,
    outstandingTier: 32,
    networkTier: 32,
    failureDebt: 32,
    assuranceDebt: 32,
    trustCredits: 0,
  });
  const proof = {
    token: challenge.token,
    time_lock: solveTimeLock(challenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(challenge.render),
    },
  };
  const redeemed = await service.redeem(proof);
  assert.equal(redeemed.receipt.tier, 0);
  assert.equal(redeemed.receipt.time_lock_iterations, "16");
  const verified = await service.siteverify({
    token: redeemed.token,
    action: "signup",
    origin: "https://app.example",
  });
  assert.equal(verified.success, true);
  await assert.rejects(
    () => service.siteverify({ token: redeemed.token }),
    (e) => e.code === "replayed_verification",
  );
});

test("default quotes contain one bounded million-predicate rendering round", async () => {
  assert.equal(DEFAULT_RENDER_TRIANGLES, 256);
  assert.equal(DEFAULT_RENDER_SAMPLES, 4096);
  assert.equal(DEFAULT_RENDER_PREDICATES, 1_048_576);
  const { service } = fixture({
    renderTriangles: undefined,
    renderSamples: undefined,
  });
  const challenge = await service.challenge(challengeRequest);
  assert.equal(challenge.render.triangles, DEFAULT_RENDER_TRIANGLES);
  assert.equal(challenge.render.samples, DEFAULT_RENDER_SAMPLES);
});

test("challenge responses advertise validated host presence and fallback plans", async () => {
  const defaultService = fixture().service;
  const defaults = await defaultService.challenge(challengeRequest);
  assert.deepEqual(defaults.presence, { mode: "none" });
  assert.deepEqual(defaults.fallback, { available: false, methods: [] });
  await assert.rejects(
    defaultService.completeFallback({
      ...challengeRequest,
      method: "passkey",
      assertion_id: "host-assertion-disabled-0001",
    }),
    (error) =>
      error.status === 501 &&
      error.code === "fallback_not_configured" &&
      error.retryable === false &&
      error.next_action === "fallback",
  );

  const configured = fixture({
    presence: { mode: "host" },
    fallback: { available: true, methods: ["passkey", "email"] },
  });
  const direct = await configured.service.challenge(challengeRequest);
  assert.deepEqual(direct.presence, { mode: "host" });
  assert.deepEqual(direct.fallback, {
    available: true,
    methods: ["passkey", "email"],
  });

  assert.throws(
    () => fixture({ fallback: { available: true, methods: [] } }),
    /fallback_plan/,
  );
  assert.throws(
    () =>
      fixture({
        fallback: { available: true, methods: ["email", "email"] },
      }),
    /fallback_plan/,
  );

  const secret = new Uint8Array(32).fill(11);
  const handlerService = fixture({
    presence: { mode: "host" },
    fallback: { available: true, methods: ["passkey", "support"] },
  }).service;
  const handler = createSharHandler(handlerService, {
    allowedOrigins: [challengeRequest.origin],
    fallbackSecret: secret,
    fallbackMethods: ["passkey", "support"],
    presence: { mode: "host" },
  });
  const response = await handler(
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: {
        origin: challengeRequest.origin,
        "content-type": "application/json",
      },
      body: JSON.stringify(challengeRequest),
    }),
  );
  assert.equal(response.status, 200);
  const advertised = await response.json();
  assert.deepEqual(advertised.presence, { mode: "host" });
  assert.deepEqual(advertised.fallback, {
    available: true,
    methods: ["passkey", "support"],
  });
  assert.throws(
    () =>
      createSharHandler(fixture().service, {
        fallbackMethods: ["email"],
      }),
    /fallback_methods_without_secret/,
  );
  assert.throws(
    () =>
      createSharHandler(fixture().service, {
        fallbackSecret: secret,
        fallbackMethods: ["bad method"],
      }),
    /invalid_fallback_methods/,
  );
  assert.throws(
    () =>
      createSharHandler(fixture().service, {
        fallbackSecret: secret,
      }),
    /handler_browser_plan_mismatch/,
  );
});

test("redeem rejects an unavailable clock before classifying proof work", async () => {
  const fixtureState = fixture();
  const challenge = await fixtureState.service.challenge(challengeRequest);
  fixtureState.setNow(-1);
  await assert.rejects(
    () =>
      fixtureState.service.redeem({
        token: challenge.token,
        time_lock: { output: "invalid" },
        rendering: { backend: "css", digest: "invalid" },
      }),
    (error) =>
      error?.code === "clock_unavailable" &&
      error?.status === 503 &&
      error?.retryable === true,
  );
});

test("optional region binding survives redemption and final verification", async () => {
  const { service } = fixture();
  const challenge = await service.challenge({
    ...challengeRequest,
    region: "au-mel-1",
  });
  assert.equal(challenge.region, "au-mel-1");
  const redeemed = await service.redeem({
    token: challenge.token,
    time_lock: solveTimeLock(challenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(challenge.render),
    },
  });
  const verified = await service.siteverify({
    token: redeemed.token,
    region: "au-mel-1",
  });
  assert.equal(verified.region, "au-mel-1");
});

test("concurrent redemption has exactly one winner and replays can get new work", async () => {
  const { service } = fixture();
  const challenge = await service.challenge(challengeRequest);
  const request = {
    token: challenge.token,
    time_lock: solveTimeLock(challenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(challenge.render),
    },
  };
  const outcomes = await Promise.allSettled(
    Array.from({ length: 8 }, () => service.redeem(request)),
  );
  assert.equal(outcomes.filter((x) => x.status === "fulfilled").length, 1);
  assert.equal(
    outcomes.filter(
      (x) => x.status === "rejected" && x.reason.code === "replayed_challenge",
    ).length,
    7,
  );
  assert.ok(
    (await service.challenge(challengeRequest)).token.startsWith("shr1_"),
  );
});

test("expiry and invalid work fail without creating a permanent policy rejection", async () => {
  const f = fixture();
  const challenge = await f.service.challenge(challengeRequest);
  const invalid = {
    token: challenge.token,
    time_lock: { output: "AA" },
    rendering: {
      backend: "webgpu",
      digest: await solveRendering(challenge.render),
    },
  };
  await assert.rejects(
    () => f.service.redeem(invalid),
    (e) => e.code === "invalid_work" && e.next_action === "new_challenge",
  );
  assert.ok((await f.service.challenge(challengeRequest)).token);
  const commitmentFixture = fixture();
  const commitmentChallenge =
    await commitmentFixture.service.challenge(challengeRequest);
  const commitmentProof = {
    token: commitmentChallenge.token,
    time_lock: solveTimeLock(commitmentChallenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(commitmentChallenge.render),
      css_commitment: {
        version: "css-transcript-v1",
        digest: "malformed",
      },
    },
  };
  await assert.rejects(
    () => commitmentFixture.service.redeem(commitmentProof),
    (error) => error.code === "invalid_work",
  );
  commitmentProof.rendering.css_commitment = null;
  await assert.rejects(
    () => commitmentFixture.service.redeem(commitmentProof),
    (error) => error.code === "invalid_work",
  );
  commitmentProof.rendering.css_commitment = {
    version: "css-transcript-v1",
    digest: base64url(new Uint8Array(32)),
  };
  await assert.rejects(
    () => commitmentFixture.service.redeem(commitmentProof),
    (error) => error.code === "invalid_work",
  );
  commitmentProof.rendering.css_commitment = {
    version: "css-transcript-v1",
    digest: await cssTranscriptCommitment(commitmentChallenge.render),
  };
  assert.equal(
    (await commitmentFixture.service.redeem(commitmentProof)).receipt
      .rendering_backend,
    "css",
  );
  const boundary = fixture();
  const boundaryChallenge = await boundary.service.challenge(challengeRequest);
  boundary.setNow(boundaryChallenge.quote.expires_at);
  await boundary.service.redeem({
    token: boundaryChallenge.token,
    time_lock: solveTimeLock(boundaryChallenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(boundaryChallenge.render),
    },
  });
  f.setNow(challenge.quote.expires_at + 1);
  const correct = {
    token: challenge.token,
    time_lock: solveTimeLock(challenge.time_lock),
    rendering: {
      backend: "webgl2",
      digest: await solveRendering(challenge.render),
    },
  };
  await assert.rejects(
    () => f.service.redeem(correct),
    (e) => e.code === "expired_challenge",
  );
});

test("Fetch handler enforces browser Origin and body bounds", async () => {
  const { service } = fixture();
  assert.throws(
    () => createSharHandler(service, { maxBodyBytes: 0 }),
    /invalid_body_limit/,
  );
  const verifierMaster = new Uint8Array(32).fill(14);
  const unconfigured = createSharHandler(service);
  const unconfiguredResponse = await unconfigured(
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example",
      },
      body: JSON.stringify(challengeRequest),
    }),
  );
  assert.equal(unconfiguredResponse.status, 400);
  assert.equal(
    (await unconfiguredResponse.json()).code,
    "origin_not_configured",
  );
  const handler = createSharHandler(service, {
    allowedOrigins: ["https://app.example"],
    maxBodyBytes: 2048,
    siteVerifyMasterSecret: verifierMaster,
  });
  const missing = await handler(
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(challengeRequest),
    }),
  );
  assert.equal(missing.status, 400);
  assert.equal((await missing.json()).code, "origin_required");
  const good = await handler(
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example",
      },
      body: JSON.stringify(challengeRequest),
    }),
  );
  assert.equal(good.status, 200);
  assert.equal(good.headers.get("cache-control"), "no-store");
  assert.equal(good.headers.get("x-content-type-options"), "nosniff");
  assert.equal(
    good.headers.get("access-control-allow-origin"),
    "https://app.example",
  );
  const issued = await good.json();
  const malformedCommitment = await handler(
    new Request("https://shar.example/v1/challenges/redeem", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example",
      },
      body: JSON.stringify({
        token: issued.token,
        time_lock: { output: "AA" },
        rendering: {
          backend: "css",
          digest: "AA",
          css_commitment: null,
        },
      }),
    }),
  );
  assert.equal(malformedCommitment.status, 400);
  assert.equal((await malformedCommitment.json()).code, "malformed_json");
  const redeemedResponse = await handler(
    new Request("https://shar.example/v1/challenges/redeem", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example",
      },
      body: JSON.stringify({
        token: issued.token,
        time_lock: solveTimeLock(issued.time_lock),
        rendering: {
          backend: "css",
          digest: await solveRendering(issued.render),
        },
      }),
    }),
  );
  assert.equal(redeemedResponse.status, 200);
  assert.equal(
    redeemedResponse.headers.get("access-control-allow-origin"),
    "https://app.example",
  );
  const redeemed = await redeemedResponse.json();
  const siteSecret = await deriveSiteVerifySecret(
    verifierMaster,
    "tenant-a",
    "site-a",
  );
  const unauthorized = await handler(
    new Request("https://shar.example/v1/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        "g-recaptcha-response": redeemed.token,
        secret: "wrong",
      }),
    }),
  );
  assert.equal(unauthorized.status, 401);
  assert.equal((await unauthorized.json()).code, "siteverify_unauthorized");
  const compatible = await handler(
    new Request("https://shar.example/v1/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        "g-recaptcha-response": redeemed.token,
        secret: siteSecret,
      }),
    }),
  );
  const compatibilityBody = await compatible.json();
  assert.equal(compatibilityBody.success, true);
  assert.equal(compatibilityBody.score, 1);
  const huge = await handler(
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: {
        origin: "https://app.example",
        "content-type": "application/json",
      },
      body: "x".repeat(3000),
    }),
  );
  assert.equal(huge.status, 413);
  assert.equal(huge.headers.get("cache-control"), "no-store");
  assert.equal(huge.headers.get("x-content-type-options"), "nosniff");
  assert.equal(
    huge.headers.get("access-control-allow-origin"),
    "https://app.example",
  );
  const streamedHuge = await handler(
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: {
        origin: "https://app.example",
        "content-type": "application/json",
      },
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(2048));
          controller.enqueue(new Uint8Array(1));
          controller.close();
        },
      }),
      duplex: "half",
    }),
  );
  assert.equal(streamedHuge.status, 413);
  assert.equal(streamedHuge.headers.get("cache-control"), "no-store");
  assert.equal(streamedHuge.headers.get("x-content-type-options"), "nosniff");
  const preflight = await handler(
    new Request("https://shar.example/v1/challenges", {
      method: "OPTIONS",
      headers: {
        origin: "https://app.example",
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type",
      },
    }),
  );
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get("cache-control"), "no-store");
  assert.equal(preflight.headers.get("x-content-type-options"), "nosniff");
  assert.equal(
    preflight.headers.get("access-control-allow-origin"),
    "https://app.example",
  );
  const method = await handler(
    new Request("https://shar.example/v1/challenges", { method: "PUT" }),
  );
  assert.equal(method.status, 405);
  assert.equal((await method.json()).code, "method_not_allowed");
  const media = await handler(
    new Request("https://shar.example/v1/siteverify", {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "token=x",
    }),
  );
  assert.equal(media.status, 415);
  assert.equal((await media.json()).code, "unsupported_media_type");
});

test("Fetch handler allowlists match canonical standalone origin vectors", () => {
  assert.equal(allowedOriginVectors.version, "allowed-origin-v1");
  for (const vector of allowedOriginVectors.vectors) {
    const options = {
      allowedOrigins: vector.valid ? vector.origins : vector.input.split(","),
    };
    if (vector.valid)
      assert.equal(
        typeof createSharHandler(fixture().service, options),
        "function",
      );
    else
      assert.throws(
        () => createSharHandler(fixture().service, options),
        /invalid_allowed_origins/,
        vector.name,
      );
  }
  assert.equal(typeof createSharHandler(fixture().service), "function");
});

test("browser-supplied pricing signals are replaced by trusted handler signals", async () => {
  const { service } = fixture();
  const handler = createSharHandler(service, {
    allowedOrigins: ["https://app.example"],
    assuranceTier: () => 2,
    networkPseudonym: () => "trusted-daily-network",
  });
  const response = await handler(
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: {
        origin: "https://app.example",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        ...challengeRequest,
        assurance_tier: 32,
        network_pseudonym: "attacker-selected",
        session_binding: "attacker-selected",
      }),
    }),
  );
  assert.equal(response.status, 200);
  const issued = await response.json();
  assert.equal(issued.quote.tier, 2);
  const claims = decodeCbor(
    await coseVerify(issued.token, [
      {
        keyId: new Uint8Array([9, 9, 9, 1]),
        publicKey: await publicFromSeed(new Uint8Array(32).fill(7)),
      },
    ]),
  );
  assert.equal(claims.has(15), false);

  const trustedHandler = createSharHandler(service, {
    allowedOrigins: ["https://app.example"],
    sessionBinding: () => "trusted-session",
  });
  const trustedResponse = await trustedHandler(
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: {
        origin: "https://app.example",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        ...challengeRequest,
        session_binding: "attacker-selected",
      }),
    }),
  );
  assert.equal(trustedResponse.status, 200);
  const trustedClaims = decodeCbor(
    await coseVerify((await trustedResponse.json()).token, [
      {
        keyId: new Uint8Array([9, 9, 9, 1]),
        publicKey: await publicFromSeed(new Uint8Array(32).fill(7)),
      },
    ]),
  );
  assert.equal(trustedClaims.get(15), "trusted-session");
});

test("admin policy API is opt-in, authenticated, validated, and changes new quotes", async () => {
  const { service } = fixture();
  const secret = new Uint8Array(32).fill(12);
  const disabled = createSharHandler(service);
  const query = "?tenant=tenant-a&site_key=site-a&action=signup";
  const hidden = await disabled(
    new Request(`https://shar.example/v1/admin/policy${query}`),
  );
  assert.equal(hidden.status, 404);

  const handler = createSharHandler(service, { adminSecret: secret });
  const unauthorized = await handler(
    new Request(`https://shar.example/v1/admin/policy${query}`),
  );
  assert.equal(unauthorized.status, 401);
  assert.equal((await unauthorized.json()).code, "admin_unauthorized");
  const authorization = `Bearer ${base64url(secret)}`;
  const read = await handler(
    new Request(`https://shar.example/v1/admin/policy${query}`, {
      headers: { authorization },
    }),
  );
  assert.equal(read.status, 200);
  const document = await read.json();
  assert.equal(document.policy.base_iterations, "16");

  const updated = structuredClone(document);
  updated.policy.version = "policy-admin-v2";
  updated.policy.base_iterations = "32";
  const write = await handler(
    new Request("https://shar.example/v1/admin/policy", {
      method: "PUT",
      headers: { authorization, "content-type": "application/json" },
      body: JSON.stringify(updated),
    }),
  );
  assert.equal(write.status, 200);
  assert.equal((await write.json()).policy.base_iterations, "32");
  assert.equal(
    (await service.challenge(challengeRequest)).quote.time_lock_iterations,
    "32",
  );

  updated.policy.base_iterations = (1n << 63n).toString();
  const invalid = await handler(
    new Request("https://shar.example/v1/admin/policy", {
      method: "PUT",
      headers: { authorization, "content-type": "application/json" },
      body: JSON.stringify(updated),
    }),
  );
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).code, "invalid_policy");
});

test("scoped admin audit API is authenticated, bounded, and privacy-filtered", async () => {
  const { service, audit } = fixture();
  await audit.record({
    version: "audit-v1",
    kind: "proof_redeemed",
    occurred_at: 1_800_000_000,
    tenant: "tenant-a",
    site_key: "site-a",
    action: "signup",
    tier: 2,
    backend: "css",
  });
  await audit.record({
    version: "audit-v1",
    kind: "site_verified",
    occurred_at: 1_800_000_001,
    tenant: "other-tenant",
    site_key: "site-a",
    action: "signup",
  });
  const secret = new Uint8Array(32).fill(12);
  const handler = createSharHandler(service, { adminSecret: secret });
  const query = "?tenant=tenant-a&site_key=site-a&action=signup&limit=1";
  const unauthorized = await handler(
    new Request(`https://shar.example/v1/admin/audit${query}`),
  );
  assert.equal(unauthorized.status, 401);
  const response = await handler(
    new Request(`https://shar.example/v1/admin/audit${query}`, {
      headers: { authorization: `Bearer ${base64url(secret)}` },
    }),
  );
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    tenant: "tenant-a",
    site_key: "site-a",
    action: "signup",
    events: [
      {
        version: "audit-v1",
        kind: "proof_redeemed",
        occurred_at: 1_800_000_000,
        tenant: "tenant-a",
        site_key: "site-a",
        action: "signup",
        tier: 2,
        backend: "css",
      },
    ],
  });
  const invalidLimit = await handler(
    new Request(
      "https://shar.example/v1/admin/audit?tenant=tenant-a&site_key=site-a&action=signup&limit=101",
      { headers: { authorization: `Bearer ${base64url(secret)}` } },
    ),
  );
  assert.equal(invalidLimit.status, 400);
  assert.equal((await invalidLimit.json()).code, "invalid_audit_limit");
  const malformedLimit = await handler(
    new Request(
      "https://shar.example/v1/admin/audit?tenant=tenant-a&site_key=site-a&action=signup&limit=slow",
      { headers: { authorization: `Bearer ${base64url(secret)}` } },
    ),
  );
  assert.equal(malformedLimit.status, 400);
  assert.equal((await malformedLimit.json()).code, "invalid_audit_limit");
});

test("pricing failures are retryable service errors with retry guidance", async () => {
  const p = 1_000_003n,
    q = 1_000_033n;
  const service = new SharService({
    signing: {
      keyId: new Uint8Array([1]),
      privateSeed: new Uint8Array(32).fill(7),
    },
    timeLock: { id: "test", modulus: p * q, lambda: 166_672_333_344n },
    nonces: new MemoryNonceStore(),
    pressure: new MemoryPressureStore(),
    config: new StaticConfigStore({ ...policy, baseIterations: 1n << 64n }),
    clock: { now: () => 100 },
    random: { bytes: (length) => new Uint8Array(length) },
  });
  const handler = createSharHandler(service, {
    allowedOrigins: ["https://app.example"],
  });
  const response = await handler(
    new Request("https://shar.example/v1/challenges", {
      method: "POST",
      headers: {
        origin: "https://app.example",
        "content-type": "application/json",
      },
      body: JSON.stringify(challengeRequest),
    }),
  );
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("retry-after"), "1");
  assert.deepEqual(await response.json(), {
    code: "pricing_unavailable",
    retryable: true,
    next_action: "retry",
    retry_after: 1,
  });
});

test("host providers price only new quotes and verify fallback before nonce use", async () => {
  let signalCalls = 0;
  let signalUnavailable = false;
  let fallbackMode = "reject";
  const originalRequest = { ...challengeRequest };
  const { service } = fixture({
    signals: {
      async health() {
        if (signalUnavailable) throw new Error("signals offline");
      },
      async assuranceTier(request) {
        signalCalls++;
        assert.notEqual(request, originalRequest);
        if (signalUnavailable) throw new Error("signals offline");
        return 7;
      },
    },
    fallback: { available: true, methods: ["passkey"] },
    fallbackVerifier: {
      async health() {
        if (fallbackMode === "unavailable") throw new Error("host offline");
      },
      async verify(method, payload) {
        assert.equal(method, "passkey");
        assert.equal(payload.assertion_id.startsWith("host-assertion-"), true);
        if (fallbackMode === "unavailable") throw new Error("host offline");
        return fallbackMode === "accept";
      },
    },
  });

  const challenge = await service.challenge(originalRequest);
  assert.equal(challenge.quote.tier, 7);
  assert.equal(originalRequest.assurance_tier, undefined);
  assert.equal(signalCalls, 1);

  // Once the quote exists, provider failure cannot affect proof validity.
  signalUnavailable = true;
  await assert.rejects(
    service.ready(),
    (error) => error.code === "readiness_unavailable",
  );
  const redeemed = await service.redeem({
    token: challenge.token,
    time_lock: solveTimeLock(challenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(challenge.render),
    },
  });
  assert.equal(redeemed.receipt.tier, 7);
  assert.equal(signalCalls, 1);
  signalUnavailable = false;
  await service.ready();

  const fallback = {
    ...challengeRequest,
    method: "passkey",
    assertion_id: "host-assertion-provider-0001",
  };
  await assert.rejects(
    service.completeFallback(fallback),
    (error) =>
      error.code === "fallback_not_verified" &&
      error.next_action === "fallback" &&
      error.retryable === false,
  );
  fallbackMode = "accept";
  assert.equal((await service.completeFallback(fallback)).success, true);
  await assert.rejects(
    service.completeFallback(fallback),
    (error) => error.code === "replayed_fallback_assertion",
  );

  fallbackMode = "unavailable";
  await assert.rejects(
    service.ready(),
    (error) => error.code === "readiness_unavailable",
  );
  const retryable = {
    ...fallback,
    assertion_id: "host-assertion-provider-0002",
  };
  await assert.rejects(
    service.completeFallback(retryable),
    (error) =>
      error.code === "fallback_unavailable" &&
      error.retryable === true &&
      error.retry_after === 1,
  );
  fallbackMode = "accept";
  assert.equal((await service.completeFallback(retryable)).success, true);
  await service.ready();
});

test("stored fallback assertions enforce exact bindings, lifetime, and idempotent lookup", async () => {
  assert.equal(
    fallbackAssertionVectors.schema,
    "shar-fallback-assertion-vectors-v1",
  );
  for (const vector of fallbackAssertionVectors.vectors) {
    let healthCalls = 0;
    let findCalls = 0;
    const verifier = new StoredFallbackVerifier(
      {
        async health() {
          healthCalls++;
        },
        async find(assertionId) {
          findCalls++;
          assert.equal(
            assertionId,
            fallbackAssertionVectors.request.assertion_id,
          );
          if (vector.missing) return undefined;
          return {
            ...fallbackAssertionVectors.assertion,
            ...vector.overrides,
          };
        },
      },
      { now: () => fallbackAssertionVectors.now },
    );
    await verifier.health();
    assert.equal(healthCalls, 1, vector.name);
    if (vector.result === "unavailable") {
      await assert.rejects(
        verifier.verify(
          fallbackAssertionVectors.request.method,
          fallbackAssertionVectors.request,
        ),
        /fallback_assertion/,
        vector.name,
      );
    } else {
      assert.equal(
        await verifier.verify(
          fallbackAssertionVectors.request.method,
          fallbackAssertionVectors.request,
        ),
        vector.result === "accepted",
        vector.name,
      );
    }
    assert.equal(findCalls, 1, vector.name);
  }

  const brokenClock = new StoredFallbackVerifier(
    {
      async find() {
        return fallbackAssertionVectors.assertion;
      },
    },
    { now: () => -1 },
  );
  await assert.rejects(
    brokenClock.verify(
      fallbackAssertionVectors.request.method,
      fallbackAssertionVectors.request,
    ),
    /clock/,
  );
});

test("stored fallback verifier integrates with retry and replay semantics", async () => {
  let record = { ...fallbackAssertionVectors.assertion };
  let unavailable = false;
  const verifier = new StoredFallbackVerifier(
    {
      async health() {
        if (unavailable) throw new Error("offline");
      },
      async find() {
        if (unavailable) throw new Error("offline");
        return { ...record };
      },
    },
    { now: () => fallbackAssertionVectors.now },
  );
  const service = fixture({
    fallback: {
      available: true,
      methods: [fallbackAssertionVectors.request.method],
    },
    fallbackVerifier: verifier,
  }).service;
  assert.equal(
    (await service.completeFallback(fallbackAssertionVectors.request)).success,
    true,
  );
  await assert.rejects(
    service.completeFallback(fallbackAssertionVectors.request),
    (error) => error.code === "replayed_fallback_assertion",
  );

  const retry = {
    ...fallbackAssertionVectors.request,
    assertion_id: "host-assertion-stored-0002",
  };
  record = { ...record, assertion_id: retry.assertion_id };
  unavailable = true;
  await assert.rejects(
    service.ready(),
    (error) => error.code === "readiness_unavailable",
  );
  await assert.rejects(
    service.completeFallback(retry),
    (error) => error.code === "fallback_unavailable" && error.retryable,
  );
  unavailable = false;
  await service.ready();
  assert.equal((await service.completeFallback(retry)).success, true);

  const wrongBinding = {
    ...retry,
    assertion_id: "host-assertion-stored-0003",
    action: "other-action",
  };
  record = { ...record, assertion_id: wrongBinding.assertion_id };
  await assert.rejects(
    service.completeFallback(wrongBinding),
    (error) => error.code === "fallback_not_verified",
  );
});

test("host provider behavior matches language-neutral vectors", async () => {
  assert.equal(hostProviderVectors.schema, "shar-host-provider-vectors-v1");
  for (const vector of hostProviderVectors.signals) {
    let pricingCalls = 0;
    const pressure = new MemoryPressureStore();
    const original = pressure.priceAndRecord.bind(pressure);
    pressure.priceAndRecord = async (...arguments_) => {
      pricingCalls++;
      return original(...arguments_);
    };
    const service = fixture({
      pressure,
      signals: {
        assuranceTier: async () => {
          if (vector.provider.outcome === "unavailable")
            throw new Error("offline");
          return vector.provider.tier;
        },
      },
    }).service;
    const request = { ...challengeRequest };
    if (vector.request_assurance_tier !== null)
      request.assurance_tier = vector.request_assurance_tier;
    if (vector.result.outcome === "quote") {
      assert.equal(
        (await service.challenge(request)).quote.tier,
        vector.result.tier,
      );
      assert.equal(pricingCalls, 1, vector.name);
    } else {
      await assert.rejects(
        service.challenge(request),
        (error) =>
          error.code === vector.result.code &&
          error.retryable === vector.result.retryable &&
          error.next_action === vector.result.next_action &&
          error.retry_after === vector.result.retry_after,
        vector.name,
      );
      assert.equal(pricingCalls, vector.result.pricing_mutations, vector.name);
    }
  }

  for (const vector of hostProviderVectors.fallback) {
    let outcome = vector.provider.outcome;
    const service = fixture({
      fallback: { available: true, methods: ["passkey"] },
      fallbackVerifier: {
        async verify() {
          if (outcome === "unavailable") throw new Error("offline");
          return outcome === "accepted";
        },
      },
    }).service;
    const request = {
      ...challengeRequest,
      method: "passkey",
      assertion_id: `host-assertion-vector-${vector.name}`,
    };
    if (vector.result.outcome === "success") {
      assert.equal((await service.completeFallback(request)).success, true);
      await assert.rejects(
        service.completeFallback(request),
        (error) => error.code === "replayed_fallback_assertion",
        vector.name,
      );
    } else {
      await assert.rejects(
        service.completeFallback(request),
        (error) =>
          error.code === vector.result.code &&
          error.retryable === vector.result.retryable &&
          error.next_action === vector.result.next_action &&
          error.retry_after === vector.result.retry_after,
        vector.name,
      );
      // A rejected or unavailable verifier must not consume the assertion.
      outcome = "accepted";
      assert.equal((await service.completeFallback(request)).success, true);
    }
  }
});

test("privileged host fallback is bound, authenticated, and replay safe", async () => {
  const { service } = fixture({
    fallback: { available: true, methods: ["passkey"] },
  });
  const secret = new Uint8Array(32).fill(11);
  const handler = createSharHandler(service, {
    fallbackSecret: secret,
    fallbackMethods: ["passkey"],
  });
  const body = {
    ...challengeRequest,
    method: "passkey",
    assertion_id: "host-assertion-0001",
  };
  const unauthorized = await handler(
    new Request("https://shar.example/v1/fallback/complete", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
  assert.equal(unauthorized.status, 401);
  assert.equal((await unauthorized.json()).code, "fallback_unauthorized");
  const unsupported = await handler(
    new Request("https://shar.example/v1/fallback/complete", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${base64url(secret)}`,
      },
      body: JSON.stringify({
        ...body,
        method: "sms",
        assertion_id: "host-assertion-unsupported",
      }),
    }),
  );
  assert.equal(unsupported.status, 400);
  assert.equal((await unsupported.json()).code, "invalid_fallback_method");
  const request = () =>
    new Request("https://shar.example/v1/fallback/complete", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${base64url(secret)}`,
      },
      body: JSON.stringify(body),
    });
  const completed = await handler(request());
  assert.equal(completed.status, 200);
  assert.deepEqual(await completed.json(), {
    success: true,
    tenant: "tenant-a",
    site_key: "site-a",
    action: "signup",
    origin: "https://app.example",
    verification_method: "fallback",
    method: "passkey",
  });
  const replay = await handler(request());
  assert.equal(replay.status, 409);
  assert.equal((await replay.json()).code, "replayed_fallback_assertion");
  const metrics = await handler(new Request("https://shar.example/metrics"));
  assert.match(await metrics.text(), /shar_fallback_completions_total 1\n/);
});
