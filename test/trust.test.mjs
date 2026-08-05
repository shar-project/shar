import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  base64url,
  blindTrustInput,
  deriveTrustKeyPair,
  deriveScopedTrustKeyPair,
  decodeTrustCreditToken,
  deterministicTrustRandom,
  equalTrustOutput,
  evaluateTrustDirect,
  evaluateTrustInput,
  finalizeTrustInput,
  fromBase64url,
  MemoryNonceStore,
  MemoryPressureStore,
  SharService,
  StaticConfigStore,
  solveRendering,
  solveTimeLock,
  encodeTrustCreditToken,
  trustInputForScope,
  trustInput,
  trustCreditChallengeDigest,
  trustCreditLifetime,
  trustCreditReplayId,
} from "../dist/packages/server/src/index.js";

const vector = JSON.parse(
  await readFile(
    new URL("../protocol/trust-voprf-vectors.json", import.meta.url),
  ),
);

function bytes(value) {
  return fromBase64url(value);
}

function fixed(byte) {
  return (length = 32) => new Uint8Array(length).fill(byte);
}

test("trust proof randomness is deterministic without relying on global crypto", () => {
  const seed = new Uint8Array(32).fill(7);
  const left = deterministicTrustRandom(seed);
  const right = deterministicTrustRandom(seed);
  const first = left(64);
  assert.deepEqual(first, right(64));
  const second = left(64);
  assert.notDeepEqual(first, second);
  assert.deepEqual(second, right(64));
  assert.equal(left(48).length, 48);
});

test("RFC 9497 trust-credit transcript matches the shared vector", () => {
  const seed = bytes(vector.seed);
  const keyId = bytes(vector.key_id);
  const input = bytes(vector.input);
  const key = deriveTrustKeyPair(seed, keyId);
  assert.equal(base64url(key.secretKey), vector.secret_key);
  assert.equal(base64url(key.publicKey), vector.public_key);
  assert.equal(
    base64url(
      deriveScopedTrustKeyPair(key, {
        tenant: "tenant-a",
        siteKey: "site-a",
        action: "signup",
        origin: "https://app.example",
      }).publicKey,
    ),
    vector.scoped_public_key,
  );

  const blind = blindTrustInput(input, fixed(9));
  assert.equal(base64url(blind.blind), vector.blind);
  assert.equal(base64url(blind.blinded), vector.blinded);

  const evaluation = evaluateTrustInput(key, blind.blinded, fixed(11));
  assert.equal(base64url(evaluation.evaluated), vector.evaluated);
  assert.equal(base64url(evaluation.proof), vector.proof);

  const output = finalizeTrustInput(input, blind, evaluation, key.publicKey);
  assert.equal(base64url(output), vector.output);
  assert.equal(base64url(evaluateTrustDirect(key, input)), vector.output);
  assert.equal(equalTrustOutput(output, bytes(vector.output)), true);

  assert.equal(
    base64url(
      trustInput(
        "credit",
        new Uint8Array(32).fill(0x21),
        new Uint8Array(32).fill(0x42),
        keyId,
      ),
    ),
    vector.trust_input,
  );
  assert.equal(
    base64url(
      trustInputForScope(
        "credit",
        bytes(vector.seed),
        new Uint8Array(32).fill(0x42),
        keyId,
        {
          tenant: "tenant-a",
          siteKey: "site-a",
          action: "signup",
          origin: "https://app.example",
        },
      ),
    ),
    vector.scoped_trust_input,
  );
  const scope = {
    tenant: "tenant-a",
    siteKey: "site-a",
    action: "signup",
    origin: "https://app.example",
  };
  assert.equal(
    base64url(
      trustCreditChallengeDigest(keyId, scope, 1_800_000_000, 1_800_086_400),
    ),
    vector.credit_challenge_digest,
  );
  assert.equal(
    base64url(trustCreditReplayId(keyId, new Uint8Array(64).fill(0x55))),
    vector.credit_replay_id,
  );
  assert.deepEqual(trustCreditLifetime(1_800_001_234, 86_400), {
    issuedAt: 1_800_000_000,
    expiresAt: 1_800_086_400,
  });
});

test("trust-credit transcript rejects altered proof and bounded fields", () => {
  const key = deriveTrustKeyPair(bytes(vector.seed), bytes(vector.key_id));
  const input = bytes(vector.input);
  const blind = blindTrustInput(input, fixed(9));
  const evaluation = evaluateTrustInput(key, blind.blinded, fixed(11));
  const altered = evaluation.proof.slice();
  altered[0] ^= 1;
  assert.throws(
    () =>
      finalizeTrustInput(
        input,
        blind,
        { evaluated: evaluation.evaluated, proof: altered },
        key.publicKey,
      ),
    /proof verification failed|trust_/i,
  );
  assert.throws(
    () => deriveTrustKeyPair(new Uint8Array(31), bytes(vector.key_id)),
    /trust_seed_length/,
  );
  assert.throws(
    () =>
      trustInput(
        "",
        new Uint8Array(32),
        new Uint8Array(32),
        bytes(vector.key_id),
      ),
    /trust_token_type_length/,
  );
});

test("opt-in trust credits are scoped, single-use, and retained only briefly", async () => {
  const p = 1_000_003n;
  const q = 1_000_033n;
  const gcd = (a, b) => {
    while (b) [a, b] = [b, a % b];
    return a;
  };
  let counter = 0;
  const random = {
    bytes(length) {
      return new Uint8Array(length).fill(counter++);
    },
  };
  const request = {
    tenant: "tenant-a",
    site_key: "site-a",
    action: "signup",
    origin: "https://app.example",
  };
  const issuer = deriveTrustKeyPair(
    new Uint8Array(32).fill(17),
    new Uint8Array([7, 7, 7, 1]),
  );
  const service = new SharService({
    signing: {
      keyId: new Uint8Array([9]),
      privateSeed: new Uint8Array(32).fill(8),
    },
    timeLock: {
      id: "trust-rsw",
      modulus: p * q,
      lambda: ((p - 1n) * (q - 1n)) / gcd(p - 1n, q - 1n),
    },
    nonces: new MemoryNonceStore(() => 1_800_000_000),
    pressure: new MemoryPressureStore(),
    config: new StaticConfigStore({
      version: "trust-policy",
      baseIterations: 16n,
      baseRenderRounds: 1,
      quietWindowSeconds: 60,
      baseLifetimeSeconds: 120,
      iterationAllowance: 1000n,
      roundAllowanceSeconds: 1,
      maxLifetimeSeconds: 86_400,
    }),
    clock: { now: () => 1_800_000_000 },
    random,
    renderTriangles: 8,
    renderSamples: 16,
    trust: { keys: [issuer], retentionSeconds: 86_400 },
  });
  const challenge = await service.challenge(request);
  assert.equal(challenge.trust?.mode, "voprf-v1");
  if (!challenge.trust || challenge.trust.mode !== "voprf-v1")
    throw new Error("trust plan missing");
  assert.equal(challenge.trust.expires_at, 1_800_086_400);
  assert.equal(challenge.trust.issued_at, 1_800_000_000);
  assert.equal("input" in challenge.trust, false);
  assert.equal("nonce" in challenge.trust, false);
  const creditNonce = new Uint8Array(32).fill(13);
  const input = trustInputForScope(
    "credit",
    creditNonce,
    fromBase64url(challenge.trust.challenge_digest),
    fromBase64url(challenge.trust.key_id),
    {
      tenant: request.tenant,
      siteKey: request.site_key,
      action: request.action,
      origin: request.origin,
    },
  );
  const blind = blindTrustInput(input, fixed(9));
  const redeemed = await service.redeem({
    token: challenge.token,
    time_lock: solveTimeLock(challenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(challenge.render),
    },
    trust_blinded: base64url(blind.blinded),
  });
  assert.equal(redeemed.trust_evaluation?.version, "trust-evaluation-v1");
  const evaluation = redeemed.trust_evaluation;
  if (!evaluation) throw new Error("trust evaluation missing");
  assert.equal(evaluation.issued_at, challenge.trust.issued_at);
  assert.equal(evaluation.expires_at, challenge.trust.expires_at);
  const output = finalizeTrustInput(
    input,
    blind,
    {
      evaluated: fromBase64url(evaluation.evaluated),
      proof: fromBase64url(evaluation.proof),
    },
    fromBase64url(challenge.trust.public_key),
  );
  const credit = encodeTrustCreditToken({
    version: "trust-credit-v1",
    suite: "ristretto255-SHA512",
    keyId: fromBase64url(evaluation.key_id),
    challengeNonce: creditNonce,
    challengeDigest: fromBase64url(challenge.trust.challenge_digest),
    tenant: request.tenant,
    siteKey: request.site_key,
    action: request.action,
    origin: request.origin,
    issuedAt: evaluation.issued_at,
    expiresAt: evaluation.expires_at,
    output,
  });
  const followUp = await service.challenge({ ...request, trust_token: credit });
  assert.ok(followUp.token.startsWith("shr1_"));
  await assert.rejects(
    () => service.challenge({ ...request, trust_token: credit }),
    /replayed_trust_token/,
  );
  await assert.rejects(
    () =>
      service.challenge({ ...request, trust_token: credit, action: "other" }),
    /trust_binding_mismatch|replayed_trust_token/,
  );
  const rewrapped = encodeTrustCreditToken({
    ...decodeTrustCreditToken(credit),
    issuedAt: 1_800_000_001,
    expiresAt: 1_800_086_401,
  });
  await assert.rejects(
    () => service.challenge({ ...request, trust_token: rewrapped }),
    /invalid_trust_token/,
  );
  const launderingChallenge = await service.challenge(request);
  if (
    !launderingChallenge.trust ||
    launderingChallenge.trust.mode !== "voprf-v1"
  )
    throw new Error("trust plan missing");
  const otherRequest = { ...request, action: "other" };
  const otherScope = {
    tenant: otherRequest.tenant,
    siteKey: otherRequest.site_key,
    action: otherRequest.action,
    origin: otherRequest.origin,
  };
  const launderingNonce = new Uint8Array(32).fill(19);
  const launderingDigest = trustCreditChallengeDigest(
    fromBase64url(launderingChallenge.trust.key_id),
    otherScope,
    launderingChallenge.trust.issued_at,
    launderingChallenge.trust.expires_at,
  );
  const launderingInput = trustInputForScope(
    "credit",
    launderingNonce,
    launderingDigest,
    fromBase64url(launderingChallenge.trust.key_id),
    otherScope,
  );
  const launderingBlind = blindTrustInput(launderingInput, fixed(21));
  const launderingRedemption = await service.redeem({
    token: launderingChallenge.token,
    time_lock: solveTimeLock(launderingChallenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(launderingChallenge.render),
    },
    trust_blinded: base64url(launderingBlind.blinded),
  });
  const launderingEvaluation = launderingRedemption.trust_evaluation;
  if (!launderingEvaluation) throw new Error("trust evaluation missing");
  const launderingOutput = finalizeTrustInput(
    launderingInput,
    launderingBlind,
    {
      evaluated: fromBase64url(launderingEvaluation.evaluated),
      proof: fromBase64url(launderingEvaluation.proof),
    },
    fromBase64url(launderingChallenge.trust.public_key),
  );
  const laundered = encodeTrustCreditToken({
    version: "trust-credit-v1",
    suite: "ristretto255-SHA512",
    keyId: fromBase64url(launderingChallenge.trust.key_id),
    challengeNonce: launderingNonce,
    challengeDigest: launderingDigest,
    tenant: otherScope.tenant,
    siteKey: otherScope.siteKey,
    action: otherScope.action,
    origin: otherScope.origin,
    issuedAt: launderingEvaluation.issued_at,
    expiresAt: launderingEvaluation.expires_at,
    output: launderingOutput,
  });
  await assert.rejects(
    () => service.challenge({ ...otherRequest, trust_token: laundered }),
    /invalid_trust_token/,
  );
  const optional = await service.challenge(request);
  const honored = await service.redeem({
    token: optional.token,
    time_lock: solveTimeLock(optional.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(optional.render),
    },
    trust_blinded: base64url(new Uint8Array(32).fill(0xff)),
  });
  assert.ok(honored.token.startsWith("shr1_"));
  assert.equal(honored.trust_evaluation, undefined);
});
