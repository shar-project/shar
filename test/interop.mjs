import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  base64url,
  blindTrustInput,
  deriveSiteVerifySecret,
  encodeTrustCreditToken,
  finalizeTrustInput,
  fromBase64url,
  solveRendering,
  solveTimeLock,
  trustInputForScope,
} from "../dist/packages/server/src/index.js";
import { validateProtocolResponse } from "./protocol-schema.mjs";

const endpointA = process.env.SHAR_ENDPOINT_A;
const endpointB = process.env.SHAR_ENDPOINT_B;
const origin = process.env.SHAR_TEST_ORIGIN ?? "http://localhost:3000";
if (!endpointA || !endpointB) {
  throw new Error(
    "set SHAR_ENDPOINT_A and SHAR_ENDPOINT_B to servers sharing keys and nonce storage",
  );
}
let verifierMaster = process.env.SHAR_SITEVERIFY_MASTER_SECRET;
if (!verifierMaster && process.env.SHAR_KEY_FILE) {
  const keyDocument = JSON.parse(
    await readFile(process.env.SHAR_KEY_FILE, "utf8"),
  );
  verifierMaster = keyDocument.SHAR_SITEVERIFY_MASTER_SECRET;
}
if (!verifierMaster)
  throw new Error(
    "set SHAR_SITEVERIFY_MASTER_SECRET or SHAR_KEY_FILE to the servers' verifier master",
  );
const siteSecret = await deriveSiteVerifySecret(
  fromBase64url(verifierMaster),
  "interop",
  "interop-site",
);

async function request(endpoint, path, body, expectedStatus = 200, headers) {
  const { response, value } = await requestResult(
    endpoint,
    path,
    body,
    headers,
  );
  assert.equal(
    response.status,
    expectedStatus,
    `${path} returned ${response.status}: ${JSON.stringify(value)}`,
  );
  return value;
}

async function requestResult(endpoint, path, body, extraHeaders = {}) {
  const response = await fetch(new URL(path, endpoint), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin,
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
  assert.equal(response.headers.get("cache-control"), "no-store", path);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff", path);
  assert.match(
    response.headers.get("x-shar-request-id"),
    /^[A-Za-z0-9_-]{22}$/,
    path,
  );
  const value = await response.json();
  await validateProtocolResponse(
    path,
    response.status,
    value,
    `${endpoint}${path}`,
  );
  return { response, value };
}

async function solve(challenge) {
  return {
    token: challenge.token,
    time_lock: solveTimeLock(challenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(challenge.render),
    },
  };
}

async function assertOperationalBackpressure(endpoint) {
  let streamController;
  const body = new ReadableStream({
    start(controller) {
      streamController = controller;
      controller.enqueue(new TextEncoder().encode("{"));
    },
  });
  const held = fetch(new URL("/v1/challenges", endpoint), {
    method: "POST",
    headers: { "content-type": "application/json", origin },
    body,
    duplex: "half",
  });
  await new Promise((resolve) => setTimeout(resolve, 100));

  const live = await fetch(new URL("/healthz", endpoint));
  assert.equal(live.status, 200, "liveness must bypass request admission");
  const overloaded = await fetch(new URL("/v1/challenges", endpoint), {
    method: "POST",
    headers: { "content-type": "application/json", origin },
    body: JSON.stringify({
      tenant: "interop",
      site_key: "interop-site",
      action: "capacity-probe",
      origin,
    }),
  });
  assert.equal(overloaded.status, 503);
  assert.equal(overloaded.headers.get("retry-after"), "1");
  assert.equal(overloaded.headers.get("access-control-allow-origin"), origin);
  const overloadedBody = await overloaded.json();
  await validateProtocolResponse(
    "/v1/challenges",
    overloaded.status,
    overloadedBody,
    `${endpoint}/v1/challenges overload response`,
  );
  assert.deepEqual(overloadedBody, {
    code: "capacity_unavailable",
    retryable: true,
    next_action: "retry",
    retry_after: 1,
  });

  streamController.close();
  assert.equal((await held).status, 400);
  const recovered = await request(endpoint, "/v1/challenges", {
    tenant: "interop",
    site_key: "interop-site",
    action: "capacity-recovery",
    origin,
  });
  assert.ok(recovered.token.startsWith("shr1_"));
}

for (const endpoint of [endpointA, endpointB])
  await assertOperationalBackpressure(endpoint);

for (const endpoint of [endpointA, endpointB]) {
  const live = await fetch(new URL("/healthz", endpoint));
  assert.equal(live.status, 200);
  assert.equal(live.headers.get("cache-control"), "no-store");
  assert.match(live.headers.get("x-shar-request-id"), /^[A-Za-z0-9_-]{22}$/);
  assert.deepEqual(await live.json(), { status: "ok" });
  const ready = await fetch(new URL("/readyz", endpoint));
  assert.equal(ready.status, 200);
  assert.equal(ready.headers.get("cache-control"), "no-store");
  assert.match(ready.headers.get("x-shar-request-id"), /^[A-Za-z0-9_-]{22}$/);
  assert.deepEqual(await ready.json(), { status: "ready" });
  const unmatched = await fetch(
    new URL("/private-tenant-name?session=must-not-appear", endpoint),
  );
  assert.equal(unmatched.status, 404);
  assert.equal(unmatched.headers.get("cache-control"), "no-store");
  assert.equal(unmatched.headers.get("x-content-type-options"), "nosniff");
  assert.match(
    unmatched.headers.get("x-shar-request-id"),
    /^[A-Za-z0-9_-]{22}$/,
  );
  const oversized = await fetch(new URL("/v1/challenges", endpoint), {
    method: "POST",
    headers: { "content-type": "application/json", origin },
    body: "x".repeat(16_385),
  });
  assert.equal(oversized.status, 413);
  assert.equal(oversized.headers.get("cache-control"), "no-store");
  assert.equal(oversized.headers.get("x-content-type-options"), "nosniff");
  assert.equal(oversized.headers.get("access-control-allow-origin"), origin);
  assert.equal(
    oversized.headers.get("access-control-expose-headers"),
    "X-Shar-Request-Id",
  );
  assert.match(
    oversized.headers.get("x-shar-request-id"),
    /^[A-Za-z0-9_-]{22}$/,
  );
  const oversizedBody = await oversized.json();
  await validateProtocolResponse(
    "/v1/challenges",
    oversized.status,
    oversizedBody,
    `${endpoint}/v1/challenges oversized response`,
  );
  assert.deepEqual(oversizedBody, {
    code: "body_too_large",
    retryable: false,
    next_action: "none",
  });
}

for (const [index, endpoint] of [endpointA, endpointB].entries()) {
  const scope = {
    tenant: "interop",
    site_key: "interop-site",
    action: `trusted-assurance-${index}`,
    origin,
  };
  const trusted = await request(endpoint, "/v1/challenges", scope, 200, {
    "x-shar-assurance-tier": "6",
  });
  assert.equal(trusted.quote.tier, 6);

  const invalid = await requestResult(endpoint, "/v1/challenges", scope, {
    "x-shar-assurance-tier": "06",
  });
  assert.equal(invalid.response.status, 400);
  assert.equal(invalid.value.code, "invalid_assurance_tier");

  const browserSelected = await request(endpoint, "/v1/challenges", {
    ...scope,
    action: `browser-assurance-${index}`,
    assurance_tier: 32,
  });
  assert.equal(browserSelected.quote.tier, 0);
}

const [discoveryA, discoveryB] = await Promise.all(
  [endpointA, endpointB].map(async (endpoint) => {
    const response = await fetch(new URL("/.well-known/shar/v1", endpoint));
    assert.equal(response.status, 200);
    return response.json();
  }),
);
assert.deepEqual(
  discoveryA,
  discoveryB,
  "Rust and JavaScript discovery documents differ",
);

const challenge = await request(endpointA, "/v1/challenges", {
  tenant: "interop",
  site_key: "interop-site",
  action: "shared-state",
  origin,
});
const proof = await solve(challenge);
const redemptionRace = await Promise.all(
  [endpointA, endpointB].map((endpoint) =>
    requestResult(endpoint, "/v1/challenges/redeem", proof),
  ),
);
assert.deepEqual(
  redemptionRace.map(({ response }) => response.status).sort(),
  [200, 409],
  "concurrent cross-server challenge redemption must have exactly one winner",
);
const redemption = redemptionRace.find(
  ({ response }) => response.status === 200,
).value;
assert.equal(
  redemptionRace.find(({ response }) => response.status === 409).value.code,
  "replayed_challenge",
);

const verificationBody = {
  token: redemption.token,
  secret: siteSecret,
  action: "shared-state",
  origin,
};
const verificationRace = await Promise.all(
  [endpointA, endpointB].map((endpoint) =>
    requestResult(endpoint, "/v1/siteverify", verificationBody),
  ),
);
assert.deepEqual(
  verificationRace.map(({ response }) => response.status).sort(),
  [200, 409],
  "concurrent cross-server final verification must have exactly one winner",
);
const verified = verificationRace.find(
  ({ response }) => response.status === 200,
).value;
assert.equal(verified.success, true);
assert.equal(verified.receipt.tier, challenge.quote.tier);
assert.equal(
  verificationRace.find(({ response }) => response.status === 409).value.code,
  "replayed_verification",
);

const replacement = await request(endpointB, "/v1/challenges", {
  tenant: "interop",
  site_key: "interop-site",
  action: "shared-state",
  origin,
});
assert.ok(replacement.token.startsWith("shr1_"));
const replacementRedemption = await request(
  endpointA,
  "/v1/challenges/redeem",
  await solve(replacement),
);
const replacementVerification = await request(endpointB, "/v1/siteverify", {
  token: replacementRedemption.token,
  secret: siteSecret,
  action: "shared-state",
  origin,
});
assert.equal(replacementVerification.success, true);

// Exercise the optional blinded-credit path in the opposite direction from
// the ordinary replay race: issue on Rust, redeem on JavaScript, then spend
// the unblinded credit on Rust. The key discovery comparison above also proves
// both servers loaded the same current/overlap issuer material.
const trustChallenge = await request(endpointA, "/v1/challenges", {
  tenant: "interop",
  site_key: "interop-site",
  action: "trust-credit",
  origin,
});
assert.equal(trustChallenge.trust?.mode, "voprf-v1");
const trustNonce = crypto.getRandomValues(new Uint8Array(32));
const trustInput = trustInputForScope(
  "credit",
  trustNonce,
  fromBase64url(trustChallenge.trust.challenge_digest),
  fromBase64url(trustChallenge.trust.key_id),
  {
    tenant: "interop",
    siteKey: "interop-site",
    action: "trust-credit",
    origin,
  },
);
const trustBlind = blindTrustInput(trustInput);
const trustProof = await solve(trustChallenge);
trustProof.trust_blinded = base64url(trustBlind.blinded);
const trustRedemption = await request(
  endpointB,
  "/v1/challenges/redeem",
  trustProof,
);
assert.equal(trustRedemption.trust_evaluation?.version, "trust-evaluation-v1");
const trustEvaluation = trustRedemption.trust_evaluation;
const trustOutput = finalizeTrustInput(
  trustInput,
  trustBlind,
  {
    evaluated: fromBase64url(trustEvaluation.evaluated),
    proof: fromBase64url(trustEvaluation.proof),
  },
  fromBase64url(trustChallenge.trust.public_key),
);
const trustToken = encodeTrustCreditToken({
  version: "trust-credit-v1",
  suite: "ristretto255-SHA512",
  keyId: fromBase64url(trustEvaluation.key_id),
  challengeNonce: trustNonce,
  challengeDigest: fromBase64url(trustChallenge.trust.challenge_digest),
  tenant: "interop",
  siteKey: "interop-site",
  action: "trust-credit",
  origin,
  issuedAt: trustEvaluation.issued_at,
  expiresAt: trustEvaluation.expires_at,
  output: trustOutput,
});
const trustFollowUp = await request(endpointA, "/v1/challenges", {
  tenant: "interop",
  site_key: "interop-site",
  action: "trust-credit",
  origin,
  trust_token: trustToken,
});
assert.ok(trustFollowUp.token.startsWith("shr1_"));
console.log(
  "cross-server backpressure recovery, readiness, trusted assurance, concurrent replay exclusion, reverse-direction verification, trust credits, and retry passed",
);
