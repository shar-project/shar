// This file intentionally uses only standard ECMAScript and Web Platform APIs.
// CI runs it unchanged in Node, Bun, and permission-denied Deno.
// Materialize the host's Fetch constructors before removing compatibility
// globals. Native Node's Undici implementation also reads the global Buffer
// during every Request/Response body operation, so Buffer can only be masked
// in Bun/Deno here; package-closure tests independently reject Buffer usage in
// Shar and its production dependencies.
void globalThis.Request;
void globalThis.Response;
void globalThis.Headers;
const forbiddenFetch = globalThis.fetch;
const nativeNodeFetchUsesBuffer =
  typeof process === "object" &&
  process.release?.name === "node" &&
  typeof Bun === "undefined" &&
  typeof Deno === "undefined";
function disableGlobal(name) {
  if (!(name in globalThis)) return;
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
  if (descriptor?.configurable)
    Object.defineProperty(globalThis, name, {
      configurable: true,
      value: undefined,
    });
  else if (descriptor?.writable) globalThis[name] = undefined;
}
const compatibilityGlobals = ["process", "WebAssembly", "Deno", "Bun"];
if (!nativeNodeFetchUsesBuffer) compatibilityGlobals.push("Buffer");
for (const name of compatibilityGlobals) disableGlobal(name);
globalThis.fetch = async () => {
  throw new Error("unexpected outbound fetch");
};

const {
  BufferedAuditStore,
  MemoryAuditStore,
  MemoryNonceStore,
  MemoryPressureStore,
  SharService,
  StaticConfigStore,
  base64url,
  coseSign,
  coseVerify,
  createSharHandler,
  deriveSiteVerifySecret,
  publicFromSeed,
  solveRendering,
  solveTimeLock,
  validateTimeLockKey,
} = await import("../packages/server/dist/index.js");

function check(condition, message) {
  if (!condition) throw new Error(message);
}

const seed = new Uint8Array(32).fill(7);
const keyId = new Uint8Array([1, 2, 3, 4]);
const payload = new TextEncoder().encode("shar-runtime-smoke-v1");
const publicKey = await publicFromSeed(seed, "typescript");
check(
  base64url(publicKey) === "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",
  "public key mismatch",
);
const token = await coseSign(
  payload,
  { keyId, privateSeed: seed },
  "typescript",
);
const verified = await coseVerify(token, [{ keyId, publicKey }], "typescript");
check(
  new TextDecoder().decode(verified) === "shar-runtime-smoke-v1",
  "COSE verification mismatch",
);

const timeLock = {
  id: "runtime-smoke",
  modulus: 1_000_036_000_099n,
  lambda: 166_672_333_344n,
};
check(validateTimeLockKey(timeLock), "valid RSW trapdoor rejected");
check(
  !validateTimeLockKey({ ...timeLock, lambda: timeLock.lambda + 1n }),
  "corrupt RSW trapdoor accepted",
);

const policy = {
  version: "runtime-policy-v1",
  baseIterations: 16n,
  baseRenderRounds: 1,
  quietWindowSeconds: 60,
  baseLifetimeSeconds: 120,
  iterationAllowance: 1_000n,
  roundAllowanceSeconds: 1,
  maxLifetimeSeconds: 86_400,
};
let randomCounter = 0;
const persistedAudit = new MemoryAuditStore();
const audit = new BufferedAuditStore(persistedAudit, 64);
const service = new SharService({
  signing: { keyId, privateSeed: seed },
  timeLock,
  nonces: new MemoryNonceStore(() => 1_800_000_000),
  pressure: new MemoryPressureStore(),
  config: new StaticConfigStore(policy),
  audit,
  clock: { now: () => 1_800_000_000 },
  random: {
    bytes(length) {
      const output = new Uint8Array(length);
      for (let index = 0; index < length; index++)
        output[index] = (randomCounter + index) & 255;
      randomCounter += length;
      return output;
    },
  },
  renderTriangles: 8,
  renderSamples: 16,
});
const siteVerifyMasterSecret = new Uint8Array(32).fill(14);
const origin = "https://app.example";
const challengeBody = {
  tenant: "runtime-tenant",
  site_key: "runtime-site",
  action: "submit",
  origin,
};
const handler = createSharHandler(service, {
  allowedOrigins: [origin],
  siteVerifyMasterSecret,
});

function protocolRequest(path, body, contentType = "application/json") {
  const bytes = new TextEncoder().encode(
    contentType === "application/json" ? JSON.stringify(body) : body.toString(),
  );
  return new Request(`https://shar.example${path}`, {
    method: "POST",
    headers: {
      "content-type": contentType,
      ...(path.startsWith("/v1/challenges") ? { origin } : {}),
    },
    body: bytes,
  });
}

async function issue() {
  const response = await handler(
    protocolRequest("/v1/challenges", challengeBody),
  );
  check(response.status === 200, "challenge issuance failed");
  return response.json();
}

const originalChallenge = await issue();
check(originalChallenge.quote.tier === 0, "first quote was not tier zero");

// Increase current pressure after the original signed quote has been issued.
// Its promised work must remain sufficient and must never be repriced.
const laterChallenge = await issue();
check(
  laterChallenge.quote.tier > originalChallenge.quote.tier,
  "pressure did not increase a future quote",
);

const proof = {
  token: originalChallenge.token,
  time_lock: solveTimeLock(originalChallenge.time_lock),
  rendering: {
    backend: "css",
    digest: await solveRendering(originalChallenge.render),
  },
};
const redeemedResponse = await handler(
  protocolRequest("/v1/challenges/redeem", proof),
);
check(
  redeemedResponse.status === 200,
  "issued proof was not honored after pressure increased",
);
const redeemed = await redeemedResponse.json();
check(redeemed.receipt.tier === 0, "receipt did not preserve quoted tier");

const replayedChallenge = await handler(
  protocolRequest("/v1/challenges/redeem", proof),
);
check(replayedChallenge.status === 409, "challenge replay succeeded");
check(
  (await replayedChallenge.json()).code === "replayed_challenge",
  "challenge replay returned an unstable error",
);

const siteSecret = await deriveSiteVerifySecret(
  siteVerifyMasterSecret,
  challengeBody.tenant,
  challengeBody.site_key,
);
const verifyBody = new URLSearchParams({
  "g-recaptcha-response": redeemed.token,
  secret: siteSecret,
});
const verifiedResponse = await handler(
  protocolRequest(
    "/v1/siteverify",
    verifyBody,
    "application/x-www-form-urlencoded",
  ),
);
check(verifiedResponse.status === 200, "site verification failed");
const verification = await verifiedResponse.json();
check(verification.success === true, "site verification was not successful");
check(verification.score === 1, "compatibility score was not successful");
check(
  verification.action === challengeBody.action &&
    verification.origin === challengeBody.origin,
  "verification bindings changed",
);

const replayedVerification = await handler(
  protocolRequest(
    "/v1/siteverify",
    verifyBody,
    "application/x-www-form-urlencoded",
  ),
);
check(replayedVerification.status === 409, "verification replay succeeded");
check(
  (await replayedVerification.json()).code === "replayed_verification",
  "verification replay returned an unstable error",
);

const metrics = await handler(new Request("https://shar.example/metrics"));
const metricsText = await metrics.text();
check(
  metricsText.includes("shar_challenges_issued_total 2\n"),
  "challenge metric mismatch",
);
check(
  metricsText.includes("shar_challenges_redeemed_total 1\n"),
  "redemption metric mismatch",
);
check(
  metricsText.includes("shar_site_verifications_total 1\n"),
  "verification metric mismatch",
);

await audit.flush();
const auditKinds = persistedAudit.snapshot().map((event) => event.kind);
for (const expected of [
  "challenge_issued",
  "proof_redeemed",
  "proof_failed",
  "site_verified",
  "verification_failed",
])
  check(auditKinds.includes(expected), `missing audit event: ${expected}`);

// Keep the original reference alive only to make the intentional override
// explicit to static analyzers; no protocol code was allowed to use it.
void forbiddenFetch;
console.log("pure TypeScript restricted-runtime lifecycle passed");
