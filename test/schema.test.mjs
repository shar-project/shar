import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  MemoryAuditStore,
  MemoryNonceStore,
  MemoryPressureStore,
  SharError,
  SharService,
  StaticConfigStore,
  solveRendering,
  solveTimeLock,
} from "../dist/packages/server/src/index.js";
import {
  assertProtocolSchema,
  protocolValidators,
} from "./protocol-schema.mjs";

const fallbackAssertionVectors = JSON.parse(
  await readFile(
    new URL("../protocol/fallback-assertion-vectors.json", import.meta.url),
  ),
);

const policy = {
  version: "schema-policy-v1",
  baseIterations: 16n,
  baseRenderRounds: 1,
  quietWindowSeconds: 60,
  baseLifetimeSeconds: 120,
  iterationAllowance: 1_000n,
  roundAllowanceSeconds: 1,
  maxLifetimeSeconds: 86_400,
};

test("real TypeScript lifecycle documents satisfy every public schema", async () => {
  const validators = await protocolValidators();
  let randomCounter = 0;
  const audit = new MemoryAuditStore();
  const service = new SharService({
    signing: {
      keyId: new Uint8Array([1, 2, 3, 4]),
      privateSeed: new Uint8Array(32).fill(7),
    },
    timeLock: {
      id: "schema-rsw",
      modulus: 1_000_036_000_099n,
      lambda: 166_672_333_344n,
    },
    nonces: new MemoryNonceStore(() => 1_800_000_000),
    pressure: new MemoryPressureStore(),
    config: new StaticConfigStore(policy),
    audit,
    clock: { now: () => 1_800_000_000 },
    random: {
      bytes(length) {
        const bytes = new Uint8Array(length);
        for (let index = 0; index < length; index++)
          bytes[index] = (randomCounter + index) & 255;
        randomCounter += length;
        return bytes;
      },
    },
    renderTriangles: 8,
    renderSamples: 16,
    presence: { mode: "host" },
    fallback: { available: true, methods: ["passkey"] },
  });

  const challengeRequest = {
    tenant: "tenant-a",
    site_key: "site-a",
    action: "signup",
    origin: "https://app.example",
    region: "test-region",
    session_binding: "session-binding-hash",
  };
  assertProtocolSchema(
    validators.challengeRequest,
    challengeRequest,
    "challenge request",
  );
  const challenge = await service.challenge(challengeRequest);
  assertProtocolSchema(
    validators.challengeResponse,
    challenge,
    "challenge response",
  );

  const redeemRequest = {
    token: challenge.token,
    time_lock: solveTimeLock(challenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(challenge.render),
    },
  };
  assertProtocolSchema(
    validators.redeemRequest,
    redeemRequest,
    "redeem request",
  );
  const redeemed = await service.redeem(redeemRequest);
  assertProtocolSchema(validators.redeemResponse, redeemed, "redeem response");

  const siteVerifyDocument = {
    token: redeemed.token,
    secret: "shrs1_schema-conformance-secret",
    tenant: challengeRequest.tenant,
    site_key: challengeRequest.site_key,
    action: challengeRequest.action,
    origin: challengeRequest.origin,
    region: challengeRequest.region,
    session_binding: challengeRequest.session_binding,
  };
  assertProtocolSchema(
    validators.siteVerifyRequest,
    siteVerifyDocument,
    "site verification request",
  );
  const verified = await service.siteverify({
    ...siteVerifyDocument,
    secret: undefined,
  });
  assertProtocolSchema(
    validators.siteVerifyResponse,
    verified,
    "site verification response",
  );

  const fallbackRequest = {
    ...challengeRequest,
    method: "passkey",
    assertion_id: "schema-assertion-0001",
  };
  assertProtocolSchema(
    validators.fallbackRequest,
    fallbackRequest,
    "fallback request",
  );
  const fallback = await service.completeFallback(fallbackRequest);
  assertProtocolSchema(
    validators.fallbackResponse,
    fallback,
    "fallback response",
  );
  assertProtocolSchema(
    validators.fallbackAssertion,
    fallbackAssertionVectors.assertion,
    "stored fallback assertion",
  );

  const auditDocument = await service.adminAudit(
    challengeRequest.tenant,
    challengeRequest.site_key,
    challengeRequest.action,
    100,
  );
  assertProtocolSchema(validators.adminAudit, auditDocument, "admin audit");
  for (const event of auditDocument.events)
    assertProtocolSchema(validators.auditEvent, event, "audit event");

  const error = new SharError(503, "pricing_unavailable", true, "retry", 1);
  assertProtocolSchema(validators.error, error.toJSON(), "error response");
  assert.equal(auditDocument.events.length >= 4, true);
});

test("schemas reject cross-envelope fields and malformed protocol values", async () => {
  const validators = await protocolValidators();
  assert.equal(
    validators.challengeRequest({
      tenant: "😀".repeat(32),
      site_key: "site",
      action: "submit",
      origin: "https://app.example",
    }),
    true,
  );
  assert.equal(
    validators.challengeRequest({
      tenant: "😀".repeat(33),
      site_key: "site",
      action: "submit",
      origin: "https://app.example",
    }),
    false,
  );
  assert.equal(
    validators.challengeRequest({
      tenant: "tenant",
      site_key: "site",
      action: "submit\u0085",
      origin: "https://app.example",
    }),
    false,
  );
  assert.equal(
    validators.fallbackRequest({
      tenant: "tenant",
      site_key: "site",
      action: "submit",
      origin: "https://app.example",
      method: "passkey",
      assertion_id: "😀".repeat(4),
    }),
    true,
  );
  assert.equal(
    validators.fallbackAssertion({
      ...fallbackAssertionVectors.assertion,
      version: "fallback-assertion-v0",
    }),
    false,
  );
  assert.equal(
    validators.challengeRequest({
      tenant: "tenant",
      site_key: "site",
      action: "submit",
      origin: "https://app.example",
      assurance_tier: 1,
    }),
    false,
  );
  assert.equal(
    validators.error({
      code: "invalid-work",
      retryable: false,
      next_action: "ban",
    }),
    false,
  );
  assert.equal(
    validators.redeemRequest({
      token: "shr1_bad",
      time_lock: { output: "AA" },
      rendering: { backend: "software", digest: "A".repeat(43) },
    }),
    false,
  );
});
