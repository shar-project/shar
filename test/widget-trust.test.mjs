import assert from "node:assert/strict";
import test from "node:test";
import {
  base64url,
  decodeTrustCreditToken,
  deriveTrustKeyPair,
  deriveScopedTrustKeyPair,
  evaluateTrustInput,
  fromBase64url,
  trustCreditChallengeDigest,
} from "../packages/server/dist/index.js";
import {
  TRUST_CREDIT_STORAGE_KEY,
  TrustCreditWallet,
  issueWithTrustCredit,
  prepareTrustCreditIssuance,
} from "../packages/widget/dist/trust-credits.js";

class MemorySessionStorage {
  values = new Map();
  failWrites = false;

  get length() {
    return this.values.size;
  }
  clear() {
    this.values.clear();
  }
  getItem(key) {
    return this.values.get(String(key)) ?? null;
  }
  key(index) {
    return [...this.values.keys()][index] ?? null;
  }
  removeItem(key) {
    this.values.delete(String(key));
  }
  setItem(key, value) {
    if (this.failWrites) throw new DOMException("quota", "QuotaExceededError");
    this.values.set(String(key), String(value));
  }
}

const originalStorage = Object.getOwnPropertyDescriptor(
  globalThis,
  "sessionStorage",
);
const storage = new MemorySessionStorage();
Object.defineProperty(globalThis, "sessionStorage", {
  configurable: true,
  value: storage,
});
test.after(() => {
  if (originalStorage)
    Object.defineProperty(globalThis, "sessionStorage", originalStorage);
  else delete globalThis.sessionStorage;
});
test.beforeEach(() => {
  storage.failWrites = false;
  storage.clear();
});

const scope = {
  endpoint: "https://verify.example/v1/challenges",
  tenant: "public",
  sitekey: "site-a",
  action: "signup",
  origin: "https://app.example",
};
const key = deriveTrustKeyPair(
  new Uint8Array(32).fill(3),
  new Uint8Array([1, 2, 3]),
);
const scopeBinding = {
  tenant: scope.tenant,
  siteKey: scope.sitekey,
  action: scope.action,
  origin: scope.origin,
};
const scopedKey = deriveScopedTrustKeyPair(key, scopeBinding);
const challengeDigest = trustCreditChallengeDigest(
  key.keyId,
  scopeBinding,
  1_900_000_000,
  1_900_086_400,
);
const plan = {
  mode: "voprf-v1",
  suite: "ristretto255-SHA512",
  token_type: "credit",
  key_id: base64url(key.keyId),
  public_key: base64url(scopedKey.publicKey),
  challenge_digest: base64url(challengeDigest),
  issued_at: 1_900_000_000,
  expires_at: 1_900_086_400,
};

function fixed(byte) {
  return (length = 32) => new Uint8Array(length).fill(byte);
}

function credit(expiresAt = 1_900_086_400) {
  const issuance = prepareTrustCreditIssuance(plan, scope, fixed(9));
  const evaluated = evaluateTrustInput(
    scopedKey,
    fromBase64url(issuance.blinded),
    fixed(11),
  );
  return issuance.finalize({
    version: "trust-evaluation-v1",
    suite: "ristretto255-SHA512",
    key_id: plan.key_id,
    evaluated: base64url(evaluated.evaluated),
    proof: base64url(evaluated.proof),
    issued_at: 1_900_000_000,
    expires_at: expiresAt,
  });
}

test("browser trust issuance verifies and finalizes the VOPRF transcript", () => {
  const token = credit();
  assert.match(token, /^shrtrust1_/);

  const issuance = prepareTrustCreditIssuance(plan, scope, fixed(9));
  const evaluated = evaluateTrustInput(
    scopedKey,
    fromBase64url(issuance.blinded),
    fixed(11),
  );
  const altered = evaluated.proof.slice();
  altered[0] ^= 1;
  assert.throws(() =>
    issuance.finalize({
      version: "trust-evaluation-v1",
      suite: "ristretto255-SHA512",
      key_id: plan.key_id,
      evaluated: base64url(evaluated.evaluated),
      proof: base64url(altered),
      issued_at: 1_900_000_000,
      expires_at: 1_900_086_400,
    }),
  );
  assert.throws(() =>
    prepareTrustCreditIssuance(
      { ...plan, challenge_digest: base64url(new Uint8Array(32)) },
      scope,
      fixed(9),
    ),
  );
});

test("client-chosen credit nonces make equal issuer plans unlinkable", () => {
  const first = prepareTrustCreditIssuance(plan, scope, fixed(9));
  const second = prepareTrustCreditIssuance(plan, scope, fixed(10));
  assert.notEqual(first.blinded, second.blinded);
  const finalize = (issuance) => {
    const evaluated = evaluateTrustInput(
      scopedKey,
      fromBase64url(issuance.blinded),
      fixed(11),
    );
    return decodeTrustCreditToken(
      issuance.finalize({
        version: "trust-evaluation-v1",
        suite: "ristretto255-SHA512",
        key_id: plan.key_id,
        evaluated: base64url(evaluated.evaluated),
        proof: base64url(evaluated.proof),
        issued_at: plan.issued_at,
        expires_at: plan.expires_at,
      }),
    );
  };
  assert.notDeepEqual(
    finalize(first).challengeNonce,
    finalize(second).challengeNonce,
  );
});

test("same-tab wallet scopes, claims, consumes, and expires one credit", () => {
  const token = credit();
  const wallet = new TrustCreditWallet(scope);
  assert.equal(wallet.store(token, 1_900_000_001), true);
  assert.equal(
    new TrustCreditWallet({ ...scope, action: "checkout" }).offer(
      1_900_000_002,
    ),
    undefined,
  );

  const first = wallet.offer(1_900_000_002);
  assert.equal(first?.token, token);
  assert.equal(wallet.offer(1_900_000_002), undefined);
  first?.release();
  const second = wallet.offer(1_900_086_400);
  assert.equal(second?.token, token, "the exact expiry second remains valid");
  second?.release();
  assert.equal(wallet.offer(1_900_086_401), undefined);
  assert.equal(storage.getItem(TRUST_CREDIT_STORAGE_KEY), null);

  assert.equal(wallet.store(token, 1_900_000_001), true);
  wallet.offer(1_900_000_002)?.accepted();
  assert.equal(wallet.offer(1_900_000_002), undefined);
});

test("wallet rejects wrong bindings and tolerates corruption or denied storage", () => {
  const token = credit();
  assert.equal(
    new TrustCreditWallet({ ...scope, sitekey: "other" }).store(
      token,
      1_900_000_001,
    ),
    false,
  );
  storage.setItem(TRUST_CREDIT_STORAGE_KEY, "{not-json");
  assert.equal(new TrustCreditWallet(scope).offer(1_900_000_001), undefined);
  assert.equal(storage.getItem(TRUST_CREDIT_STORAGE_KEY), null);

  storage.failWrites = true;
  assert.equal(new TrustCreditWallet(scope).store(token, 1_900_000_001), false);
  assert.equal(new TrustCreditWallet(scope).offer(1_900_000_001), undefined);
});

test("issuance retries a rejected credit once but retains it on outage", async () => {
  const token = credit();
  const wallet = new TrustCreditWallet(scope);
  assert.equal(wallet.store(token, 1_800_000_000), true);
  const calls = [];
  const result = await issueWithTrustCredit(wallet, async (offered) => {
    calls.push(offered);
    if (offered) {
      const error = new Error("expired_trust_token");
      error.code = "expired_trust_token";
      throw error;
    }
    return "ordinary-quote";
  });
  assert.equal(result, "ordinary-quote");
  assert.deepEqual(calls, [token, undefined]);
  assert.equal(wallet.offer(), undefined);

  assert.equal(wallet.store(token, 1_800_000_000), true);
  await assert.rejects(
    () =>
      issueWithTrustCredit(wallet, async () => {
        const error = new Error("pricing_unavailable");
        error.code = "pricing_unavailable";
        throw error;
      }),
    /pricing_unavailable/,
  );
  const retained = wallet.offer();
  assert.equal(retained?.token, token);
  retained?.release();
});
