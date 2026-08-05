import {
  base64url,
  fromBase64url,
  type RedeemResponse,
  type TrustTokenPlan,
} from "@shar/server/browser";
import {
  blindTrustInput,
  decodeTrustCreditToken,
  encodeTrustCreditToken,
  finalizeTrustInput,
  trustCreditChallengeDigest,
  trustInputForScope,
  type TrustRandom,
} from "@shar/server/trust";
import { TRUST_CREDIT_STORAGE_KEY } from "./trust-credit-storage.js";

export { TRUST_CREDIT_STORAGE_KEY } from "./trust-credit-storage.js";
const STORAGE_VERSION = "shar-widget-trust-wallet-v1";
const MAX_CREDITS = 16;
const MAX_TOKEN_BYTES = 131_072;
const MAX_STORAGE_BYTES = 2 * 1024 * 1024;

export interface TrustCreditScope {
  endpoint: string;
  tenant: string;
  sitekey: string;
  action: string;
  origin: string;
}

interface StoredTrustCredit {
  scope: TrustCreditScope;
  token: string;
  expiresAt: number;
  updatedAt: number;
}

interface StoredTrustWallet {
  version: typeof STORAGE_VERSION;
  credits: StoredTrustCredit[];
}

const claimedTokens = new Set<string>();

export interface TrustCreditOffer {
  readonly token: string;
  /** The issuer returned a challenge, so the one-shot credit was consumed. */
  accepted(): void;
  /** The issuer explicitly rejected the credit; remove the unusable token. */
  discard(): void;
  /** The request did not establish consumption; retain the credit for retry. */
  release(): void;
}

/**
 * A bounded, first-party, same-tab wallet. Credits never leave their exact
 * endpoint/tenant/site/action/origin scope and storage failure only disables
 * the optional pricing optimization.
 */
export class TrustCreditWallet {
  constructor(readonly scope: TrustCreditScope) {}

  offer(nowSeconds = currentSeconds()): TrustCreditOffer | undefined {
    const credits = readCredits(nowSeconds);
    const credit = credits.find(
      (candidate) =>
        sameScope(candidate.scope, this.scope) &&
        !claimedTokens.has(candidate.token),
    );
    if (!credit) return undefined;
    claimedTokens.add(credit.token);
    let settled = false;
    const settle = (remove: boolean): void => {
      if (settled) return;
      settled = true;
      claimedTokens.delete(credit.token);
      if (remove) removeCredit(this.scope, credit.token, nowSeconds);
    };
    return {
      token: credit.token,
      accepted: () => settle(true),
      discard: () => settle(true),
      release: () => settle(false),
    };
  }

  store(token: string, nowSeconds = currentSeconds()): boolean {
    try {
      if (token.length > MAX_TOKEN_BYTES) return false;
      const decoded = decodeTrustCreditToken(token);
      if (
        decoded.tenant !== this.scope.tenant ||
        decoded.siteKey !== this.scope.sitekey ||
        decoded.action !== this.scope.action ||
        decoded.origin !== this.scope.origin ||
        decoded.expiresAt < nowSeconds
      )
        return false;
      const credits = readCredits(nowSeconds).filter(
        (candidate) => !sameScope(candidate.scope, this.scope),
      );
      credits.unshift({
        scope: { ...this.scope },
        token,
        expiresAt: decoded.expiresAt,
        updatedAt: Date.now(),
      });
      return writeCredits(credits.slice(0, MAX_CREDITS));
    } catch {
      return false;
    }
  }

  clear(nowSeconds = currentSeconds()): void {
    const credits = readCredits(nowSeconds);
    writeCredits(
      credits.filter((candidate) => !sameScope(candidate.scope, this.scope)),
    );
  }
}

type VoprfTrustPlan = Extract<TrustTokenPlan, { mode: "voprf-v1" }>;

export interface TrustCreditIssuance {
  readonly blinded: string;
  finalize(evaluation: NonNullable<RedeemResponse["trust_evaluation"]>): string;
}

/** Validate a signed challenge's plan and create the private blinding state. */
export function prepareTrustCreditIssuance(
  plan: VoprfTrustPlan,
  scope: TrustCreditScope,
  random: TrustRandom = secureTrustRandom,
): TrustCreditIssuance {
  if (
    plan.suite !== "ristretto255-SHA512" ||
    plan.token_type !== "credit" ||
    !Number.isSafeInteger(plan.expires_at) ||
    plan.expires_at < 0
  )
    throw new Error("trust_plan");
  const keyId = canonicalBytes(plan.key_id, 1, 32, "trust_key_id");
  const publicKey = canonicalBytes(plan.public_key, 32, 32, "trust_public_key");
  const nonce = new Uint8Array(random(32));
  if (nonce.length !== 32) throw new Error("trust_nonce");
  const challengeDigest = canonicalBytes(
    plan.challenge_digest,
    32,
    32,
    "trust_challenge_digest",
  );
  if (!Number.isSafeInteger(plan.issued_at) || plan.issued_at < 0)
    throw new Error("trust_plan");
  const scopeBinding = {
    tenant: scope.tenant,
    siteKey: scope.sitekey,
    action: scope.action,
    origin: scope.origin,
  };
  if (
    base64url(
      trustCreditChallengeDigest(
        keyId,
        scopeBinding,
        plan.issued_at,
        plan.expires_at,
      ),
    ) !== plan.challenge_digest
  )
    throw new Error("trust_challenge_binding");
  const input = trustInputForScope(
    "credit",
    nonce,
    challengeDigest,
    keyId,
    scopeBinding,
  );
  const blind = blindTrustInput(input, random);

  return {
    blinded: base64url(blind.blinded),
    finalize(evaluation): string {
      if (
        evaluation.version !== "trust-evaluation-v1" ||
        evaluation.suite !== plan.suite ||
        evaluation.key_id !== plan.key_id ||
        !Number.isSafeInteger(evaluation.issued_at) ||
        !Number.isSafeInteger(evaluation.expires_at) ||
        evaluation.issued_at < 0 ||
        evaluation.expires_at < evaluation.issued_at ||
        evaluation.issued_at !== plan.issued_at ||
        evaluation.expires_at !== plan.expires_at
      )
        throw new Error("trust_evaluation");
      const output = finalizeTrustInput(
        input,
        blind,
        {
          evaluated: canonicalBytes(
            evaluation.evaluated,
            32,
            32,
            "trust_evaluated",
          ),
          proof: canonicalBytes(evaluation.proof, 64, 64, "trust_proof"),
        },
        publicKey,
      );
      return encodeTrustCreditToken({
        version: "trust-credit-v1",
        suite: "ristretto255-SHA512",
        keyId,
        challengeNonce: nonce,
        challengeDigest,
        tenant: scope.tenant,
        siteKey: scope.sitekey,
        action: scope.action,
        origin: scope.origin,
        issuedAt: evaluation.issued_at,
        expiresAt: evaluation.expires_at,
        output,
      });
    },
  };
}

/**
 * Offer one stored credit during challenge issuance. An explicitly stale or
 * rejected credit is removed and issuance is retried once without it.
 */
export async function issueWithTrustCredit<T>(
  wallet: TrustCreditWallet,
  issue: (trustToken?: string) => Promise<T>,
): Promise<T> {
  const offer = wallet.offer();
  if (!offer) return issue();
  try {
    const result = await issue(offer.token);
    offer.accepted();
    return result;
  } catch (error) {
    if (isRejectedTrustCredit(error)) {
      offer.discard();
      return issue();
    }
    offer.release();
    throw error;
  }
}

function isRejectedTrustCredit(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const code = (error as Error & { code?: unknown }).code;
  return (
    typeof code === "string" &&
    [
      "trust_not_configured",
      "invalid_trust_token",
      "expired_trust_token",
      "trust_binding_mismatch",
      "unknown_trust_key",
      "replayed_trust_token",
    ].includes(code)
  );
}

function secureTrustRandom(length = 32): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0)
    throw new Error("trust_random_length");
  if (typeof crypto === "undefined" || !crypto.getRandomValues)
    throw new Error("trust_random_unavailable");
  const output = new Uint8Array(length);
  for (let offset = 0; offset < output.length; offset += 65_536)
    crypto.getRandomValues(output.subarray(offset, offset + 65_536));
  return output;
}

function canonicalBytes(
  encoded: string,
  minimum: number,
  maximum: number,
  label: string,
): Uint8Array {
  const value = fromBase64url(encoded);
  if (
    value.length < minimum ||
    value.length > maximum ||
    base64url(value) !== encoded
  )
    throw new Error(label);
  return value;
}

function currentSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function storageOrUndefined(): Storage | undefined {
  try {
    return typeof sessionStorage === "undefined" ? undefined : sessionStorage;
  } catch {
    return undefined;
  }
}

function readCredits(nowSeconds: number): StoredTrustCredit[] {
  const storage = storageOrUndefined();
  if (!storage) return [];
  try {
    const raw = storage.getItem(TRUST_CREDIT_STORAGE_KEY);
    if (raw === null) return [];
    if (raw.length > MAX_STORAGE_BYTES) throw new Error("trust_wallet_size");
    const value = JSON.parse(raw) as unknown;
    if (!isRecord(value) || value.version !== STORAGE_VERSION)
      throw new Error("trust_wallet_shape");
    if (!Array.isArray(value.credits) || value.credits.length > MAX_CREDITS)
      throw new Error("trust_wallet_shape");
    const credits = value.credits.filter(
      (candidate): candidate is StoredTrustCredit =>
        validStoredCredit(candidate, nowSeconds),
    );
    if (credits.length !== value.credits.length) writeCredits(credits);
    return credits;
  } catch {
    try {
      storage.removeItem(TRUST_CREDIT_STORAGE_KEY);
    } catch {}
    return [];
  }
}

function writeCredits(credits: StoredTrustCredit[]): boolean {
  const storage = storageOrUndefined();
  if (!storage) return false;
  try {
    if (credits.length === 0) {
      storage.removeItem(TRUST_CREDIT_STORAGE_KEY);
      return true;
    }
    const raw = JSON.stringify({ version: STORAGE_VERSION, credits });
    if (raw.length > MAX_STORAGE_BYTES) return false;
    storage.setItem(TRUST_CREDIT_STORAGE_KEY, raw);
    return true;
  } catch {
    return false;
  }
}

function removeCredit(
  scope: TrustCreditScope,
  token: string,
  nowSeconds: number,
): void {
  writeCredits(
    readCredits(nowSeconds).filter(
      (candidate) =>
        candidate.token !== token || !sameScope(candidate.scope, scope),
    ),
  );
}

function validStoredCredit(
  value: unknown,
  nowSeconds: number,
): value is StoredTrustCredit {
  if (!isRecord(value) || !validScope(value.scope)) return false;
  if (
    typeof value.token !== "string" ||
    value.token.length > MAX_TOKEN_BYTES ||
    !Number.isSafeInteger(value.expiresAt) ||
    (value.expiresAt as number) < nowSeconds ||
    typeof value.updatedAt !== "number" ||
    !Number.isFinite(value.updatedAt) ||
    value.updatedAt < 0
  )
    return false;
  try {
    const decoded = decodeTrustCreditToken(value.token);
    return (
      decoded.expiresAt === value.expiresAt &&
      decoded.tenant === value.scope.tenant &&
      decoded.siteKey === value.scope.sitekey &&
      decoded.action === value.scope.action &&
      decoded.origin === value.scope.origin
    );
  } catch {
    return false;
  }
}

function validScope(value: unknown): value is TrustCreditScope {
  if (!isRecord(value)) return false;
  return ["endpoint", "tenant", "sitekey", "action", "origin"].every(
    (key) =>
      typeof value[key] === "string" &&
      value[key].length >= 1 &&
      value[key].length <= 2048,
  );
}

function sameScope(left: TrustCreditScope, right: TrustCreditScope): boolean {
  return (
    left.endpoint === right.endpoint &&
    left.tenant === right.tenant &&
    left.sitekey === right.sitekey &&
    left.action === right.action &&
    left.origin === right.origin
  );
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
