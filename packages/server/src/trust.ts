import { ristretto255_oprf } from "@noble/curves/ed25519.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

import {
  base64url,
  concatBytes,
  equalBytes,
  fromBase64url,
  utf8,
} from "./bytes.js";
import { Cbor, decodeCbor, encodeCbor } from "./cbor.js";

/**
 * Shar's first-party blinded-credit primitive.
 *
 * The wire protocol is deliberately kept above this module: callers choose
 * how a blinded request and evaluation are transported and how a finalized
 * output is turned into a single-use credit. The primitive itself is the
 * verifiable mode from RFC 9497, using the Ristretto255-SHA512 suite. Keeping
 * this boundary small lets the Rust and TypeScript implementations share the
 * exact cryptographic transcript without making privacy-sensitive policy
 * decisions in the primitive.
 */
export const TRUST_TOKEN_VERSION = "trust-voprf-v1" as const;
export const TRUST_VOPRF_SUITE = "ristretto255-SHA512" as const;
export const TRUST_KEY_INFO = utf8("shar/trust/v1");
export const TRUST_OUTPUT_BYTES = 64;
export const TRUST_POINT_BYTES = 32;
export const TRUST_SCALAR_BYTES = 32;
export const TRUST_PROOF_BYTES = 64;
export const TRUST_CREDIT_PREFIX = "shrtrust1_";

export type TrustRandom = (length?: number) => Uint8Array;

type VoprfWithDirectEvaluate = typeof ristretto255_oprf.voprf & {
  evaluate(secretKey: Uint8Array, value: Uint8Array): Uint8Array;
};

// noble-curves implements the RFC 9497 non-interactive VOPRF evaluation but
// its generated declaration currently omits that member from the voprf type.
const voprf = ristretto255_oprf.voprf as VoprfWithDirectEvaluate;

function randomAdapter(random: TrustRandom): (length?: number) => Uint8Array {
  return (length?: number) => new Uint8Array(random(length ?? 32));
}

/**
 * Produce the same domain-separated seeded byte stream as the Rust core for
 * deterministic proof transcripts. The two audited VOPRF libraries may map
 * the requested bytes to scalars differently; the proof remains verifiable,
 * while the seeded stream keeps TypeScript tests independent of global RNG.
 * Production derives the seed from fresh response/challenge nonces.
 */
export function deterministicTrustRandom(seedValue: Uint8Array): TrustRandom {
  const seed = new Uint8Array(nobleSha256(seedValue));
  const domain = utf8("shar/trust/rng/v1\0");
  let counter = 0n;
  let buffer = new Uint8Array();
  return (length = 32) => {
    if (!Number.isSafeInteger(length) || length < 0)
      throw new Error("trust_random_length");
    while (buffer.length < length) {
      const counterBytes = new Uint8Array(8);
      let value = counter;
      for (let index = counterBytes.length - 1; index >= 0; index--) {
        counterBytes[index] = Number(value & 0xffn);
        value >>= 8n;
      }
      counter = (counter + 1n) & 0xffffffffffffffffn;
      buffer = new Uint8Array(
        concatBytes(
          buffer,
          new Uint8Array(nobleSha256(concatBytes(domain, seed, counterBytes))),
        ),
      );
    }
    const output = buffer.slice(0, length);
    buffer = buffer.slice(length);
    return output;
  };
}

export interface TrustKeyPair {
  /** Public key identifier carried by the surrounding issuance protocol. */
  keyId: Uint8Array;
  /** Secret scalar. Keep this on the issuer only. */
  secretKey: Uint8Array;
  /** Serialized Ristretto public key distributed to clients. */
  publicKey: Uint8Array;
}

export interface TrustBlindState {
  /** The scalar that must remain private until finalization. */
  blind: Uint8Array;
  /** Serialized element sent to the issuer. */
  blinded: Uint8Array;
}

export interface TrustEvaluation {
  /** Serialized evaluated element returned by the issuer. */
  evaluated: Uint8Array;
  /** Serialized VOPRF DLEQ proof. */
  proof: Uint8Array;
}

export interface TrustScope {
  tenant: string;
  siteKey: string;
  action: string;
  origin: string;
}

/** Opaque, single-use credit envelope created by the browser after finalize. */
export interface TrustCreditToken {
  version: "trust-credit-v1";
  suite: typeof TRUST_VOPRF_SUITE;
  keyId: Uint8Array;
  challengeNonce: Uint8Array;
  challengeDigest: Uint8Array;
  tenant: string;
  siteKey: string;
  action: string;
  origin: string;
  issuedAt: number;
  expiresAt: number;
  output: Uint8Array;
}

/**
 * Coarse public lifetime shared by many issuances. The bucket is at most one
 * hour and at most 1/24 of retention, leaving at least 23/24 of the configured
 * lifetime while avoiding an exact per-challenge timestamp tag.
 */
export function trustCreditLifetime(
  nowValue: number,
  retentionSecondsValue: number,
): { issuedAt: number; expiresAt: number } {
  const now = trustNumber(nowValue, "issued_at");
  const retention = trustNumber(retentionSecondsValue, "retention");
  if (retention < 1) throw new Error("trust_retention");
  const bucket = Math.min(3600, Math.max(1, Math.floor(retention / 24)));
  const issuedAt = now - (now % bucket);
  if (issuedAt > Number.MAX_SAFE_INTEGER - retention)
    throw new Error("trust_expiry");
  return { issuedAt, expiresAt: issuedAt + retention };
}

/** Public metadata digest bound into a credit's hidden VOPRF input. */
export function trustCreditChallengeDigest(
  keyIdValue: Uint8Array,
  scope: TrustScope,
  issuedAtValue: number,
  expiresAtValue: number,
): Uint8Array {
  const issuedAt = trustNumber(issuedAtValue, "issued_at");
  const expiresAt = trustNumber(expiresAtValue, "expires_at");
  if (expiresAt < issuedAt) throw new Error("trust_expiry");
  const fields = [scope.tenant, scope.siteKey, scope.action, scope.origin].map(
    (value) => lengthPrefix(utf8(trustText(value, 512, "scope"))),
  );
  return new Uint8Array(
    nobleSha256(
      concatBytes(
        utf8("shar/trust/challenge/v1\0"),
        lengthPrefix(keyId(keyIdValue)),
        ...fields,
        uint64(issuedAt),
        uint64(expiresAt),
      ),
    ),
  );
}

/** Stable one-shot identity; re-encoding clear metadata cannot bypass replay. */
export function trustCreditReplayId(
  keyIdValue: Uint8Array,
  output: Uint8Array,
): Uint8Array {
  if (output.length !== TRUST_OUTPUT_BYTES)
    throw new Error("trust_output_length");
  return new Uint8Array(
    nobleSha256(
      concatBytes(
        utf8("shar/trust/replay/v1\0"),
        lengthPrefix(keyId(keyIdValue)),
        output,
      ),
    ),
  );
}

function copy(value: Uint8Array): Uint8Array {
  return value.slice();
}

function keyId(value: Uint8Array): Uint8Array {
  if (value.length < 1 || value.length > 32)
    throw new Error("trust_key_id_length");
  return copy(value);
}

function seed(value: Uint8Array): Uint8Array {
  if (value.length !== 32) throw new Error("trust_seed_length");
  return copy(value);
}

function input(value: Uint8Array): Uint8Array {
  if (value.length < 1 || value.length > 0xffff)
    throw new Error("trust_input_length");
  return copy(value);
}

function point(value: Uint8Array, label: string): Uint8Array {
  if (value.length !== TRUST_POINT_BYTES)
    throw new Error(`trust_${label}_length`);
  return copy(value);
}

function scalar(value: Uint8Array, label: string): Uint8Array {
  if (value.length !== TRUST_SCALAR_BYTES)
    throw new Error(`trust_${label}_length`);
  return copy(value);
}

function proof(value: Uint8Array): Uint8Array {
  if (value.length !== TRUST_PROOF_BYTES) throw new Error("trust_proof_length");
  return copy(value);
}

/** Derive a stable issuer key from a 32-byte deployment seed. */
export function deriveTrustKeyPair(
  deploymentSeed: Uint8Array,
  keyIdValue: Uint8Array,
): TrustKeyPair {
  const keys = ristretto255_oprf.voprf.deriveKeyPair(
    seed(deploymentSeed),
    TRUST_KEY_INFO,
  );
  return {
    keyId: keyId(keyIdValue),
    secretKey: copy(keys.secretKey),
    publicKey: copy(keys.publicKey),
  };
}

/** Derive a cryptographically distinct issuer key for one complete scope. */
export function deriveScopedTrustKeyPair(
  root: TrustKeyPair,
  scope: TrustScope,
): TrustKeyPair {
  const fields = [scope.tenant, scope.siteKey, scope.action, scope.origin].map(
    (value) => lengthPrefix(utf8(trustText(value, 512, "scope"))),
  );
  const scopedSeed = new Uint8Array(
    nobleSha256(
      concatBytes(
        utf8("shar/trust/scoped-key/v1\0"),
        scalar(root.secretKey, "secret_key"),
        ...fields,
      ),
    ),
  );
  return deriveTrustKeyPair(scopedSeed, root.keyId);
}

/** Blind an input before sending it to the issuer. */
export function blindTrustInput(
  value: Uint8Array,
  random?: TrustRandom,
): TrustBlindState {
  const blinded = random
    ? voprf.blind(input(value), randomAdapter(random))
    : voprf.blind(input(value));
  return {
    blind: scalar(blinded.blind, "blind"),
    blinded: point(blinded.blinded, "blinded"),
  };
}

/** Evaluate a blinded input and produce a proof bound to the public key. */
export function evaluateTrustInput(
  key: TrustKeyPair,
  blindedValue: Uint8Array,
  random?: TrustRandom,
): TrustEvaluation {
  const secretKey = scalar(key.secretKey, "secret_key");
  const publicKey = point(key.publicKey, "public_key");
  const blinded = point(blindedValue, "blinded");
  const evaluated = random
    ? voprf.blindEvaluate(secretKey, publicKey, blinded, randomAdapter(random))
    : voprf.blindEvaluate(secretKey, publicKey, blinded);
  return {
    evaluated: point(evaluated.evaluated, "evaluated"),
    proof: proof(evaluated.proof),
  };
}

/** Verify the issuer proof and unblind the resulting credit value. */
export function finalizeTrustInput(
  value: Uint8Array,
  state: TrustBlindState,
  evaluation: TrustEvaluation,
  publicKey: Uint8Array,
): Uint8Array {
  const output = ristretto255_oprf.voprf.finalize(
    input(value),
    scalar(state.blind, "blind"),
    point(evaluation.evaluated, "evaluated"),
    point(state.blinded, "blinded"),
    point(publicKey, "public_key"),
    proof(evaluation.proof),
  );
  if (output.length !== TRUST_OUTPUT_BYTES)
    throw new Error("trust_output_length");
  return copy(output);
}

/** Compute the same output directly when the issuer knows the input. */
export function evaluateTrustDirect(
  key: TrustKeyPair,
  value: Uint8Array,
): Uint8Array {
  const output = voprf.evaluate(
    scalar(key.secretKey, "secret_key"),
    input(value),
  );
  if (output.length !== TRUST_OUTPUT_BYTES)
    throw new Error("trust_output_length");
  return copy(output);
}

/** Constant-time comparison helper for credit verification adapters. */
export function equalTrustOutput(left: Uint8Array, right: Uint8Array): boolean {
  return equalBytes(left, right);
}

function lengthPrefix(value: Uint8Array): Uint8Array {
  if (value.length > 0xffff) throw new Error("trust_field_length");
  return concatBytes(
    new Uint8Array([value.length >>> 8, value.length & 0xff]),
    value,
  );
}

function uint64(value: number): Uint8Array {
  let remaining = BigInt(value);
  const encoded = new Uint8Array(8);
  for (let index = encoded.length - 1; index >= 0; index--) {
    encoded[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return encoded;
}

/**
 * Build the domain-separated input used by Shar's credit envelope.
 *
 * The surrounding protocol should include a fresh nonce and challenge digest;
 * binding both here prevents a credit from being moved between challenges or
 * scopes. Length prefixes make concatenation unambiguous and are intentionally
 * independent of JSON, CBOR, or transport encoding.
 */
export function trustInput(
  tokenType: string,
  nonce: Uint8Array,
  challengeDigest: Uint8Array,
  keyIdValue: Uint8Array,
): Uint8Array {
  const type = utf8(tokenType);
  if (type.length < 1 || type.length > 128)
    throw new Error("trust_token_type_length");
  if (nonce.length !== 32) throw new Error("trust_nonce_length");
  if (challengeDigest.length !== 32)
    throw new Error("trust_challenge_digest_length");
  const kid = keyId(keyIdValue);
  return concatBytes(
    utf8("shar/trust/input/v1\0"),
    lengthPrefix(type),
    lengthPrefix(nonce),
    lengthPrefix(challengeDigest),
    lengthPrefix(kid),
  );
}

/** Bind a credit to the complete Shar scope, including the allowed origin. */
export function trustInputForScope(
  tokenType: string,
  nonce: Uint8Array,
  challengeDigest: Uint8Array,
  keyIdValue: Uint8Array,
  scope: TrustScope,
): Uint8Array {
  const base = trustInput(tokenType, nonce, challengeDigest, keyIdValue);
  const fields = [scope.tenant, scope.siteKey, scope.action, scope.origin].map(
    (value) => {
      const encoded = utf8(value);
      if (encoded.length < 1 || encoded.length > 512)
        throw new Error("trust_scope_length");
      return lengthPrefix(encoded);
    },
  );
  return concatBytes(base, ...fields);
}

function trustText(value: string, maximum: number, label: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    /[\0-\x1f\x7f]/.test(value)
  )
    throw new Error(`trust_${label}`);
  return value;
}

function trustNumber(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error(`trust_${label}`);
  return value;
}

/** Encode a finalized credit using canonical CBOR and a non-confusable prefix. */
export function encodeTrustCreditToken(token: TrustCreditToken): string {
  if (token.version !== "trust-credit-v1") throw new Error("trust_version");
  if (token.suite !== TRUST_VOPRF_SUITE) throw new Error("trust_suite");
  const key = keyId(token.keyId);
  const nonce = token.challengeNonce;
  if (nonce.length !== 32) throw new Error("trust_challenge_nonce_length");
  const digest = token.challengeDigest;
  if (digest.length !== 32) throw new Error("trust_challenge_digest_length");
  const output = token.output;
  if (output.length !== TRUST_OUTPUT_BYTES)
    throw new Error("trust_output_length");
  const issuedAt = trustNumber(token.issuedAt, "issued_at");
  const expiresAt = trustNumber(token.expiresAt, "expires_at");
  if (expiresAt < issuedAt) throw new Error("trust_expiry");
  return `${TRUST_CREDIT_PREFIX}${base64url(
    encodeCbor(
      new Map<Cbor, Cbor>([
        [0, "trust-credit"],
        [1, "shar-v1"],
        [2, key],
        [3, nonce],
        [4, digest],
        [5, trustText(token.tenant, 128, "tenant")],
        [6, trustText(token.siteKey, 256, "site_key")],
        [7, trustText(token.action, 128, "action")],
        [8, trustText(token.origin, 512, "origin")],
        [9, issuedAt],
        [10, expiresAt],
        [11, output],
        [12, TRUST_VOPRF_SUITE],
      ]),
    ),
  )}`;
}

function trustMap(value: Cbor): Map<Cbor, Cbor> {
  if (!(value instanceof Map)) throw new Error("trust_shape");
  return value;
}

function trustMapString(
  map: Map<Cbor, Cbor>,
  key: number,
  maximum: number,
  label: string,
): string {
  const value = map.get(key);
  if (typeof value !== "string") throw new Error("trust_shape");
  return trustText(value, maximum, label);
}

function trustMapBytes(
  map: Map<Cbor, Cbor>,
  key: number,
  length: number,
  label: string,
): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || value.length !== length)
    throw new Error(`trust_${label}_length`);
  return copy(value);
}

function trustMapKeyId(map: Map<Cbor, Cbor>): Uint8Array {
  const value = map.get(2);
  if (!(value instanceof Uint8Array)) throw new Error("trust_key_id_length");
  return keyId(value);
}

function trustMapNumber(
  map: Map<Cbor, Cbor>,
  key: number,
  label: string,
): number {
  const value = map.get(key);
  if (typeof value !== "number") throw new Error("trust_shape");
  return trustNumber(value, label);
}

/** Decode and fully validate a credit before it reaches a storage adapter. */
export function decodeTrustCreditToken(token: string): TrustCreditToken {
  if (typeof token !== "string" || !token.startsWith(TRUST_CREDIT_PREFIX))
    throw new Error("trust_prefix");
  const map = trustMap(
    decodeCbor(
      // Importing the base64 decoder through the public bytes module keeps this
      // helper usable in edge runtimes without Buffer.
      fromBase64url(token.slice(TRUST_CREDIT_PREFIX.length)),
    ),
  );
  if (map.get(0) !== "trust-credit" || map.get(1) !== "shar-v1")
    throw new Error("trust_version");
  const suite = map.get(12);
  if (suite !== TRUST_VOPRF_SUITE) throw new Error("trust_suite");
  const issuedAt = trustMapNumber(map, 9, "issued_at");
  const expiresAt = trustMapNumber(map, 10, "expires_at");
  if (expiresAt < issuedAt) throw new Error("trust_expiry");
  return {
    version: "trust-credit-v1",
    suite: TRUST_VOPRF_SUITE,
    keyId: trustMapKeyId(map),
    challengeNonce: trustMapBytes(map, 3, 32, "challenge_nonce"),
    challengeDigest: trustMapBytes(map, 4, 32, "challenge_digest"),
    tenant: trustMapString(map, 5, 128, "tenant"),
    siteKey: trustMapString(map, 6, 256, "site_key"),
    action: trustMapString(map, 7, 128, "action"),
    origin: trustMapString(map, 8, 512, "origin"),
    issuedAt,
    expiresAt,
    output: trustMapBytes(map, 11, TRUST_OUTPUT_BYTES, "output"),
  };
}

/** A log-safe representation for diagnostics; it never includes secret state. */
export function trustPublicKeySummary(key: TrustKeyPair): {
  suite: typeof TRUST_VOPRF_SUITE;
  key_id: string;
  public_key: string;
} {
  return {
    suite: TRUST_VOPRF_SUITE,
    key_id: base64url(keyId(key.keyId)),
    public_key: base64url(point(key.publicKey, "public_key")),
  };
}
