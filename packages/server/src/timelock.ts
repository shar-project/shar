import {
  base64url,
  bigintToBytes,
  bytesToBigint,
  fromBase64url,
  utf8,
} from "./bytes.js";
import { sha256 } from "./crypto.js";
import { TimeLockPlan, TimeLockProof } from "./types.js";

export interface TimeLockKey {
  id: string;
  modulus: bigint;
  lambda: bigint;
}

const MAX_VALIDATED_MODULUS_BITS = 4096;
const VALIDATION_MARGIN_BITS = 64;
const VALIDATION_BASES = [2n, 65_537n, 4_294_967_291n] as const;
const VALIDATION_OFFSETS = [0, 1, 31] as const;

export async function deriveTimeLockInput(
  nonce: Uint8Array,
  modulus: bigint,
): Promise<bigint> {
  if (modulus <= 3n) throw new Error("invalid_modulus");
  for (let counter = 0; counter <= 0xffff_ffff; counter++) {
    const word = new Uint8Array([
      counter >>> 24,
      counter >>> 16,
      counter >>> 8,
      counter,
    ]);
    let candidate = bytesToBigint(
      await sha256(utf8("shar/rsw-v1/input\0"), nonce, word),
    );
    if (candidate >= modulus) candidate %= modulus;
    // Reduce the 2048-bit modulus once, then use binary GCD on digest-width
    // values. This preserves the exact rejection-sampling result while
    // avoiding repeated BigInt division in the Euclidean loop.
    if (candidate > 1n && gcd(modulus, candidate) === 1n) return candidate;
  }
  throw new Error("timelock_input_exhausted");
}

function gcd(a: bigint, b: bigint): bigint {
  if (a === 0n) return b;
  if (b === 0n) return a;
  if (a > b) a %= b;
  else b %= a;
  if (a === 0n) return b;
  if (b === 0n) return a;
  let commonTwos = 0n;
  while ((a & 1n) === 0n && (b & 1n) === 0n) {
    a >>= 1n;
    b >>= 1n;
    commonTwos++;
  }
  while ((a & 1n) === 0n) a >>= 1n;
  while ((b & 1n) === 0n) b >>= 1n;
  while (a !== b) {
    if (a > b) {
      a -= b;
      do a >>= 1n;
      while ((a & 1n) === 0n);
    } else {
      b -= a;
      do b >>= 1n;
      while ((b & 1n) === 0n);
    }
  }
  return a << commonTwos;
}

/**
 * Checks that the protected RSW trapdoor produces the same result as actual
 * sequential squaring. This is intentionally deterministic so every runtime
 * rejects the same corrupted key material before it can issue work.
 *
 * The check establishes operational consistency, rather than trying to prove
 * how the modulus was generated. A multiple of the group exponent is valid
 * trapdoor material and is therefore accepted.
 */
export function validateTimeLockKey(key: TimeLockKey): boolean {
  if (
    typeof key.id !== "string" ||
    utf8(key.id).length < 1 ||
    utf8(key.id).length > 64 ||
    key.modulus <= 3n ||
    (key.modulus & 1n) === 0n ||
    key.lambda <= 1n ||
    key.lambda >= key.modulus
  )
    return false;
  const modulusBits = key.modulus.toString(2).length;
  if (modulusBits > MAX_VALIDATED_MODULUS_BITS) return false;

  for (let index = 0; index < VALIDATION_BASES.length; index++) {
    let base = VALIDATION_BASES[index]! % key.modulus;
    if (base <= 1n) base = 2n;
    while (gcd(base, key.modulus) !== 1n) {
      base += 1n;
      if (base >= key.modulus) base = 2n;
    }
    const iterations =
      modulusBits + VALIDATION_MARGIN_BITS + VALIDATION_OFFSETS[index]!;
    let sequential = base;
    for (let round = 0; round < iterations; round++)
      sequential = (sequential * sequential) % key.modulus;
    const exponent = modPow(2n, BigInt(iterations), key.lambda);
    if (sequential !== modPow(base, exponent, key.modulus)) return false;
  }
  return true;
}

export function modPow(
  base: bigint,
  exponent: bigint,
  modulus: bigint,
): bigint {
  if (modulus <= 1n || exponent < 0n) throw new Error("invalid_modpow");
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

export function solveTimeLock(
  plan: TimeLockPlan,
  onProgress?: (completed: bigint, total: bigint) => void,
): TimeLockProof {
  const modulus = bytesToBigint(fromBase64url(plan.modulus));
  let value = bytesToBigint(fromBase64url(plan.input));
  const iterations = BigInt(plan.iterations);
  for (let i = 0n; i < iterations; i++) {
    value = (value * value) % modulus;
    if (onProgress && (i & 1023n) === 1023n) onProgress(i + 1n, iterations);
  }
  onProgress?.(iterations, iterations);
  return { output: base64url(bigintToBytes(value)) };
}

export function verifyTimeLock(
  key: TimeLockKey,
  input: bigint,
  iterations: bigint,
  proof: TimeLockProof,
): boolean {
  if (iterations <= 0n) return false;
  let received: bigint;
  try {
    received = bytesToBigint(fromBase64url(proof.output));
  } catch {
    return false;
  }
  const exponent = modPow(2n, iterations, key.lambda);
  return received === modPow(input, exponent, key.modulus);
}
