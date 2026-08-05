import {
  base64url,
  concatBytes,
  equalBytes,
  fromBase64url,
  utf8,
  utf8Decode,
} from "./bytes.js";
import { Cbor, decodeCbor, encodeCbor } from "./cbor.js";

const PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
  0x22, 0x04, 0x20,
]);
const SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function source(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

export interface SigningMaterial {
  keyId: Uint8Array;
  privateSeed: Uint8Array;
}
export interface VerificationMaterial {
  keyId: Uint8Array;
  publicKey: Uint8Array;
}
export type Ed25519Implementation = "auto" | "webcrypto" | "typescript";

async function pureEd25519() {
  return (await import("@noble/curves/ed25519.js")).ed25519;
}

export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", source(concatBytes(...parts))),
  );
}

export async function hmacSha256(
  key: Uint8Array,
  ...parts: Uint8Array[]
): Promise<Uint8Array> {
  return new HmacSha256(key).sign(...parts);
}

/** Reusable HMAC-SHA-256 key for request paths that repeatedly use one
 * configured secret. The constructor snapshots the key so later caller
 * mutation cannot silently change the active identity. */
export class HmacSha256 {
  readonly #key: Promise<CryptoKey>;

  constructor(key: Uint8Array) {
    this.#key = crypto.subtle.importKey(
      "raw",
      source(key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
  }

  async sign(...parts: Uint8Array[]): Promise<Uint8Array> {
    return new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        await this.#key,
        source(concatBytes(...parts)),
      ),
    );
  }
}

async function webCryptoPublicFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    source(concatBytes(PKCS8_PREFIX, seed)),
    "Ed25519",
    true,
    ["sign"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (!jwk.x) throw new Error("ed25519_public_export");
  return fromBase64url(jwk.x);
}

export async function publicFromSeed(
  seed: Uint8Array,
  implementation: Ed25519Implementation = "auto",
): Promise<Uint8Array> {
  if (seed.length !== 32) throw new Error("ed25519_seed_length");
  if (implementation === "typescript")
    return (await pureEd25519()).getPublicKey(seed);
  if (implementation === "webcrypto") return webCryptoPublicFromSeed(seed);
  try {
    return await webCryptoPublicFromSeed(seed);
  } catch {
    return (await pureEd25519()).getPublicKey(seed);
  }
}

type SignOperation = (structure: Uint8Array) => Promise<Uint8Array>;

async function signingOperation(
  seed: Uint8Array,
  implementation: Ed25519Implementation,
): Promise<SignOperation> {
  if (implementation !== "typescript") {
    try {
      const key = await crypto.subtle.importKey(
        "pkcs8",
        source(concatBytes(PKCS8_PREFIX, seed)),
        "Ed25519",
        false,
        ["sign"],
      );
      return async (structure) =>
        new Uint8Array(
          await crypto.subtle.sign("Ed25519", key, source(structure)),
        );
    } catch (error) {
      if (implementation === "webcrypto") throw error;
    }
  }
  const implementationModule = await pureEd25519();
  return async (structure) => implementationModule.sign(structure, seed);
}

/** Reusable COSE Sign1 signer. Importing an Ed25519 seed into WebCrypto can be
 * more expensive than signing, so service instances retain the imported key
 * and canonical protected header for their lifetime. */
export class CoseSigner {
  readonly #protectedBytes: Uint8Array;
  readonly #operation: Promise<SignOperation>;

  constructor(
    material: SigningMaterial,
    implementation: Ed25519Implementation = "auto",
  ) {
    if (material.privateSeed.length !== 32)
      throw new Error("ed25519_seed_length");
    const seed = material.privateSeed.slice();
    this.#protectedBytes = encodeCbor(
      new Map<Cbor, Cbor>([
        [1, -8],
        [4, material.keyId.slice()],
      ]),
    );
    this.#operation = signingOperation(seed, implementation);
  }

  async sign(payload: Uint8Array): Promise<string> {
    const structure = encodeCbor([
      "Signature1",
      this.#protectedBytes,
      new Uint8Array(),
      payload,
    ]);
    const signature = await (await this.#operation)(structure);
    const sign1 = encodeCbor([
      this.#protectedBytes,
      new Map<Cbor, Cbor>(),
      payload,
      signature,
    ]);
    return `shr1_${base64url(sign1)}`;
  }
}

export async function coseSign(
  payload: Uint8Array,
  material: SigningMaterial,
  implementation: Ed25519Implementation = "auto",
): Promise<string> {
  return new CoseSigner(material, implementation).sign(payload);
}

async function webCryptoVerify(
  signature: Uint8Array,
  structure: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  const imported = await crypto.subtle.importKey(
    "spki",
    source(concatBytes(SPKI_PREFIX, publicKey)),
    "Ed25519",
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "Ed25519",
    imported,
    source(signature),
    source(structure),
  );
}

export async function coseVerify(
  token: string,
  keys: readonly VerificationMaterial[],
  implementation: Ed25519Implementation = "auto",
): Promise<Uint8Array> {
  if (!token.startsWith("shr1_")) throw new Error("token_prefix");
  const decoded = decodeCbor(fromBase64url(token.slice(5)));
  if (!Array.isArray(decoded) || decoded.length !== 4)
    throw new Error("cose_shape");
  const [protectedBytes, unprotected, payload, signature] = decoded;
  if (
    !(protectedBytes instanceof Uint8Array) ||
    !(unprotected instanceof Map) ||
    unprotected.size !== 0 ||
    !(payload instanceof Uint8Array) ||
    !(signature instanceof Uint8Array) ||
    signature.length !== 64
  )
    throw new Error("cose_shape");
  const headers = decodeCbor(protectedBytes);
  if (
    !(headers instanceof Map) ||
    headers.get(1) !== -8 ||
    !(headers.get(4) instanceof Uint8Array)
  )
    throw new Error("cose_headers");
  const kid = headers.get(4) as Uint8Array;
  const key = keys.find(
    (candidate) => base64url(candidate.keyId) === base64url(kid),
  );
  if (!key || key.publicKey.length !== 32) throw new Error("unknown_key");
  const structure = encodeCbor([
    "Signature1",
    protectedBytes,
    new Uint8Array(),
    payload,
  ]);
  let valid: boolean;
  if (implementation === "typescript")
    valid = (await pureEd25519()).verify(signature, structure, key.publicKey, {
      zip215: false,
    });
  else if (implementation === "webcrypto")
    valid = await webCryptoVerify(signature, structure, key.publicKey);
  else {
    try {
      valid = await webCryptoVerify(signature, structure, key.publicKey);
    } catch {
      valid = (await pureEd25519()).verify(
        signature,
        structure,
        key.publicKey,
        { zip215: false },
      );
    }
  }
  if (!valid) throw new Error("bad_signature");
  return payload;
}

const NETWORK_PSEUDONYM_DOMAIN = utf8("shar/network/v1\0");
const ZERO_SEPARATOR = new Uint8Array([0]);

export class DailyNetworkPseudonymizer {
  readonly #hmac: HmacSha256;

  constructor(secret: Uint8Array) {
    this.#hmac = new HmacSha256(secret);
  }

  async pseudonym(ipBytes: Uint8Array, unixSeconds: number): Promise<string> {
    const day = Math.floor(unixSeconds / 86400).toString(10);
    return base64url(
      (
        await this.#hmac.sign(
          NETWORK_PSEUDONYM_DOMAIN,
          utf8(day),
          ZERO_SEPARATOR,
          ipBytes,
        )
      ).slice(0, 16),
    );
  }
}

export async function dailyNetworkPseudonym(
  secret: Uint8Array,
  ipBytes: Uint8Array,
  unixSeconds: number,
): Promise<string> {
  return new DailyNetworkPseudonymizer(secret).pseudonym(ipBytes, unixSeconds);
}

const SITE_VERIFY_PREFIX = "shrs1_";
const SITE_VERIFY_DOMAIN = utf8("shar/siteverify/v1\0");

export interface SiteVerifyScope {
  tenant: string;
  site_key: string;
}

export async function deriveSiteVerifySecret(
  master: Uint8Array,
  tenant: string,
  siteKey: string,
): Promise<string> {
  if (master.length !== 32) throw new Error("siteverify_master_length");
  const tenantBytes = scopedText(tenant, 128, "tenant");
  const siteBytes = scopedText(siteKey, 256, "site_key");
  const body = new Uint8Array(5 + tenantBytes.length + siteBytes.length);
  body[0] = 1;
  body[1] = tenantBytes.length >>> 8;
  body[2] = tenantBytes.length;
  body.set(tenantBytes, 3);
  const siteOffset = 3 + tenantBytes.length;
  body[siteOffset] = siteBytes.length >>> 8;
  body[siteOffset + 1] = siteBytes.length;
  body.set(siteBytes, siteOffset + 2);
  const mac = await hmacSha256(master, SITE_VERIFY_DOMAIN, body);
  return `${SITE_VERIFY_PREFIX}${base64url(concatBytes(body, mac))}`;
}

export async function verifySiteVerifySecret(
  master: Uint8Array,
  secret: string,
): Promise<SiteVerifyScope | undefined> {
  if (master.length !== 32) throw new Error("siteverify_master_length");
  if (!secret.startsWith(SITE_VERIFY_PREFIX)) return undefined;
  try {
    const decoded = fromBase64url(secret.slice(SITE_VERIFY_PREFIX.length));
    if (decoded.length < 5 + 1 + 1 + 32 || decoded[0] !== 1) return undefined;
    const tenantLength = ((decoded[1] ?? 0) << 8) | (decoded[2] ?? 0);
    const siteLengthOffset = 3 + tenantLength;
    if (siteLengthOffset + 2 > decoded.length - 32) return undefined;
    const siteLength =
      ((decoded[siteLengthOffset] ?? 0) << 8) |
      (decoded[siteLengthOffset + 1] ?? 0);
    const bodyLength = siteLengthOffset + 2 + siteLength;
    if (bodyLength + 32 !== decoded.length) return undefined;
    const body = decoded.slice(0, bodyLength);
    const suppliedMac = decoded.slice(bodyLength);
    const expectedMac = await hmacSha256(master, SITE_VERIFY_DOMAIN, body);
    if (!equalBytes(suppliedMac, expectedMac)) return undefined;
    const tenant = utf8Decode(body.slice(3, siteLengthOffset));
    const site_key = utf8Decode(body.slice(siteLengthOffset + 2));
    scopedText(tenant, 128, "tenant");
    scopedText(site_key, 256, "site_key");
    return { tenant, site_key };
  } catch {
    return undefined;
  }
}

function scopedText(value: string, maximum: number, name: string): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    /[\0-\x1f\x7f]/.test(value)
  )
    throw new Error(`invalid_${name}`);
  const encoded = utf8(value);
  if (encoded.length > 0xffff) throw new Error(`invalid_${name}`);
  return encoded;
}
