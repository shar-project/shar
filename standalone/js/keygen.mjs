import { readFile, stat, open } from "node:fs/promises";
import process from "node:process";
import {
  base64url,
  fromBase64url,
  publicFromSeed,
} from "../../dist/packages/server/src/index.js";

const cryptoSource =
  globalThis.crypto ?? (await import("node:crypto")).webcrypto;
const args = parseArgs(process.argv.slice(2));
if (args.command === "site-secret") {
  const document = await readKeyDocument(
    args.keyFile ?? process.env.SHAR_KEY_FILE,
  );
  const master = fromBase64url(
    requireField(document, "SHAR_SITEVERIFY_MASTER_SECRET"),
  );
  if (master.length !== 32)
    throw new Error("SHAR_SITEVERIFY_MASTER_SECRET must decode to 32 bytes");
  const secret = await deriveSiteSecret(master, args.tenant, args.siteKey);
  process.stdout.write(`${secret}\n`);
} else if (args.command === "rotate") {
  const old = await readKeyDocument(args.input);
  const rotated = await makeBundle(old);
  await writeDocument(args.output, rotated);
  console.error(`wrote rotated protected key material to ${args.output}`);
} else {
  const document = await makeBundle();
  await writeDocument(args.output, document);
  console.error(`wrote new protected key material to ${args.output}`);
}

async function makeBundle(old) {
  const signingSeed = randomBytes(32);
  const keyId = randomBytes(8);
  const networkSecret = old
    ? fromBase64url(requireField(old, "SHAR_NETWORK_SECRET"))
    : randomBytes(32);
  const fallbackSecret = old
    ? fromBase64url(requireField(old, "SHAR_FALLBACK_SECRET"))
    : randomBytes(32);
  const adminSecret = old
    ? fromBase64url(requireField(old, "SHAR_ADMIN_SECRET"))
    : randomBytes(32);
  const siteVerifyMasterSecret = old
    ? fromBase64url(requireField(old, "SHAR_SITEVERIFY_MASTER_SECRET"))
    : randomBytes(32);
  const trustSeed = randomBytes(32);
  const trustKeyId = randomBytes(8);
  for (const [name, value] of [
    ["SHAR_NETWORK_SECRET", networkSecret],
    ["SHAR_FALLBACK_SECRET", fallbackSecret],
    ["SHAR_ADMIN_SECRET", adminSecret],
    ["SHAR_SITEVERIFY_MASTER_SECRET", siteVerifyMasterSecret],
  ]) {
    if (value.length !== 32) throw new Error(`${name} must decode to 32 bytes`);
  }

  console.error(
    `${old ? "generating" : "generating"} a 2048-bit RSW modulus; this can take a while`,
  );
  const p = await generatePrime(1024);
  let q;
  let modulus;
  do {
    q = await generatePrime(1024);
    modulus = p * q;
  } while (q === p || bitLength(modulus) !== 2048);
  const lambda = lcm(p - 1n, q - 1n);
  const modulusBytes = bigintBytes(modulus, 256);
  const modulusId = `rsw-${base64url(await sha256(modulusBytes).then((value) => value.slice(0, 12)))}`;
  const result = {
    SHAR_SIGNING_SEED: base64url(signingSeed),
    SHAR_KEY_ID: base64url(keyId),
    SHAR_RSW_MODULUS: base64url(modulusBytes),
    SHAR_RSW_LAMBDA: base64url(bigintBytes(lambda)),
    SHAR_RSW_ID: modulusId,
    SHAR_NETWORK_SECRET: base64url(networkSecret),
    SHAR_FALLBACK_SECRET: base64url(fallbackSecret),
    SHAR_ADMIN_SECRET: base64url(adminSecret),
    SHAR_SITEVERIFY_MASTER_SECRET: base64url(siteVerifyMasterSecret),
    SHAR_TRUST_SEED: base64url(trustSeed),
    SHAR_TRUST_KEY_ID: base64url(trustKeyId),
  };
  if (old) {
    const oldTrustSeed = old.SHAR_TRUST_SEED;
    const oldTrustKeyId = old.SHAR_TRUST_KEY_ID;
    if ((oldTrustSeed === undefined) !== (oldTrustKeyId === undefined))
      throw new Error(
        "old key file must contain both SHAR_TRUST_SEED and SHAR_TRUST_KEY_ID",
      );
    if (oldTrustSeed !== undefined) {
      const oldTrustSeedBytes = fromBase64url(oldTrustSeed);
      const oldTrustKeyIdBytes = fromBase64url(oldTrustKeyId);
      if (oldTrustSeedBytes.length !== 32)
        throw new Error("old SHAR_TRUST_SEED must decode to 32 bytes");
      if (oldTrustKeyIdBytes.length < 1 || oldTrustKeyIdBytes.length > 32)
        throw new Error("old SHAR_TRUST_KEY_ID must decode to 1..32 bytes");
    }
    const oldSeed = fromBase64url(requireField(old, "SHAR_SIGNING_SEED"));
    const oldKeyId = requireField(old, "SHAR_KEY_ID");
    const oldKeyIdBytes = fromBase64url(oldKeyId);
    const oldModulus = fromBase64url(requireField(old, "SHAR_RSW_MODULUS"));
    const oldLambda = fromBase64url(requireField(old, "SHAR_RSW_LAMBDA"));
    const oldModulusValue = bytesToBigint(oldModulus);
    const oldLambdaValue = bytesToBigint(oldLambda);
    if (oldSeed.length !== 32)
      throw new Error("old signing seed must decode to 32 bytes");
    if (oldKeyIdBytes.length < 1 || oldKeyIdBytes.length > 32)
      throw new Error("old key id must decode to 1..32 bytes");
    if (
      oldModulus.length !== 256 ||
      (oldModulus[0] ?? 0) < 0x80 ||
      (oldModulus.at(-1) ?? 0) % 2 === 0
    )
      throw new Error("old RSW modulus must decode to an odd 2048-bit value");
    if (
      oldLambda.length < 1 ||
      oldLambdaValue <= 1n ||
      oldLambdaValue >= oldModulusValue
    )
      throw new Error("old RSW lambda must satisfy 1 < lambda < modulus");
    const oldPublic = await publicFromSeed(oldSeed, "typescript");
    result.SHAR_PREVIOUS_VERIFY_KEYS = JSON.stringify(
      prepend(old.SHAR_PREVIOUS_VERIFY_KEYS, {
        kid: oldKeyId,
        x: base64url(oldPublic),
      }),
    );
    result.SHAR_PREVIOUS_RSW_KEYS = JSON.stringify(
      prepend(old.SHAR_PREVIOUS_RSW_KEYS, {
        id: requireField(old, "SHAR_RSW_ID"),
        modulus: requireField(old, "SHAR_RSW_MODULUS"),
        lambda: requireField(old, "SHAR_RSW_LAMBDA"),
      }),
    );
    if (oldTrustSeed !== undefined) {
      result.SHAR_PREVIOUS_TRUST_KEYS = JSON.stringify(
        prepend(old.SHAR_PREVIOUS_TRUST_KEYS, {
          seed: oldTrustSeed,
          key_id: oldTrustKeyId,
        }),
      );
    } else if (old.SHAR_PREVIOUS_TRUST_KEYS) {
      result.SHAR_PREVIOUS_TRUST_KEYS = old.SHAR_PREVIOUS_TRUST_KEYS;
    }
  }
  return result;
}

function parseArgs(argumentsList) {
  const command =
    argumentsList[0] === "rotate" || argumentsList[0] === "site-secret"
      ? argumentsList[0]
      : "generate";
  const start = command === "generate" ? 0 : 1;
  const values = new Map();
  for (let index = start; index < argumentsList.length; index += 2) {
    const flag = argumentsList[index];
    const value = argumentsList[index + 1];
    if (!flag?.startsWith("--") || value === undefined) usage(command);
    if (values.has(flag)) usage(command);
    values.set(flag, value);
  }
  if (command === "site-secret") {
    if (!values.get("--tenant") || !values.get("--site-key")) usage(command);
    return {
      command,
      keyFile: values.get("--key-file"),
      tenant: values.get("--tenant"),
      siteKey: values.get("--site-key"),
    };
  }
  const input = values.get("--input");
  const output = values.get("--output");
  if (
    !output ||
    (command === "rotate" && !input) ||
    (command === "generate" && input)
  )
    usage(command);
  return { command, input, output };
}

function usage(command) {
  throw new Error(
    command === "rotate"
      ? "usage: npm run keygen:js -- rotate --input OLD_PATH --output NEW_PATH"
      : command === "site-secret"
        ? "usage: npm run keygen:js -- site-secret --key-file PATH --tenant TENANT --site-key SITE"
        : "usage: npm run keygen:js -- --output PATH",
  );
}

async function readKeyDocument(path) {
  if (!path) throw new Error("a mode-0600 key file is required");
  const metadata = await stat(path);
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0)
    throw new Error("key file must not be accessible by group or other users");
  const value = JSON.parse(await readFile(path, "utf8"));
  if (!value || Array.isArray(value) || typeof value !== "object")
    throw new Error("key file must contain a JSON object");
  for (const item of Object.values(value))
    if (typeof item !== "string")
      throw new Error("key file values must be strings");
  return value;
}

function requireField(document, name) {
  const value = document?.[name];
  if (typeof value !== "string" || value.length === 0)
    throw new Error(`key file does not contain ${name}`);
  return value;
}

function prepend(encoded, entry) {
  let values = [];
  if (encoded !== undefined) {
    try {
      values = JSON.parse(encoded);
    } catch {
      throw new Error("previous key lists must be JSON arrays");
    }
    if (!Array.isArray(values))
      throw new Error("previous key lists must be JSON arrays");
  }
  return [
    entry,
    ...values.filter(
      (value) => JSON.stringify(value) !== JSON.stringify(entry),
    ),
  ];
}

async function writeDocument(path, document) {
  if (!path) throw new Error("output path is required");
  const file = await open(path, "wx", 0o600);
  try {
    await file.writeFile(`${JSON.stringify(document, null, 2)}\n`, "utf8");
    await file.sync();
  } finally {
    await file.close();
  }
}

function randomBytes(length) {
  const value = new Uint8Array(length);
  cryptoSource.getRandomValues(value);
  return value;
}

function randomBelow(limit) {
  const bytes = Math.ceil(bitLength(limit) / 8);
  const range = 1n << BigInt(bytes * 8);
  const limitRange = range - (range % limit);
  while (true) {
    const value = bytesToBigint(randomBytes(bytes));
    if (value < limitRange) return value % limit;
  }
}

async function generatePrime(bits) {
  while (true) {
    const bytes = randomBytes(Math.ceil(bits / 8));
    bytes[0] |= 0x80;
    bytes[bytes.length - 1] |= 1;
    const candidate = bytesToBigint(bytes);
    if (smallPrimeReject(candidate) || !(await probablePrime(candidate, 64)))
      continue;
    return candidate;
  }
}

function smallPrimeReject(value) {
  for (const prime of [
    3n,
    5n,
    7n,
    11n,
    13n,
    17n,
    19n,
    23n,
    29n,
    31n,
    37n,
    41n,
    43n,
    47n,
  ]) {
    if (value === prime) return false;
    if (value % prime === 0n) return true;
  }
  return false;
}

async function probablePrime(value, rounds) {
  if (value < 2n || value % 2n === 0n) return value === 2n;
  let d = value - 1n;
  let s = 0;
  while (d % 2n === 0n) {
    d /= 2n;
    s++;
  }
  for (let round = 0; round < rounds; round++) {
    const base = 2n + randomBelow(value - 3n);
    let x = modPow(base, d, value);
    if (x === 1n || x === value - 1n) continue;
    let witness = true;
    for (let index = 1; index < s; index++) {
      x = (x * x) % value;
      if (x === value - 1n) {
        witness = false;
        break;
      }
    }
    if (witness) return false;
  }
  return true;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

function gcd(a, b) {
  while (b) [a, b] = [b, a % b];
  return a;
}
function lcm(a, b) {
  return (a / gcd(a, b)) * b;
}
function bitLength(value) {
  return value.toString(2).length;
}
function bytesToBigint(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}
function bigintBytes(value, width) {
  const output = [];
  while (value > 0n) {
    output.push(Number(value & 255n));
    value >>= 8n;
  }
  output.reverse();
  const bytes = new Uint8Array(width ?? (output.length || 1));
  if (output.length > bytes.length) throw new Error("bigint_width");
  bytes.set(output, bytes.length - output.length);
  return bytes;
}
async function sha256(bytes) {
  return new Uint8Array(await cryptoSource.subtle.digest("SHA-256", bytes));
}
async function deriveSiteSecret(master, tenant, siteKey) {
  const encoder = new TextEncoder();
  const tenantBytes = encoder.encode(tenant);
  const siteBytes = encoder.encode(siteKey);
  if (
    !tenantBytes.length ||
    tenantBytes.length > 128 ||
    !siteBytes.length ||
    siteBytes.length > 256
  )
    throw new Error("invalid_site_scope");
  const body = new Uint8Array(5 + tenantBytes.length + siteBytes.length);
  body[0] = 1;
  body[1] = tenantBytes.length >>> 8;
  body[2] = tenantBytes.length;
  body.set(tenantBytes, 3);
  const offset = 3 + tenantBytes.length;
  body[offset] = siteBytes.length >>> 8;
  body[offset + 1] = siteBytes.length;
  body.set(siteBytes, offset + 2);
  const key = await cryptoSource.subtle.importKey(
    "raw",
    master,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const tag = new Uint8Array(
    await cryptoSource.subtle.sign(
      "HMAC",
      key,
      new Uint8Array([...encoder.encode("shar/siteverify/v1\0"), ...body]),
    ),
  );
  return `shrs1_${base64url(new Uint8Array([...body, ...tag]))}`;
}
