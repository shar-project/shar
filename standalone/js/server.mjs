import { createServer } from "node:http";
import process from "node:process";
import { readFileSync, statSync } from "node:fs";
import { extname } from "node:path";
import {
  PostgresStore,
  RedisStore,
  BufferedAuditStore,
  SharService,
  base64url,
  createSharHandler,
  DailyNetworkPseudonymizer,
  deriveTrustKeyPair,
  fromBase64url,
  bytesToBigint,
  publicFromSeed,
  validateTimeLockKey,
} from "../../dist/packages/server/src/index.js";
import { SqliteStore } from "./sqlite.mjs";
import {
  clientAddress,
  isTrustedProxy,
  parseTrustedProxyCidrs,
} from "./proxy.mjs";
import { parseListenAddress } from "./listen.mjs";
import { parseAllowedOrigins } from "./origins.mjs";
import {
  canonicalAdminRoot,
  decodeAdminRelative,
  resolveAdminAsset,
} from "./admin-assets.mjs";

function startupFailure(error) {
  const message =
    error instanceof Error ? error.message : "unknown startup failure";
  console.error(message);
  process.exit(78);
}
process.once("uncaughtException", startupFailure);
process.once("unhandledRejection", startupFailure);

function loadKeyFile() {
  const path = process.env.SHAR_KEY_FILE;
  if (!path) return {};
  const stat = statSync(path);
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
    throw new Error(
      "SHAR_KEY_FILE must not be accessible by group or other users",
    );
  const value = JSON.parse(readFileSync(path, "utf8"));
  if (
    !value ||
    Array.isArray(value) ||
    typeof value !== "object" ||
    Object.values(value).some((item) => typeof item !== "string")
  )
    throw new Error(
      "SHAR_KEY_FILE must contain a JSON object of string values",
    );
  return value;
}
const keyFile = loadKeyFile();
function configured(name) {
  return process.env[name] ?? keyFile[name];
}
function required(name) {
  const value = configured(name);
  if (!value) throw new Error(`${name} is required`);
  return value;
}
function developmentKeys() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return {
    signing: { keyId: new Uint8Array([1]), privateSeed: seed },
    timeLock: {
      id: "development-only",
      modulus: 1_000_036_000_099n,
      lambda: 166_672_333_344n,
    },
  };
}
function parseTimeLock(id, modulusText, lambdaText, label = "RSW key") {
  const modulus = bytesToBigint(fromBase64url(modulusText));
  if (modulus.toString(2).length !== 2048 || modulus % 2n === 0n)
    throw new Error(`${label} modulus must be odd and exactly 2048 bits`);
  const lambda = bytesToBigint(fromBase64url(lambdaText));
  if (lambda <= 1n || lambda >= modulus)
    throw new Error(`${label} lambda must satisfy 1 < lambda < modulus`);
  if (typeof id !== "string" || id.length < 1 || id.length > 64)
    throw new Error(`${label} id must contain 1..64 bytes`);
  const key = { id, modulus, lambda };
  if (!validateTimeLockKey(key))
    throw new Error(`${label} trapdoor is inconsistent with its modulus`);
  return key;
}
function configuredKeys() {
  if (
    process.env.SHAR_INSECURE_DEVELOPMENT === "1" &&
    !configured("SHAR_SIGNING_SEED")
  ) {
    console.error(
      "WARNING: using an ephemeral signing key and tiny development-only RSW modulus",
    );
    return developmentKeys();
  }
  const seed = fromBase64url(required("SHAR_SIGNING_SEED"));
  if (seed.length !== 32)
    throw new Error("SHAR_SIGNING_SEED must decode to 32 bytes");
  const keyId = fromBase64url(required("SHAR_KEY_ID"));
  if (keyId.length < 1 || keyId.length > 32)
    throw new Error("SHAR_KEY_ID must decode to 1..32 bytes");
  return {
    signing: { keyId, privateSeed: seed },
    timeLock: parseTimeLock(
      required("SHAR_RSW_ID"),
      required("SHAR_RSW_MODULUS"),
      required("SHAR_RSW_LAMBDA"),
      "SHAR_RSW",
    ),
  };
}

function configuredTrustKeys() {
  const seedText = configured("SHAR_TRUST_SEED");
  const keyIdText = configured("SHAR_TRUST_KEY_ID");
  if (seedText === undefined && keyIdText === undefined) {
    return [];
  }
  if (seedText === undefined || keyIdText === undefined)
    throw new Error("configure both SHAR_TRUST_SEED and SHAR_TRUST_KEY_ID");
  const current = deriveTrustKey(seedText, keyIdText, "SHAR_TRUST");
  const previousText = configured("SHAR_PREVIOUS_TRUST_KEYS");
  const keys = [current];
  if (previousText !== undefined) {
    let previous;
    try {
      previous = JSON.parse(previousText);
    } catch {
      throw new Error("SHAR_PREVIOUS_TRUST_KEYS must be JSON");
    }
    if (!Array.isArray(previous))
      throw new Error("SHAR_PREVIOUS_TRUST_KEYS must be an array");
    previous.forEach((entry, index) => {
      if (
        !entry ||
        typeof entry !== "object" ||
        typeof entry.seed !== "string" ||
        typeof entry.key_id !== "string"
      )
        throw new Error(
          `SHAR_PREVIOUS_TRUST_KEYS[${index}] must contain seed and key_id strings`,
        );
      const key = deriveTrustKey(
        entry.seed,
        entry.key_id,
        `SHAR_PREVIOUS_TRUST_KEYS[${index}]`,
      );
      if (
        !keys.some(
          (existing) =>
            existing.keyId.length === key.keyId.length &&
            existing.keyId.every((byte, i) => byte === key.keyId[i]),
        )
      )
        keys.push(key);
    });
  }
  return keys;
}

function deriveTrustKey(seedText, keyIdText, label) {
  let seed;
  let keyId;
  try {
    seed = fromBase64url(seedText);
    keyId = fromBase64url(keyIdText);
  } catch {
    throw new Error(`${label} seed and key_id must be base64url`);
  }
  if (seed.length !== 32)
    throw new Error(`${label} seed must decode to 32 bytes`);
  if (keyId.length < 1 || keyId.length > 32)
    throw new Error(`${label} key_id must decode to 1..32 bytes`);
  try {
    return deriveTrustKeyPair(seed, keyId);
  } catch {
    throw new Error(`${label} seed or key_id is invalid`);
  }
}

const keys = configuredKeys();
const trustKeys = configuredTrustKeys();
function previousTimeLocks() {
  const text = configured("SHAR_PREVIOUS_RSW_KEYS");
  if (!text) return [];
  let values;
  try {
    values = JSON.parse(text);
  } catch {
    throw new Error("SHAR_PREVIOUS_RSW_KEYS must be JSON");
  }
  if (!Array.isArray(values))
    throw new Error("SHAR_PREVIOUS_RSW_KEYS must be an array");
  return values.map((value, index) => {
    if (
      !value ||
      typeof value !== "object" ||
      typeof value.id !== "string" ||
      typeof value.modulus !== "string" ||
      typeof value.lambda !== "string"
    )
      throw new Error(
        "SHAR_PREVIOUS_RSW_KEYS entries must contain id, modulus, and lambda strings",
      );
    return parseTimeLock(
      value.id,
      value.modulus,
      value.lambda,
      `SHAR_PREVIOUS_RSW_KEYS[${index}]`,
    );
  });
}
const previousRswKeys = previousTimeLocks();
function previousVerificationKeys() {
  const text = configured("SHAR_PREVIOUS_VERIFY_KEYS");
  if (!text) return [];
  let values;
  try {
    values = JSON.parse(text);
  } catch {
    throw new Error("SHAR_PREVIOUS_VERIFY_KEYS must be JSON");
  }
  if (!Array.isArray(values))
    throw new Error("SHAR_PREVIOUS_VERIFY_KEYS must be an array");
  return values.map((value) => {
    const keyId = fromBase64url(value.kid);
    if (keyId.length < 1 || keyId.length > 32)
      throw new Error("previous kid must decode to 1..32 bytes");
    const publicKey = fromBase64url(value.x);
    if (publicKey.length !== 32)
      throw new Error("previous x must decode to 32 bytes");
    return { keyId, publicKey };
  });
}
const verificationKeys = [
  {
    keyId: keys.signing.keyId,
    publicKey: await publicFromSeed(keys.signing.privateSeed),
  },
  ...previousVerificationKeys().filter(
    (key) =>
      !(
        key.keyId.length === keys.signing.keyId.length &&
        key.keyId.every((byte, index) => byte === keys.signing.keyId[index])
      ),
  ),
];
const random = {
  bytes(length) {
    const out = new Uint8Array(length);
    crypto.getRandomValues(out);
    return out;
  },
};
const requestLogging = process.env.SHAR_REQUEST_LOG ?? "1";
if (!new Set(["0", "1"]).has(requestLogging))
  throw new Error("SHAR_REQUEST_LOG must be 0 or 1");

const observedRoutes = new Set([
  "/.well-known/shar/v1",
  "/healthz",
  "/readyz",
  "/metrics",
  "/v1/challenges",
  "/v1/challenges/redeem",
  "/v1/siteverify",
  "/v1/fallback/complete",
  "/v1/admin/policy",
  "/v1/admin/audit",
]);
function newRequestId() {
  return base64url(random.bytes(16));
}
function observedMethod(method) {
  return ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"].includes(
    method,
  )
    ? method
    : "OTHER";
}
function observedRoute(rawUrl) {
  try {
    const pathname = new URL(rawUrl ?? "/", "http://shar.invalid").pathname;
    if (pathname === "/admin" || pathname.startsWith("/admin/"))
      return "/admin/*";
    return observedRoutes.has(pathname) ? pathname : "unmatched";
  } catch {
    return "unmatched";
  }
}
function admissionBypassUrl(rawUrl, method) {
  if (method !== "GET") return false;
  try {
    return ["/healthz", "/readyz", "/metrics"].includes(
      new URL(rawUrl ?? "/", "http://shar.invalid").pathname,
    );
  } catch {
    return false;
  }
}
function networkSecret() {
  const secret = configured("SHAR_NETWORK_SECRET");
  if (secret) {
    const value = fromBase64url(secret);
    if (value.length !== 32)
      throw new Error("SHAR_NETWORK_SECRET must decode to 32 bytes");
    return value;
  }
  if (process.env.SHAR_INSECURE_DEVELOPMENT !== "1")
    throw new Error("SHAR_NETWORK_SECRET is required");
  return random.bytes(32);
}
const pressureSecret = networkSecret();
const networkPseudonymizer = new DailyNetworkPseudonymizer(pressureSecret);
function fallbackSecret() {
  const text = configured("SHAR_FALLBACK_SECRET");
  if (!text) return undefined;
  const value = fromBase64url(text);
  if (value.length !== 32)
    throw new Error("SHAR_FALLBACK_SECRET must decode to 32 bytes");
  return value;
}
const hostFallbackSecret = fallbackSecret();
function presencePlan() {
  const mode = configured("SHAR_PRESENCE_MODE") ?? "none";
  if (!["none", "host"].includes(mode))
    throw new Error("SHAR_PRESENCE_MODE must be none or host");
  return { mode };
}
const hostPresence = presencePlan();
function fallbackMethods() {
  const text = configured("SHAR_FALLBACK_METHODS");
  if (!hostFallbackSecret) {
    if (text !== undefined)
      throw new Error("SHAR_FALLBACK_METHODS requires SHAR_FALLBACK_SECRET");
    return [];
  }
  return (text ?? "passkey,email,authenticated-session,support")
    .split(",")
    .map((method) => method.trim());
}
const hostFallbackMethods = fallbackMethods();
const hostFallbackPlan = {
  available: hostFallbackSecret !== undefined,
  methods: hostFallbackMethods,
};
function adminSecret() {
  const text = configured("SHAR_ADMIN_SECRET");
  if (!text) return undefined;
  const value = fromBase64url(text);
  if (value.length !== 32)
    throw new Error("SHAR_ADMIN_SECRET must decode to 32 bytes");
  return value;
}
const hostAdminSecret = adminSecret();
function siteVerifyMasterSecret() {
  const text = configured("SHAR_SITEVERIFY_MASTER_SECRET");
  if (!text) {
    if (process.env.SHAR_INSECURE_DEVELOPMENT === "1") return undefined;
    throw new Error("SHAR_SITEVERIFY_MASTER_SECRET is required");
  }
  const value = fromBase64url(text);
  if (value.length !== 32)
    throw new Error("SHAR_SITEVERIFY_MASTER_SECRET must decode to 32 bytes");
  return value;
}
const verifierMasterSecret = siteVerifyMasterSecret();
const trustedProxyCidrs = process.env.SHAR_TRUSTED_PROXY_CIDRS ?? "";
const trustedProxies = parseTrustedProxyCidrs(trustedProxyCidrs);
const hasTrustedProxy = trustedProxyCidrs
  .split(",")
  .some((cidr) => cidr.trim().length > 0);
function assuranceMode() {
  const mode = configured("SHAR_ASSURANCE_MODE") ?? "off";
  if (!new Set(["off", "trusted-header"]).has(mode))
    throw new Error("SHAR_ASSURANCE_MODE must be off or trusted-header");
  if (mode === "trusted-header" && !hasTrustedProxy)
    throw new Error(
      "SHAR_ASSURANCE_MODE=trusted-header requires SHAR_TRUSTED_PROXY_CIDRS",
    );
  return mode;
}
const hostAssuranceMode = assuranceMode();
function assuranceTier(request) {
  const value = request.headers.get("x-shar-assurance-tier");
  if (value === null) return undefined;
  if (!/^(?:0|[1-9]|[12][0-9]|3[0-2])$/.test(value)) return Number.NaN;
  return Number(value);
}
const allowed = parseAllowedOrigins(
  process.env.SHAR_ALLOWED_ORIGINS ?? "http://localhost:3000",
);
const listen = process.env.SHAR_LISTEN ?? "127.0.0.1:8080";
const { host, port } = parseListenAddress(listen);
function region() {
  const value = configured("SHAR_REGION");
  if (!value) return undefined;
  if (new TextEncoder().encode(value).length > 64 || /\p{Cc}/u.test(value))
    throw new Error(
      "SHAR_REGION must be a non-control value of at most 64 bytes",
    );
  return value;
}
const hostRegion = region();
function trustRetentionSeconds() {
  const value = configured("SHAR_TRUST_RETENTION_SECONDS") ?? "86400";
  if (!/^(?:0|[1-9][0-9]*)$/.test(value))
    throw new Error(
      "SHAR_TRUST_RETENTION_SECONDS must be an integer from 60 through 2592000",
    );
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds) || seconds < 60 || seconds > 2_592_000)
    throw new Error(
      "SHAR_TRUST_RETENTION_SECONDS must be an integer from 60 through 2592000",
    );
  return seconds;
}
const hostTrustRetentionSeconds = trustRetentionSeconds();
const maxConcurrentRequests = Number(
  process.env.SHAR_MAX_CONCURRENT_REQUESTS ?? "256",
);
if (
  !Number.isSafeInteger(maxConcurrentRequests) ||
  maxConcurrentRequests < 1 ||
  maxConcurrentRequests > 65_536
)
  throw new Error(
    "SHAR_MAX_CONCURRENT_REQUESTS must be an integer from 1 through 65536",
  );
const stateTimeoutMilliseconds = Number(
  process.env.SHAR_STATE_TIMEOUT_MS ?? "5000",
);
if (
  !Number.isSafeInteger(stateTimeoutMilliseconds) ||
  stateTimeoutMilliseconds < 100 ||
  stateTimeoutMilliseconds > 60_000
)
  throw new Error(
    "SHAR_STATE_TIMEOUT_MS must be an integer from 100 through 60000",
  );
const requestBodyTimeoutMilliseconds = Number(
  process.env.SHAR_REQUEST_BODY_TIMEOUT_MS ?? "15000",
);
if (
  !Number.isSafeInteger(requestBodyTimeoutMilliseconds) ||
  requestBodyTimeoutMilliseconds < 100 ||
  requestBodyTimeoutMilliseconds > 60_000
)
  throw new Error(
    "SHAR_REQUEST_BODY_TIMEOUT_MS must be an integer from 100 through 60000",
  );
const shutdownTimeoutMilliseconds = Number(
  process.env.SHAR_SHUTDOWN_TIMEOUT_MS ?? "25000",
);
if (
  !Number.isInteger(shutdownTimeoutMilliseconds) ||
  shutdownTimeoutMilliseconds < 6_000 ||
  shutdownTimeoutMilliseconds > 300_000
)
  throw new Error(
    "SHAR_SHUTDOWN_TIMEOUT_MS must be an integer from 6000 through 300000",
  );
let configStore;
let nonceStore;
let pressureStore;
let auditStore;
const closeStores = [];
if (process.env.SHAR_POSTGRES_URL) {
  const { Pool } = await import("pg");
  const postgresUrl = new URL(process.env.SHAR_POSTGRES_URL);
  const plaintextPostgres =
    postgresUrl.searchParams.get("sslmode") === "disable";
  if (plaintextPostgres && process.env.SHAR_INSECURE_DEVELOPMENT !== "1")
    throw new Error(
      "SHAR_POSTGRES_URL may set sslmode=disable only in insecure development",
    );
  const ssl = plaintextPostgres
    ? false
    : { rejectUnauthorized: true, minVersion: "TLSv1.2" };
  if (ssl && process.env.SHAR_POSTGRES_CA_FILE)
    ssl.ca = readFileSync(process.env.SHAR_POSTGRES_CA_FILE, "utf8");
  const pool = new Pool({
    connectionString: process.env.SHAR_POSTGRES_URL,
    max: 10,
    ssl,
    connectionTimeoutMillis: stateTimeoutMilliseconds,
    statement_timeout: stateTimeoutMilliseconds,
    query_timeout: stateTimeoutMilliseconds,
    lock_timeout: stateTimeoutMilliseconds,
    idle_in_transaction_session_timeout: stateTimeoutMilliseconds,
  });
  const postgres = new PostgresStore(pool);
  await postgres.migrate();
  configStore = postgres;
  nonceStore = postgres;
  pressureStore = postgres;
  auditStore = postgres;
  closeStores.push(() => pool.end());
} else {
  const sqlite = new SqliteStore(process.env.SHAR_DATABASE ?? "shar.sqlite", {
    busyTimeoutMilliseconds: stateTimeoutMilliseconds,
  });
  configStore = sqlite;
  nonceStore = sqlite;
  pressureStore = sqlite;
  auditStore = sqlite;
  closeStores.push(() => sqlite.close());
}
if (process.env.SHAR_REDIS_URL) {
  const redisUrl = new URL(process.env.SHAR_REDIS_URL);
  if (
    redisUrl.protocol !== "rediss:" &&
    process.env.SHAR_INSECURE_DEVELOPMENT !== "1"
  )
    throw new Error(
      "SHAR_REDIS_URL must use rediss outside insecure development",
    );
  const { createClient } = await import("redis");
  const redis = createClient({
    url: redisUrl.href,
    socket: {
      connectTimeout: stateTimeoutMilliseconds,
      reconnectStrategy: (retries) =>
        Math.min(50 * 2 ** Math.min(retries, 5), 1_000),
    },
    commandOptions: { timeout: stateTimeoutMilliseconds },
    disableOfflineQueue: true,
  });
  redis.on("error", (error) =>
    console.error(`Redis connection error: ${error.message}`),
  );
  await redis.connect();
  const atomic = new RedisStore(redis);
  nonceStore = atomic;
  pressureStore = atomic;
  auditStore = atomic;
  closeStores.push(() => redis.close());
}
let auditEventsDropped = 0;
const bufferedAuditStore = new BufferedAuditStore(auditStore, 4_096, () => {
  auditEventsDropped++;
});
auditStore = bufferedAuditStore;
const service = new SharService({
  ...keys,
  verificationKeys,
  previousTimeLocks: previousRswKeys,
  nonces: nonceStore,
  pressure: pressureStore,
  config: configStore,
  audit: auditStore,
  clock: { now: () => Math.floor(Date.now() / 1000) },
  random,
  presence: hostPresence,
  fallback: hostFallbackPlan,
  trust: trustKeys.length
    ? {
        keys: trustKeys,
        retentionSeconds: hostTrustRetentionSeconds,
      }
    : undefined,
});
const handler = createSharHandler(service, {
  allowedOrigins: allowed,
  maxBodyBytes: 16_384,
  region: () => hostRegion,
  fallbackSecret: hostFallbackSecret,
  fallbackMethods: hostFallbackSecret ? hostFallbackMethods : undefined,
  presence: hostPresence,
  adminSecret: hostAdminSecret,
  siteVerifyMasterSecret: verifierMasterSecret,
  auditEventsDropped: () => auditEventsDropped,
  networkPseudonym: async (request, challenge) => {
    const peer = request.headers.get("x-shar-peer");
    return peer
      ? networkPseudonymizer.pseudonym(
          new TextEncoder().encode(
            `${challenge.tenant}\0${challenge.site_key}\0${peer}`,
          ),
          Math.floor(Date.now() / 1000),
        )
      : undefined;
  },
  sessionBinding: (request) =>
    request.headers.get("x-shar-session-binding") ?? undefined,
  assuranceTier:
    hostAssuranceMode === "trusted-header" ? assuranceTier : undefined,
});
const adminRoot = canonicalAdminRoot(
  process.env.SHAR_ADMIN_ASSETS ?? "dist/admin",
);
const adminTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".map", "application/json; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);
function serveAdmin(req, res) {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? listen}`);
  if (url.pathname === "/admin") {
    res.writeHead(308, { location: "/admin/" });
    res.end();
    return true;
  }
  if (!url.pathname.startsWith("/admin/")) return false;
  const relative = decodeAdminRelative(url.pathname);
  if (!relative) return false;
  const path = resolveAdminAsset(adminRoot, relative);
  if (!path) return false;
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch {
    return false;
  }
  const immutable = relative !== "index.html";
  res.writeHead(200, {
    "content-type": adminTypes.get(extname(path)) ?? "application/octet-stream",
    "cache-control": immutable
      ? "public, max-age=31536000, immutable"
      : "no-cache",
    "content-security-policy":
      "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  res.end(req.method === "HEAD" ? undefined : bytes);
  return true;
}
let activeRequests = 0;
function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const cleanup = () => {
      clearTimeout(timer);
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("error", onError);
      req.off("aborted", onAborted);
    };
    const finish = (result) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onData = (chunk) => {
      size += chunk.length;
      if (size > 16_384) {
        finish({ outcome: "too_large" });
        req.resume();
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => finish({ outcome: "complete", chunks });
    const onError = (error) => fail(error);
    const onAborted = () => fail(new Error("request aborted"));
    const timer = setTimeout(() => {
      req.pause();
      finish({ outcome: "timeout" });
    }, requestBodyTimeoutMilliseconds);
    timer.unref();
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
    req.on("aborted", onAborted);
  });
}
const server = createServer(async (req, res) => {
  const requestId = newRequestId();
  const started = performance.now();
  res.setHeader("x-shar-request-id", requestId);
  const requestOrigin =
    typeof req.headers.origin === "string" ? req.headers.origin : undefined;
  const corsOrigin =
    requestOrigin && allowed.includes(requestOrigin)
      ? requestOrigin
      : undefined;
  const transportErrorHeaders = () => {
    const headers = {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-shar-request-id": requestId,
    };
    if (corsOrigin) {
      headers["access-control-allow-origin"] = corsOrigin;
      headers["access-control-expose-headers"] = "X-Shar-Request-Id";
      headers.vary = "Origin";
    }
    return headers;
  };
  res.once("finish", () => {
    if (requestLogging !== "1") return;
    console.error(
      JSON.stringify({
        version: "request-observation-v1",
        request_id: requestId,
        method: observedMethod(req.method ?? ""),
        route: observedRoute(req.url),
        status: res.statusCode,
        duration_ms: Math.max(0, Math.round(performance.now() - started)),
      }),
    );
  });
  const bypassAdmission = admissionBypassUrl(req.url, req.method);
  if (!bypassAdmission && activeRequests >= maxConcurrentRequests) {
    const responseHeaders = {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "retry-after": "1",
      "x-shar-request-id": requestId,
    };
    if (corsOrigin) {
      responseHeaders["access-control-allow-origin"] = corsOrigin;
      responseHeaders["access-control-expose-headers"] = "X-Shar-Request-Id";
      responseHeaders.vary = "Origin";
    }
    req.resume();
    res.writeHead(503, responseHeaders);
    res.end(
      JSON.stringify({
        code: "capacity_unavailable",
        retryable: true,
        next_action: "retry",
        retry_after: 1,
      }),
    );
    return;
  }
  if (!bypassAdmission) {
    activeRequests++;
    let released = false;
    const releaseAdmission = () => {
      if (released) return;
      released = true;
      activeRequests--;
    };
    res.once("finish", releaseAdmission);
    res.once("close", releaseAdmission);
  }
  try {
    if (["GET", "HEAD"].includes(req.method ?? "") && serveAdmin(req, res))
      return;
    const contentLength = Number(req.headers["content-length"] ?? 0);
    if (Number.isFinite(contentLength) && contentLength > 16_384) {
      req.resume();
      res.writeHead(413, transportErrorHeaders());
      res.end(
        JSON.stringify({
          code: "body_too_large",
          retryable: false,
          next_action: "none",
        }),
      );
      return;
    }
    const body = await readRequestBody(req);
    if (body.outcome === "too_large") {
      res.writeHead(413, transportErrorHeaders());
      res.end(
        JSON.stringify({
          code: "body_too_large",
          retryable: false,
          next_action: "none",
        }),
      );
      return;
    }
    if (body.outcome === "timeout") {
      res.writeHead(408, {
        ...transportErrorHeaders(),
        connection: "close",
        "retry-after": "1",
      });
      res.end(
        JSON.stringify({
          code: "request_body_timeout",
          retryable: true,
          next_action: "retry",
          retry_after: 1,
        }),
      );
      return;
    }
    const origin = `http://${req.headers.host ?? listen}`;
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
      if (Array.isArray(value))
        for (const item of value) headers.append(key, item);
      else if (value !== undefined) headers.set(key, value);
    }
    const forwarded = Array.isArray(req.headers["x-forwarded-for"])
      ? req.headers["x-forwarded-for"].join(",")
      : req.headers["x-forwarded-for"];
    const trustedPeer = isTrustedProxy(
      req.socket.remoteAddress ?? "unknown",
      trustedProxies,
    );
    headers.set(
      "x-shar-peer",
      clientAddress(
        req.socket.remoteAddress ?? "unknown",
        forwarded,
        trustedProxies,
      ),
    );
    if (!trustedPeer) headers.delete("x-shar-session-binding");
    if (!trustedPeer || hostAssuranceMode !== "trusted-header")
      headers.delete("x-shar-assurance-tier");
    const request = new Request(new URL(req.url ?? "/", origin), {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method ?? "")
        ? undefined
        : Buffer.concat(body.chunks),
    });
    const response = await handler(request);
    const responseHeaders = Object.fromEntries(response.headers);
    responseHeaders["x-shar-request-id"] = requestId;
    responseHeaders["x-content-type-options"] ??= "nosniff";
    responseHeaders["cache-control"] ??= "no-store";
    res.writeHead(response.status, responseHeaders);
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    res.writeHead(500, transportErrorHeaders());
    res.end(
      JSON.stringify({
        code: "internal_error",
        retryable: true,
        next_action: "retry",
      }),
    );
  }
});
server.once("error", (error) => {
  console.error(`cannot bind SHAR_LISTEN ${listen}: ${error.message}`);
  Promise.allSettled([
    bufferedAuditStore.flush(),
    ...closeStores.map((close) => close()),
  ]).finally(() => process.exit(78));
});
server.listen(port, host, () => {
  process.off("uncaughtException", startupFailure);
  process.off("unhandledRejection", startupFailure);
  console.error(`Shar JavaScript server listening on ${listen}`);
});
let stopping = false;
let shutdownForced = false;
let finalizing = false;
function finalizeShutdown() {
  if (finalizing) return;
  finalizing = true;
  Promise.allSettled([bufferedAuditStore.flush()])
    .then(async (flushResults) => [
      ...flushResults,
      ...(await Promise.allSettled(closeStores.map((close) => close()))),
    ])
    .then((results) =>
      process.exit(
        shutdownForced || results.some((result) => result.status === "rejected")
          ? 1
          : 0,
      ),
    );
}
function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  console.error(`received ${signal}; draining connections`);
  server.close(finalizeShutdown);
  server.closeIdleConnections();
  setTimeout(() => {
    shutdownForced = true;
    console.error("graceful request drain exceeded its bounded deadline");
    server.closeAllConnections();
    finalizeShutdown();
  }, shutdownTimeoutMilliseconds - 5_000).unref();
  setTimeout(() => process.exit(1), shutdownTimeoutMilliseconds);
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
