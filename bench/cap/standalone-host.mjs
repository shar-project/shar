import { spawn } from "node:child_process";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { closeSync, existsSync, openSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { environment, manifest, workspace } from "./lib.mjs";

const root = fileURLToPath(workspace);
const config = configuration();
const capDirectory = resolve(
  root,
  config.cap_directory ?? ".bench/cap/source/standalone/standalone",
);
const rustServer = resolve(
  root,
  config.rust_server ?? "target/release/shar-server",
);
const keygen = resolve(root, config.keygen ?? "target/release/shar-keygen");
const javascriptServer = resolve(
  root,
  config.javascript_server ?? "standalone/js/server.mjs",
);
const adminIndex = resolve(root, "dist/admin/index.html");
const bun = config.bun ?? "bun";
const node = config.node ?? process.execPath;
const temporary = await mkdtemp(join(tmpdir(), "shar-cap-host-"));
const keyFile = join(temporary, "keys.json");
const capLog = join(temporary, "cap.log");
const sharLog = join(temporary, "shar.log");
const capSettings = {
  challengeCount: 80,
  saltSize: 32,
  difficulty: 4,
  instrumentation: false,
  rsw: config.cap_protocol === "rsw",
  ...(config.cap_protocol === "rsw" ? { rswT: 75_000 } : {}),
};
const pinned = await manifest();
let cap;
let shar;
let controller;
let stopping;

try {
  requireInputs();
  await run(keygen, ["--output", keyFile]);
  cap = startProcess(
    bun,
    ["src/index.js"],
    capDirectory,
    {
      ADMIN_KEY: "shar-cap-benchmark-admin",
      REDIS_URL: config.redis_url,
      REDIS_PREFIX: `shar-isolated:${randomUUID()}:`,
      SERVER_HOSTNAME: "127.0.0.1",
      SERVER_PORT: String(config.cap_port),
      DISABLE_ERROR_LOGGING: "true",
      HIDE_RATELIMIT_IP_WARNING: "true",
    },
    capLog,
  );
  await waitForUrl(new URL(`http://127.0.0.1:${config.cap_port}/`), cap);
  const siteKey = await configureCap();
  const common = {
    SHAR_INSECURE_DEVELOPMENT: "1",
    SHAR_KEY_FILE: keyFile,
    SHAR_ALLOWED_ORIGINS: config.origin,
    SHAR_DATABASE: join(temporary, "shar.sqlite"),
    SHAR_LISTEN: `127.0.0.1:${config.shar_port}`,
    SHAR_REQUEST_LOG: "0",
    SHAR_MAX_CONCURRENT_REQUESTS: "65536",
    SHAR_STATE_TIMEOUT_MS: "5000",
  };
  if (config.shar_state === "redis") common.SHAR_REDIS_URL = config.redis_url;
  shar =
    config.variant === "rust"
      ? startProcess(rustServer, [], root, common, sharLog)
      : startProcess(node, [javascriptServer], root, common, sharLog);
  await waitForUrl(
    new URL(`http://127.0.0.1:${config.shar_port}/readyz`),
    shar,
  );
  await warmup(siteKey);
  await Promise.all([stabilizeRss(cap), stabilizeRss(shar)]);
  const idle = {
    shar_rss_bytes: await processRss(shar),
    cap_rss_bytes: await processRss(cap),
  };
  const serverManifest = {
    schema: "shar-cap-isolated-host-v1",
    controller_id: randomUUID(),
    revision: config.revision,
    variant: config.variant,
    state: config.shar_state,
    cap_settings: capSettings,
    cap: pinned,
    server_environment: environment(),
    idle_memory: idle,
    artifacts: {
      host_controller_sha256: await sha256File(fileURLToPath(import.meta.url)),
      shar_server_sha256: await sha256File(
        config.variant === "rust" ? rustServer : javascriptServer,
      ),
      cap_entry_sha256: await sha256File(join(capDirectory, "src/index.js")),
      admin_index_sha256: await sha256File(adminIndex),
    },
    endpoints: {
      shar: `http://127.0.0.1:${config.shar_port}`,
      cap: `http://127.0.0.1:${config.cap_port}/${siteKey}/`,
      control: `http://127.0.0.1:${config.control_port}`,
    },
    isolation: {
      bind: "loopback_only",
      controller_authentication: "bearer_token",
      process_model: "fresh_cap_and_shar_processes",
      rss: "server_host_linux_proc_vm_rss",
      redis_process_included: false,
    },
  };
  controller = createController(serverManifest);
  await listen(controller, config.control_port);
  process.stdout.write(
    `SHAR_BENCH_HOST_READY ${Buffer.from(
      JSON.stringify(serverManifest),
    ).toString("base64url")}\n`,
  );
  await new Promise((resolvePromise) => {
    const stop = () => void shutdown().then(resolvePromise);
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    process.once("SIGHUP", stop);
    controller.once("close", resolvePromise);
  });
} catch (error) {
  const diagnostics = await processDiagnostics();
  process.stderr.write(
    `${error instanceof Error ? (error.stack ?? error.message) : String(error)}${
      diagnostics ? `\n${diagnostics}` : ""
    }\n`,
  );
  process.exitCode = 1;
} finally {
  await shutdown();
}

function configuration() {
  const encoded = process.env.SHAR_BENCH_HOST_CONFIG_B64;
  if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded))
    throw new Error(
      "SHAR_BENCH_HOST_CONFIG_B64 is required and must be base64url",
    );
  let value;
  try {
    value = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    throw new Error("SHAR_BENCH_HOST_CONFIG_B64 must encode a JSON object");
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("isolated host configuration must be an object");
  const choice = (name, values) => {
    if (!values.includes(value[name]))
      throw new Error(`${name} must be ${values.join(" or ")}`);
    return value[name];
  };
  const port = (name) => {
    const item = value[name];
    if (!Number.isSafeInteger(item) || item < 1 || item > 65_535)
      throw new Error(`${name} must be a valid TCP port`);
    return item;
  };
  const token = value.control_token;
  if (typeof token !== "string" || token.length < 32 || token.length > 256)
    throw new Error("control_token must contain 32..256 characters");
  const revision = value.revision;
  if (typeof revision !== "string" || !/^[0-9a-f]{40}$/.test(revision))
    throw new Error("revision must be a full lowercase Git commit ID");
  const redis = new URL(value.redis_url);
  if (!["redis:", "rediss:"].includes(redis.protocol))
    throw new Error("redis_url must use redis: or rediss:");
  const origin = new URL(value.origin ?? "http://localhost:3000");
  if (
    !["http:", "https:"].includes(origin.protocol) ||
    origin.origin !== origin.href.replace(/\/$/, "")
  )
    throw new Error("origin must be an HTTP(S) origin without a path");
  const result = {
    ...value,
    variant: choice("variant", ["rust", "javascript"]),
    shar_state: choice("shar_state", ["redis", "sqlite"]),
    cap_protocol: choice("cap_protocol", ["sha", "rsw"]),
    cap_port: port("cap_port"),
    shar_port: port("shar_port"),
    control_port: port("control_port"),
    control_token: token,
    revision,
    redis_url: redis.href,
    origin: origin.origin,
  };
  if (
    new Set([result.cap_port, result.shar_port, result.control_port]).size !== 3
  )
    throw new Error("cap_port, shar_port, and control_port must be distinct");
  return result;
}

function requireInputs() {
  for (const path of [
    join(capDirectory, "src/index.js"),
    join(capDirectory, "node_modules"),
    keygen,
    adminIndex,
    config.variant === "rust" ? rustServer : javascriptServer,
  ]) {
    if (!existsSync(path))
      throw new Error(`required benchmark input is missing: ${path}`);
  }
}

function startProcess(command, args, cwd, environmentValues, logPath) {
  const log = openSync(logPath, "a");
  let child;
  try {
    child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...environmentValues },
      stdio: ["ignore", log, log],
    });
  } finally {
    closeSync(log);
  }
  child.benchmarkLog = logPath;
  child.benchmarkError = undefined;
  child.once("error", (error) => {
    child.benchmarkError = error;
  });
  return child;
}

async function run(command, args) {
  const child = spawn(command, args, { cwd: root, stdio: "inherit" });
  await new Promise((resolvePromise, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} exited ${code ?? signal}`));
    });
  });
}

async function waitForUrl(url, child) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.benchmarkError)
      throw new Error(`${url.origin} failed to start: ${child.benchmarkError}`);
    if (child.exitCode !== null) {
      const log = await readFile(child.benchmarkLog, "utf8").catch(() => "");
      throw new Error(`${url.origin} exited before readiness: ${log}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
    } catch {}
    await delay(100);
  }
  throw new Error(`${url.href} did not become ready`);
}

async function configureCap() {
  const login = await jsonRequest(
    new URL(`http://127.0.0.1:${config.cap_port}/auth/login`),
    { admin_key: "shar-cap-benchmark-admin" },
  );
  const authorization = `Bearer ${Buffer.from(
    JSON.stringify({ token: login.session_token, hash: login.hashed_token }),
  ).toString("base64")}`;
  const created = await jsonRequest(
    new URL(`http://127.0.0.1:${config.cap_port}/server/keys`),
    {
      name: "Shar isolated pinned comparison",
      instrumentation: false,
      blockAutomatedBrowsers: false,
      corsOrigins: [config.origin],
      rsw: capSettings.rsw,
      ...(capSettings.rsw ? { rswT: capSettings.rswT } : {}),
    },
    authorization,
  );
  await jsonRequest(
    new URL(
      `http://127.0.0.1:${config.cap_port}/server/keys/${created.siteKey}/config`,
    ),
    {
      difficulty: capSettings.difficulty,
      challengeCount: capSettings.challengeCount,
      instrumentation: false,
      obfuscationLevel: 3,
      blockAutomatedBrowsers: false,
      ratelimitMax: 10_000,
      ratelimitDuration: 3_600_000,
      corsOrigins: [config.origin],
      blockNonBrowserUA: false,
      requiredHeaders: [],
      rsw: capSettings.rsw,
      ...(capSettings.rsw ? { rswT: capSettings.rswT } : {}),
    },
    authorization,
    "PUT",
  );
  return created.siteKey;
}

async function warmup(siteKey) {
  for (let index = 0; index < 25; index++) {
    const [sharResponse, capResponse] = await Promise.all([
      fetch(`http://127.0.0.1:${config.shar_port}/v1/challenges`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: config.origin },
        body: JSON.stringify({
          tenant: "benchmark-warmup",
          site_key: "benchmark",
          action: `warmup-${index}`,
          origin: config.origin,
        }),
      }),
      fetch(`http://127.0.0.1:${config.cap_port}/${siteKey}/challenge`, {
        method: "POST",
        headers: {
          origin: config.origin,
          "user-agent": "Mozilla/5.0 Shar-Cap-Benchmark/1.0",
        },
      }),
    ]);
    if (!sharResponse.ok || !capResponse.ok)
      throw new Error(
        `warmup failed: Shar ${sharResponse.status}, Cap ${capResponse.status}`,
      );
  }
}

async function processRss(child) {
  if (!child || child.exitCode !== null)
    throw new Error("cannot sample an exited benchmark process");
  const status = await readFile(`/proc/${child.pid}/status`, "utf8");
  const match = /^VmRSS:\s+(\d+)\s+kB$/m.exec(status);
  if (!match) throw new Error(`cannot sample RSS for PID ${child.pid}`);
  return Number(match[1]) * 1024;
}

async function stabilizeRss(child) {
  const deadline = Date.now() + 15_000;
  const recent = [];
  while (Date.now() < deadline) {
    recent.push(await processRss(child));
    if (recent.length > 5) recent.shift();
    if (
      recent.length === 5 &&
      (Math.max(...recent) - Math.min(...recent)) / Math.max(...recent) <= 0.02
    )
      return;
    await delay(250);
  }
  throw new Error(`RSS did not stabilize for PID ${child.pid}`);
}

function createController(serverManifest) {
  return createServer(async (request, response) => {
    try {
      if (!authenticated(request.headers.authorization)) {
        respond(response, 401, { code: "unauthorized" });
        return;
      }
      if (request.method === "GET" && request.url === "/manifest") {
        respond(response, 200, serverManifest);
        return;
      }
      if (request.method === "GET" && request.url === "/rss/shar") {
        respond(response, 200, { rss_bytes: await processRss(shar) });
        return;
      }
      if (request.method === "GET" && request.url === "/rss/cap") {
        respond(response, 200, { rss_bytes: await processRss(cap) });
        return;
      }
      if (request.method === "POST" && request.url === "/shutdown") {
        respond(response, 202, { stopping: true });
        setImmediate(() => void shutdown());
        return;
      }
      respond(response, 404, { code: "not_found" });
    } catch (error) {
      respond(response, 503, {
        code: "controller_error",
        message: error instanceof Error ? error.message : "unknown error",
      });
    }
  });
}

function authenticated(header) {
  const expected = Buffer.from(`Bearer ${config.control_token}`);
  const actual = Buffer.from(header ?? "");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function respond(response, status, body) {
  const bytes = Buffer.from(JSON.stringify(body));
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(bytes.length),
    "cache-control": "no-store",
  });
  response.end(bytes);
}

async function listen(server, port) {
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolvePromise);
  });
}

async function jsonRequest(url, body, authorization, method = "POST") {
  const response = await fetch(url, {
    method,
    headers: {
      "content-type": "application/json",
      ...(authorization ? { authorization } : {}),
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5_000),
  });
  const value = await response.json();
  if (!response.ok || value.success === false)
    throw new Error(
      `${url.pathname} returned ${response.status}: ${JSON.stringify(value)}`,
    );
  return value;
}

async function sha256File(path) {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

async function processDiagnostics() {
  const values = [];
  for (const [name, child] of [
    ["Cap", cap],
    ["Shar", shar],
  ]) {
    if (!child?.benchmarkLog) continue;
    const log = await readFile(child.benchmarkLog, "utf8").catch(() => "");
    if (log) values.push(`${name} log:\n${log.slice(-8_192)}`);
  }
  return values.join("\n");
}

async function stopProcess(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  const exited = new Promise((resolvePromise) =>
    child.once("exit", resolvePromise),
  );
  if (
    await Promise.race([
      exited.then(() => true),
      delay(5_000).then(() => false),
    ])
  )
    return;
  child.kill("SIGKILL");
  await exited;
}

async function shutdown() {
  if (stopping) return stopping;
  stopping = (async () => {
    if (controller?.listening)
      await new Promise((resolvePromise) => controller.close(resolvePromise));
    await stopProcess(shar);
    await stopProcess(cap);
    if (temporary.startsWith(join(tmpdir(), "shar-cap-host-")))
      await rm(temporary, { recursive: true, force: true });
  })();
  return stopping;
}

function delay(milliseconds) {
  return new Promise((resolvePromise) =>
    setTimeout(resolvePromise, milliseconds),
  );
}
