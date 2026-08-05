import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { closeSync, existsSync, openSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { format as formatSource } from "prettier";
import {
  distribution,
  evaluateAllRunGate,
  relativeStandardDeviation,
  run,
  workspace,
} from "./lib.mjs";

const root = fileURLToPath(workspace);
const capDirectory = resolve(root, ".bench/cap/source/standalone/standalone");
const redisUrl = requiredUrl("CAP_BENCH_REDIS_URL", ["redis:", "rediss:"]);
const origin = process.env.SHAR_BENCH_ORIGIN ?? "http://localhost:3000";
const repetitions = integer("SHAR_BENCH_REPETITIONS", 3, 1, 10);
const issueOperations = integer(
  "SHAR_BENCH_ISSUE_OPERATIONS",
  1_000,
  100,
  100_000,
);
const concurrency = integer("SHAR_BENCH_CONCURRENCY", 32, 1, 256);
const clientWorkers = integer(
  "SHAR_BENCH_CLIENT_WORKERS",
  1,
  1,
  Math.min(16, concurrency),
);
const actionCardinality = integer(
  "SHAR_BENCH_ACTION_CARDINALITY",
  1,
  1,
  issueOperations,
);
const solveSamples = integer("SHAR_BENCH_SAMPLES", 1, 1, 100);
const sharState = choice("SHAR_BENCH_SHAR_STATE", "redis", ["redis", "sqlite"]);
const capPort = integer("CAP_BENCH_PORT", 4210, 1, 65_534);
const sharPort = capPort + 1;
const capProtocol = choice("CAP_BENCH_PROTOCOL", "sha", ["sha", "rsw"]);
const outputDirectory = resolve(
  root,
  process.env.SHAR_BENCH_OUTPUT_DIR ??
    (capProtocol === "rsw" ? "bench/cap/results/rsw" : "bench/cap/results"),
);
const capSettings = {
  challengeCount: 80,
  saltSize: 32,
  difficulty: 4,
  instrumentation: false,
  rsw: capProtocol === "rsw",
  ...(capProtocol === "rsw" ? { rswT: 75_000 } : {}),
};

if (!existsSync(join(capDirectory, "node_modules")))
  throw new Error(
    "Cap Standalone dependencies are missing; run bun install --frozen-lockfile in the prepared standalone directory",
  );

await mkdir(outputDirectory, { recursive: true });
await run("npm", ["run", "build"]);
await run("cargo", [
  "build",
  "--locked",
  "--release",
  "--bin",
  "shar-server",
  "--bin",
  "shar-keygen",
]);

const temporary = await mkdtemp(join(tmpdir(), "shar-cap-standalone-"));
const stagedOutputDirectory = join(temporary, "results");
await mkdir(stagedOutputDirectory, { recursive: true });
const rows = [];
try {
  for (let repetition = 1; repetition <= repetitions; repetition++) {
    const order =
      repetition % 2 === 1 ? ["rust", "javascript"] : ["javascript", "rust"];
    for (const variant of order) {
      const result = await benchmarkPair(variant, repetition);
      rows.push({ variant, repetition, result });
    }
  }
} finally {
  if (temporary.startsWith(join(tmpdir(), "shar-cap-standalone-")))
    await rm(temporary, { recursive: true, force: true });
}

const variants = Object.fromEntries(
  ["rust", "javascript"].map((variant) => {
    const selected = rows.filter((row) => row.variant === variant);
    const sharThroughput = selected.map(
      (row) => row.result.issuance.shar.operations_per_second,
    );
    const capThroughput = selected.map(
      (row) => row.result.issuance.cap.operations_per_second,
    );
    const sharIdle = selected.map(
      (row) => row.result.idle_memory.shar_rss_bytes,
    );
    const capIdle = selected.map((row) => row.result.idle_memory.cap_rss_bytes);
    const throughputRatios = selected.map(
      (row) =>
        row.result.issuance.shar.operations_per_second /
        row.result.issuance.cap.operations_per_second,
    );
    const idleRatios = selected.map(
      (row) =>
        row.result.idle_memory.shar_rss_bytes /
        row.result.idle_memory.cap_rss_bytes,
    );
    return [
      variant,
      {
        repetitions: selected.length,
        shar_issuance_ops_per_second: numericDistribution(sharThroughput),
        cap_issuance_ops_per_second: numericDistribution(capThroughput),
        shar_idle_rss_bytes: numericDistribution(sharIdle),
        cap_idle_rss_bytes: numericDistribution(capIdle),
        per_run_throughput_ratio: numericDistribution(throughputRatios),
        per_run_idle_rss_ratio: numericDistribution(idleRatios),
        quality: {
          issuance_relative_standard_deviation: {
            shar: relativeStandardDeviation(sharThroughput),
            cap: relativeStandardDeviation(capThroughput),
          },
          idle_rss_relative_standard_deviation: {
            shar: relativeStandardDeviation(sharIdle),
            cap: relativeStandardDeviation(capIdle),
          },
          guidance:
            "values above 0.20 warrant more repetitions or a more isolated host; gate status still uses conservative all-run bounds",
        },
      },
    ];
  }),
);
const nativeRows = rows.filter((row) => row.variant === "rust");
const nativeThroughputRatios = nativeRows.map(
  (row) =>
    row.result.issuance.shar.operations_per_second /
    row.result.issuance.cap.operations_per_second,
);
const nativeIdleRatios = nativeRows.map(
  (row) =>
    row.result.idle_memory.shar_rss_bytes /
    row.result.idle_memory.cap_rss_bytes,
);
const summary = {
  schema: "shar-cap-local-standalone-comparison-v1",
  captured_at: new Date().toISOString(),
  scope: {
    status: "local_reference_only",
    cap: "standalone@3.1.8",
    shar_variants: ["optimized Rust", "production JavaScript"],
    state:
      sharState === "redis"
        ? "Cap and Shar use the same external Redis service for atomic state; Shar retains its documented SQLite config store"
        : "Shar uses its default SQLite WAL state while Cap uses its required external Redis service",
    isolation:
      "fresh Cap and Shar processes, fresh key/config state, stabilized process RSS, alternating Rust/JavaScript order per repetition",
    exclusions: [
      "Redis process memory",
      "container runtime overhead",
      "managed-store network latency",
      "energy and accelerated browser solve cost",
    ],
  },
  inputs: {
    repetitions,
    issue_operations: issueOperations,
    concurrency,
    http_client_workers: clientWorkers,
    shar_action_cardinality: actionCardinality,
    shar_state: sharState,
    solve_samples: solveSamples,
    cap_settings: capSettings,
  },
  variants,
  local_native_thresholds: {
    throughput_at_least_2x_cap: {
      ...evaluateAllRunGate(nativeThroughputRatios, 2, "minimum"),
    },
    idle_memory_at_most_half_cap: {
      ...evaluateAllRunGate(nativeIdleRatios, 0.5, "maximum"),
    },
  },
  raw_results: rows.map(
    ({ variant, repetition }) => `${variant}-${repetition}.json`,
  ),
};
// Do not disturb the last complete evidence set when a benchmark process or
// request fails. Raw files are staged under the run's temporary directory and
// published only after every paired run has passed validation; the summary is
// committed last so it never points at a partially refreshed set.
for (const { variant, repetition, result } of rows)
  await writeJson(
    join(outputDirectory, `${variant}-${repetition}.json`),
    result,
  );
await writeJson(
  join(outputDirectory, "local-standalone-comparison.json"),
  summary,
);
console.log(JSON.stringify(summary, null, 2));

async function benchmarkPair(variant, repetition) {
  const label = `${variant}-${repetition}`;
  const directory = join(temporary, label);
  await mkdir(directory, { recursive: true });
  const keyFile = join(directory, "keys.json");
  await run(resolve(root, "target/release/shar-keygen"), ["--output", keyFile]);
  const cap = startProcess(
    "bun",
    ["src/index.js"],
    capDirectory,
    {
      ADMIN_KEY: "shar-cap-benchmark-admin",
      REDIS_URL: redisUrl.href,
      REDIS_PREFIX: `shar-bench:${randomUUID()}:`,
      SERVER_HOSTNAME: "127.0.0.1",
      SERVER_PORT: String(capPort),
      DISABLE_ERROR_LOGGING: "true",
      HIDE_RATELIMIT_IP_WARNING: "true",
    },
    join(directory, "cap.log"),
  );
  let shar;
  try {
    await waitForUrl(new URL(`http://127.0.0.1:${capPort}/`), cap);
    const siteKey = await configureCap();
    const common = {
      SHAR_INSECURE_DEVELOPMENT: "1",
      SHAR_KEY_FILE: keyFile,
      SHAR_ALLOWED_ORIGINS: origin,
      SHAR_DATABASE: join(directory, "shar.sqlite"),
      SHAR_LISTEN: `127.0.0.1:${sharPort}`,
      SHAR_REQUEST_LOG: "0",
      SHAR_MAX_CONCURRENT_REQUESTS: "65536",
      SHAR_STATE_TIMEOUT_MS: "5000",
    };
    if (sharState === "redis") common.SHAR_REDIS_URL = redisUrl.href;
    shar =
      variant === "rust"
        ? startProcess(
            resolve(root, "target/release/shar-server"),
            [],
            root,
            common,
            join(directory, "shar.log"),
          )
        : startProcess(
            process.execPath,
            ["standalone/js/server.mjs"],
            root,
            common,
            join(directory, "shar.log"),
          );
    await waitForUrl(new URL(`http://127.0.0.1:${sharPort}/readyz`), shar);
    await warmup(siteKey);
    await Promise.all([stabilizeRss(cap), stabilizeRss(shar)]);
    const output = join(stagedOutputDirectory, `${label}.json`);
    await run(process.execPath, ["bench/cap/live.mjs"], {
      cwd: root,
      env: {
        SHAR_BENCH_ENDPOINT: `http://127.0.0.1:${sharPort}`,
        CAP_BENCH_ENDPOINT: `http://127.0.0.1:${capPort}/${siteKey}/`,
        CAP_BENCH_SETTINGS_JSON: JSON.stringify(capSettings),
        SHAR_BENCH_ORIGIN: origin,
        SHAR_BENCH_SAMPLES: String(solveSamples),
        SHAR_BENCH_ISSUE_OPERATIONS: String(issueOperations),
        SHAR_BENCH_CONCURRENCY: String(concurrency),
        SHAR_BENCH_CLIENT_WORKERS: String(clientWorkers),
        SHAR_BENCH_ACTION_CARDINALITY: String(actionCardinality),
        SHAR_BENCH_PID: String(shar.pid),
        CAP_BENCH_PID: String(cap.pid),
        SHAR_BENCH_OUTPUT: output,
      },
      capture: true,
    });
    const result = JSON.parse(await readFile(output, "utf8"));
    assertComparableResult(result);
    return result;
  } catch (error) {
    const diagnostics = [];
    for (const [name, process] of [
      ["Cap", cap],
      ["Shar", shar],
    ]) {
      if (!process?.benchmarkLog) continue;
      const log = await readFile(process.benchmarkLog, "utf8").catch(() => "");
      if (log) diagnostics.push(`${name} log:\n${log.slice(-8_192)}`);
    }
    throw new Error(
      `${error instanceof Error ? (error.stack ?? error.message) : String(error)}${
        diagnostics.length ? `\n${diagnostics.join("\n")}` : ""
      }`,
    );
  } finally {
    await stopProcess(shar);
    await stopProcess(cap);
  }
}

async function configureCap() {
  const login = await jsonRequest(
    new URL(`http://127.0.0.1:${capPort}/auth/login`),
    { admin_key: "shar-cap-benchmark-admin" },
  );
  const authorization = `Bearer ${Buffer.from(
    JSON.stringify({ token: login.session_token, hash: login.hashed_token }),
  ).toString("base64")}`;
  const created = await jsonRequest(
    new URL(`http://127.0.0.1:${capPort}/server/keys`),
    {
      name: "Shar pinned comparison",
      instrumentation: false,
      blockAutomatedBrowsers: false,
      corsOrigins: [origin],
      rsw: capSettings.rsw,
      ...(capSettings.rsw ? { rswT: capSettings.rswT } : {}),
    },
    authorization,
  );
  await jsonRequest(
    new URL(
      `http://127.0.0.1:${capPort}/server/keys/${created.siteKey}/config`,
    ),
    {
      difficulty: capSettings.difficulty,
      challengeCount: capSettings.challengeCount,
      instrumentation: false,
      obfuscationLevel: 3,
      blockAutomatedBrowsers: false,
      ratelimitMax: 10_000,
      ratelimitDuration: 3_600_000,
      corsOrigins: [origin],
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
    const [shar, cap] = await Promise.all([
      fetch(`http://127.0.0.1:${sharPort}/v1/challenges`, {
        method: "POST",
        headers: { "content-type": "application/json", origin },
        body: JSON.stringify({
          tenant: "benchmark-warmup",
          site_key: "benchmark",
          action: `warmup-${index}`,
          origin,
        }),
      }),
      fetch(`http://127.0.0.1:${capPort}/${siteKey}/challenge`, {
        method: "POST",
        headers: {
          origin,
          "user-agent": "Mozilla/5.0 Shar-Cap-Benchmark/1.0",
        },
      }),
    ]);
    if (!shar.ok || !cap.ok)
      throw new Error(`warmup failed: Shar ${shar.status}, Cap ${cap.status}`);
  }
}

function startProcess(command, args, cwd, environment, logPath) {
  const log = openSync(logPath, "a");
  let child;
  try {
    child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...environment },
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

async function waitForUrl(url, child) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.benchmarkError)
      throw new Error(`${url.origin} failed to start: ${child.benchmarkError}`);
    if (child.exitCode !== null) {
      const log = await readFile(child.benchmarkLog, "utf8").catch(() => "");
      throw new Error(`${url.origin} exited before readiness: ${log}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {}
    await delay(100);
  }
  throw new Error(`${url.href} did not become ready`);
}

function assertComparableResult(result) {
  if (
    result?.schema !== "shar-cap-live-reference-v1" ||
    result.inputs?.cap?.standalone?.tag !== "standalone@3.1.8" ||
    result.inputs?.issue_operations !== issueOperations ||
    result.inputs?.concurrency !== concurrency ||
    result.inputs?.http_client_workers !== clientWorkers ||
    result.inputs?.shar_action_cardinality !== actionCardinality ||
    JSON.stringify(result.inputs?.cap_declared_settings) !==
      JSON.stringify(capSettings)
  )
    throw new Error("live result does not match the pinned Cap comparison");
  for (const product of ["shar", "cap"]) {
    const issuance = result.issuance?.[product];
    if (
      issuance?.operations !== issueOperations ||
      issuance?.concurrency !== concurrency ||
      !Number.isFinite(issuance?.operations_per_second) ||
      issuance.operations_per_second <= 0 ||
      !Number.isFinite(issuance?.response_body_bytes?.min) ||
      issuance.response_body_bytes.min <= 0 ||
      issuance?.rss?.sample_count < 1
    )
      throw new Error(`invalid ${product} issuance evidence`);
  }
  if (
    !Number.isSafeInteger(result.idle_memory?.shar_rss_bytes) ||
    !Number.isSafeInteger(result.idle_memory?.cap_rss_bytes) ||
    result.idle_memory.shar_rss_bytes <= 0 ||
    result.idle_memory.cap_rss_bytes <= 0 ||
    result.behavior?.shar_origin_request?.status !== 200 ||
    result.behavior?.cap_browser_like_request?.status !== 200
  )
    throw new Error(
      "live result lacks comparable process or behavior evidence",
    );
}

async function stabilizeRss(child) {
  const deadline = Date.now() + 10_000;
  const recent = [];
  while (Date.now() < deadline) {
    const status = await readFile(`/proc/${child.pid}/status`, "utf8");
    const match = /^VmRSS:\s+(\d+)\s+kB$/m.exec(status);
    if (!match) throw new Error(`cannot sample RSS for PID ${child.pid}`);
    recent.push(Number(match[1]));
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

async function stopProcess(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  const exited = new Promise((resolve) => child.once("exit", resolve));
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

async function jsonRequest(url, body, authorization, method = "POST") {
  const response = await fetch(url, {
    method,
    headers: {
      "content-type": "application/json",
      ...(authorization ? { authorization } : {}),
    },
    body: JSON.stringify(body),
  });
  const value = await response.json();
  if (!response.ok || value.success === false)
    throw new Error(
      `${url.pathname} returned ${response.status}: ${JSON.stringify(value)}`,
    );
  return value;
}

function numericDistribution(values) {
  const result = distribution(values);
  return {
    samples: result.samples,
    min: result.min_ms,
    median: result.median_ms,
    p95: result.p95_ms,
    max: result.max_ms,
    mean: result.mean_ms,
  };
}

async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(
      temporaryPath,
      await formatSource(JSON.stringify(value), { parser: "json" }),
    );
    await rename(temporaryPath, path);
  } finally {
    await rm(temporaryPath, { force: true });
  }
}

function requiredUrl(name, protocols) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  const url = new URL(value);
  if (!protocols.includes(url.protocol))
    throw new Error(`${name} must use ${protocols.join(" or ")}`);
  return url;
}

function integer(name, fallback, minimum, maximum) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new Error(
      `${name} must be an integer from ${minimum} through ${maximum}`,
    );
  return value;
}

function choice(name, fallback, values) {
  const value = process.env[name] ?? fallback;
  if (!values.includes(value))
    throw new Error(`${name} must be one of ${values.join(", ")}`);
  return value;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
