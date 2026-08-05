import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
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
  manifest,
  relativeStandardDeviation,
  run,
  workspace,
} from "./lib.mjs";

const root = fileURLToPath(workspace);
const sshTarget = safeTarget("SHAR_BENCH_SSH_TARGET");
const remoteRoot = safeAbsolutePath("SHAR_BENCH_REMOTE_ROOT");
const remoteNode = safeCommand("SHAR_BENCH_REMOTE_NODE", "node");
const remoteBun = safeCommand("SHAR_BENCH_REMOTE_BUN", "bun");
const redisUrl = requiredUrl("CAP_BENCH_REDIS_URL", ["redis:", "rediss:"]);
const origin = process.env.SHAR_BENCH_ORIGIN ?? "http://localhost:3000";
const repetitions = integer("SHAR_BENCH_REPETITIONS", 3, 1, 10);
const issueOperations = integer(
  "SHAR_BENCH_ISSUE_OPERATIONS",
  3_000,
  100,
  100_000,
);
const concurrency = integer("SHAR_BENCH_CONCURRENCY", 32, 1, 256);
const clientWorkers = integer(
  "SHAR_BENCH_CLIENT_WORKERS",
  8,
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
const rssIntervalMs = integer("SHAR_BENCH_RSS_INTERVAL_MS", 100, 25, 1_000);
const sharState = choice("SHAR_BENCH_SHAR_STATE", "redis", ["redis", "sqlite"]);
const capProtocol = choice("CAP_BENCH_PROTOCOL", "rsw", ["sha", "rsw"]);
const variantsRequested = variantList();
const remotePorts = ports("SHAR_BENCH_REMOTE_PORT", 4210);
const localPorts = ports("SHAR_BENCH_LOCAL_PORT", 4310);
const outputDirectory = resolve(
  root,
  process.env.SHAR_BENCH_OUTPUT_DIR ??
    `bench/cap/results/${capProtocol === "rsw" ? "rsw/" : ""}isolated`,
);
const capSettings = {
  challengeCount: 80,
  saltSize: 32,
  difficulty: 4,
  instrumentation: false,
  rsw: capProtocol === "rsw",
  ...(capProtocol === "rsw" ? { rswT: 75_000 } : {}),
};
const pinned = await manifest();
const revision = await committedRevision();
const expectedArtifacts = {
  host_controller_sha256: await sha256File(
    resolve(root, "bench/cap/standalone-host.mjs"),
  ),
  cap_entry_sha256: await sha256File(
    resolve(root, ".bench/cap/source/standalone/standalone/src/index.js"),
  ),
  admin_index_sha256: await sha256File(resolve(root, "dist/admin/index.html")),
  ...(variantsRequested.includes("rust")
    ? {
        rust_server_sha256: await sha256File(
          resolve(root, "target/release/shar-server"),
        ),
      }
    : {}),
};
const temporary = await mkdtemp(join(tmpdir(), "shar-cap-isolated-"));
const stagedOutputDirectory = join(temporary, "results");
const rows = [];

await mkdir(stagedOutputDirectory, { recursive: true });
try {
  for (let repetition = 1; repetition <= repetitions; repetition++) {
    const order =
      repetition % 2 === 1
        ? variantsRequested
        : [...variantsRequested].reverse();
    for (const variant of order) {
      const result = await benchmarkPair(variant, repetition);
      rows.push({ variant, repetition, result });
    }
  }
  const summary = summarize();
  for (const { variant, repetition, result } of rows)
    await writeJson(
      join(outputDirectory, `${variant}-${repetition}.json`),
      result,
    );
  await writeJson(
    join(outputDirectory, "isolated-standalone-comparison.json"),
    summary,
  );
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
} finally {
  if (temporary.startsWith(join(tmpdir(), "shar-cap-isolated-")))
    await rm(temporary, { recursive: true, force: true });
}

async function benchmarkPair(variant, repetition) {
  const token = randomBytes(32).toString("base64url");
  const hostConfig = {
    variant,
    shar_state: sharState,
    cap_protocol: capProtocol,
    cap_port: remotePorts.cap,
    shar_port: remotePorts.shar,
    control_port: remotePorts.control,
    control_token: token,
    redis_url: redisUrl.href,
    origin,
    revision,
    bun: remoteBun,
    node: remoteNode,
  };
  const encoded = Buffer.from(JSON.stringify(hostConfig)).toString("base64url");
  const remoteController = `${remoteRoot}/bench/cap/standalone-host.mjs`;
  const ssh = spawn(
    "ssh",
    [
      "-T",
      "-o",
      "BatchMode=yes",
      "-o",
      "ExitOnForwardFailure=yes",
      "-o",
      "ServerAliveInterval=15",
      "-o",
      "ServerAliveCountMax=2",
      "-L",
      `127.0.0.1:${localPorts.cap}:127.0.0.1:${remotePorts.cap}`,
      "-L",
      `127.0.0.1:${localPorts.shar}:127.0.0.1:${remotePorts.shar}`,
      "-L",
      `127.0.0.1:${localPorts.control}:127.0.0.1:${remotePorts.control}`,
      sshTarget,
      "env",
      `SHAR_BENCH_HOST_CONFIG_B64=${encoded}`,
      remoteNode,
      remoteController,
    ],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] },
  );
  let stderr = "";
  ssh.stderr.on("data", (chunk) => {
    stderr += chunk;
    if (stderr.length > 65_536) stderr = stderr.slice(-65_536);
  });
  try {
    const announced = await hostAnnouncement(ssh, stderrRef());
    validateHostManifest(announced, variant);
    const fetched = await controllerJson("GET", "/manifest", token);
    if (JSON.stringify(fetched) !== JSON.stringify(announced))
      throw new Error(
        "server-host controller manifest changed after readiness",
      );
    const output = join(stagedOutputDirectory, `${variant}-${repetition}.json`);
    await run(process.execPath, ["bench/cap/live.mjs"], {
      cwd: root,
      env: {
        SHAR_BENCH_ENDPOINT: `http://127.0.0.1:${localPorts.shar}`,
        CAP_BENCH_ENDPOINT: `http://127.0.0.1:${localPorts.cap}/${
          new URL(announced.endpoints.cap).pathname
            .split("/")
            .filter(Boolean)[0]
        }/`,
        CAP_BENCH_SETTINGS_JSON: JSON.stringify(capSettings),
        SHAR_BENCH_ORIGIN: origin,
        SHAR_BENCH_SAMPLES: String(solveSamples),
        SHAR_BENCH_ISSUE_OPERATIONS: String(issueOperations),
        SHAR_BENCH_CONCURRENCY: String(concurrency),
        SHAR_BENCH_CLIENT_WORKERS: String(clientWorkers),
        SHAR_BENCH_ACTION_CARDINALITY: String(actionCardinality),
        SHAR_BENCH_RSS_INTERVAL_MS: String(rssIntervalMs),
        SHAR_BENCH_RSS_URL: `http://127.0.0.1:${localPorts.control}/rss/shar`,
        CAP_BENCH_RSS_URL: `http://127.0.0.1:${localPorts.control}/rss/cap`,
        SHAR_BENCH_RSS_TOKEN: token,
        SHAR_BENCH_OUTPUT: output,
      },
      capture: true,
    });
    const result = JSON.parse(await readFile(output, "utf8"));
    validateLiveResult(result);
    result.isolated_deployment = {
      schema: "shar-cap-isolated-deployment-v1",
      revision,
      transport: "openssh_loopback_port_forward",
      load_generator_environment: result.environment,
      server_host: announced,
      assertions: {
        ssh_target_was_non_loopback: true,
        services_bound_to_server_loopback: true,
        authenticated_remote_rss: true,
        stabilized_server_idle_rss: true,
        local_and_remote_artifacts_match: true,
      },
      caveats: [
        "SSH encryption and forwarding overhead are included equally in both HTTP measurements.",
        "Redis process memory is excluded; when Redis is server-local its CPU and I/O contention remain part of the host conditions.",
        "This server benchmark is not browser latency, energy, or attacker-economics evidence.",
      ],
    };
    result.idle_memory = announced.idle_memory;
    result.ga_gates.server_throughput_and_memory = {
      status: "isolated_candidate",
      reason:
        "separate load-generator/server hosts, fresh processes, matching state profile, stabilized server-host RSS, and authenticated in-load RSS sampling were validated",
    };
    await writeJson(output, result);
    return result;
  } catch (error) {
    throw new Error(
      `${error instanceof Error ? (error.stack ?? error.message) : String(error)}${
        stderr ? `\nRemote benchmark stderr:\n${stderr}` : ""
      }`,
    );
  } finally {
    await controllerJson("POST", "/shutdown", token).catch(() => undefined);
    if (!(await waitForExit(ssh, 10_000))) {
      ssh.kill("SIGTERM");
      if (!(await waitForExit(ssh, 5_000))) ssh.kill("SIGKILL");
    }
  }

  function stderrRef() {
    return () => stderr;
  }
}

function validateHostManifest(value, variant) {
  if (
    value?.schema !== "shar-cap-isolated-host-v1" ||
    value.revision !== revision ||
    value.variant !== variant ||
    value.state !== sharState ||
    JSON.stringify(value.cap_settings) !== JSON.stringify(capSettings) ||
    JSON.stringify(value.cap) !== JSON.stringify(pinned) ||
    value.isolation?.bind !== "loopback_only" ||
    value.isolation?.controller_authentication !== "bearer_token" ||
    !Number.isSafeInteger(value.idle_memory?.shar_rss_bytes) ||
    value.idle_memory.shar_rss_bytes <= 0 ||
    !Number.isSafeInteger(value.idle_memory?.cap_rss_bytes) ||
    value.idle_memory.cap_rss_bytes <= 0
  )
    throw new Error("invalid or incomparable isolated server-host manifest");
  if (
    value.artifacts?.host_controller_sha256 !==
      expectedArtifacts.host_controller_sha256 ||
    value.artifacts?.cap_entry_sha256 !== expectedArtifacts.cap_entry_sha256 ||
    value.artifacts?.admin_index_sha256 !==
      expectedArtifacts.admin_index_sha256 ||
    (variant === "rust" &&
      value.artifacts?.shar_server_sha256 !==
        expectedArtifacts.rust_server_sha256)
  )
    throw new Error("server-host artifact digest differs from the load host");
}

function validateLiveResult(result) {
  if (
    result?.schema !== "shar-cap-live-reference-v1" ||
    result.inputs?.cap?.standalone?.tag !== "standalone@3.1.8" ||
    result.inputs?.issue_operations !== issueOperations ||
    result.inputs?.concurrency !== concurrency ||
    result.inputs?.http_client_workers !== clientWorkers ||
    result.inputs?.shar_action_cardinality !== actionCardinality ||
    result.inputs?.rss_sources?.SHAR_BENCH_PID !== "remote_control" ||
    result.inputs?.rss_sources?.CAP_BENCH_PID !== "remote_control" ||
    JSON.stringify(result.inputs?.cap_declared_settings) !==
      JSON.stringify(capSettings)
  )
    throw new Error(
      "live result does not match the isolated pinned comparison",
    );
  for (const product of ["shar", "cap"]) {
    const issuance = result.issuance?.[product];
    if (
      issuance?.operations !== issueOperations ||
      issuance?.concurrency !== concurrency ||
      !Number.isFinite(issuance?.operations_per_second) ||
      issuance.operations_per_second <= 0 ||
      issuance?.rss?.sample_count < 2
    )
      throw new Error(`invalid isolated ${product} issuance evidence`);
  }
  if (
    result.behavior?.shar_origin_request?.status !== 200 ||
    result.behavior?.cap_browser_like_request?.status !== 200
  )
    throw new Error("isolated result lacks comparable behavior evidence");
}

function summarize() {
  const requestFloors = rows.map((row) =>
    Math.min(
      row.result.issuance.shar.latency.min_ms,
      row.result.issuance.cap.latency.min_ms,
    ),
  );
  const lowLatencyTopology = evaluateAllRunGate(requestFloors, 5, "maximum");
  const variants = Object.fromEntries(
    variantsRequested.map((variant) => {
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
      const capIdle = selected.map(
        (row) => row.result.idle_memory.cap_rss_bytes,
      );
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
  const throughputGate =
    nativeRows.length > 0
      ? evaluateAllRunGate(nativeThroughputRatios, 2, "minimum")
      : undefined;
  const memoryGate =
    nativeRows.length > 0
      ? evaluateAllRunGate(nativeIdleRatios, 0.5, "maximum")
      : undefined;
  return {
    schema: "shar-cap-isolated-standalone-comparison-v1",
    captured_at: new Date().toISOString(),
    revision,
    scope: {
      status: lowLatencyTopology.pass
        ? "isolated_candidate_evidence"
        : "isolated_latency_constrained",
      cap: "standalone@3.1.8",
      shar_variants: variantsRequested,
      topology:
        "load generator and server processes execute on separate non-loopback SSH hosts; all service and control listeners remain loopback-only and traverse authenticated SSH forwards",
      memory:
        "server-host Linux /proc VmRSS after stabilization and during issuance; Redis and SSH process memory excluded",
      exclusions: [
        "Redis and SSH process memory",
        "container runtime overhead",
        "managed-store and proxy failover",
        "browser latency and energy",
        "attacker economics",
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
      rss_interval_ms: rssIntervalMs,
      cap_settings: capSettings,
    },
    variants,
    topology_quality: {
      request_floor_ms: numericDistribution(requestFloors),
      request_floor_at_most_5ms: lowLatencyTopology,
      reason:
        "a higher floor lets transport latency dominate both products and cannot establish the native server-throughput gate",
    },
    native_thresholds:
      nativeRows.length > 0
        ? {
            throughput_at_least_2x_cap: throughputGate,
            idle_memory_at_most_half_cap: memoryGate,
            ga_scope_pass:
              lowLatencyTopology.pass && throughputGate.pass && memoryGate.pass,
          }
        : { status: "not_measured" },
    raw_results: rows.map(
      ({ variant, repetition }) => `${variant}-${repetition}.json`,
    ),
  };
}

async function hostAnnouncement(child, stderr) {
  let buffer = "";
  return new Promise((resolvePromise, reject) => {
    const deadline = setTimeout(() => {
      cleanup();
      reject(
        new Error(
          `server-host controller did not become ready${stderr() ? `: ${stderr()}` : ""}`,
        ),
      );
    }, 60_000);
    const data = (chunk) => {
      buffer += chunk;
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith("SHAR_BENCH_HOST_READY ")) continue;
        cleanup();
        try {
          resolvePromise(
            JSON.parse(
              Buffer.from(
                line.slice("SHAR_BENCH_HOST_READY ".length),
                "base64url",
              ).toString("utf8"),
            ),
          );
        } catch {
          reject(
            new Error("server-host controller emitted an invalid manifest"),
          );
        }
      }
    };
    const exit = (code, signal) => {
      cleanup();
      reject(
        new Error(
          `server-host SSH session exited ${code ?? signal}${stderr() ? `: ${stderr()}` : ""}`,
        ),
      );
    };
    const error = (cause) => {
      cleanup();
      reject(cause);
    };
    function cleanup() {
      clearTimeout(deadline);
      child.stdout.off("data", data);
      child.off("exit", exit);
      child.off("error", error);
    }
    child.stdout.on("data", data);
    child.once("exit", exit);
    child.once("error", error);
  });
}

async function controllerJson(method, path, token) {
  const response = await fetch(
    `http://127.0.0.1:${localPorts.control}${path}`,
    {
      method,
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(3_000),
    },
  );
  if (!response.ok)
    throw new Error(`isolated controller ${path} returned ${response.status}`);
  return response.json();
}

async function waitForExit(child, timeout) {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  return Promise.race([
    new Promise((resolvePromise) =>
      child.once("exit", () => resolvePromise(true)),
    ),
    new Promise((resolvePromise) =>
      setTimeout(() => resolvePromise(false), timeout),
    ),
  ]);
}

async function committedRevision() {
  const status = await run("git", ["status", "--porcelain"], {
    cwd: root,
    capture: true,
  });
  if (status.stdout.trim())
    throw new Error("isolated benchmark requires a clean committed worktree");
  const result = await run("git", ["rev-parse", "HEAD"], {
    cwd: root,
    capture: true,
  });
  const value = result.stdout.trim();
  if (!/^[0-9a-f]{40}$/.test(value))
    throw new Error("cannot determine the benchmark Git revision");
  return value;
}

function safeTarget(name) {
  const value = process.env[name];
  if (!value || !/^[A-Za-z0-9_.@:-]+$/.test(value))
    throw new Error(`${name} must be a plain SSH target`);
  const host = value.includes("@") ? value.split("@").at(-1) : value;
  if (["localhost", "127.0.0.1", "::1"].includes(host))
    throw new Error(`${name} must identify a separate non-loopback host`);
  return value;
}

function safeAbsolutePath(name) {
  const value = process.env[name];
  if (
    !value ||
    !value.startsWith("/") ||
    !/^\/[A-Za-z0-9._/-]+$/.test(value) ||
    value.split("/").includes("..") ||
    value === "/"
  )
    throw new Error(`${name} must be a narrow absolute path without ..`);
  return value.replace(/\/$/, "");
}

function safeCommand(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (!/^[A-Za-z0-9_./-]+$/.test(value) || value.includes(".."))
    throw new Error(`${name} must be a plain command or path`);
  return value;
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
    throw new Error(`${name} must be ${values.join(" or ")}`);
  return value;
}

function variantList() {
  const values = (process.env.SHAR_BENCH_VARIANTS ?? "rust")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (
    values.length < 1 ||
    new Set(values).size !== values.length ||
    values.some((value) => !["rust", "javascript"].includes(value))
  )
    throw new Error("SHAR_BENCH_VARIANTS must be rust, javascript, or both");
  return values;
}

function ports(name, fallback) {
  const cap = integer(name, fallback, 1, 65_533);
  return { cap, shar: cap + 1, control: cap + 2 };
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

async function sha256File(path) {
  if (!existsSync(path))
    throw new Error(`required benchmark artifact is missing: ${path}`);
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
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
