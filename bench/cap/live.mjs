import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { Agent as HttpAgent, request as httpRequest } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { performance } from "node:perf_hooks";
import { Worker } from "node:worker_threads";
import { format as formatSource } from "prettier";
import {
  distribution,
  environment,
  manifest,
  rssSummary,
  workspace,
} from "./lib.mjs";
import {
  solveRendering,
  solveTimeLock,
} from "../../dist/packages/server/src/index.js";

const sharEndpoint = requiredUrl("SHAR_BENCH_ENDPOINT");
const capEndpoint = requiredUrl("CAP_BENCH_ENDPOINT", true);
const capSettings = requiredJson("CAP_BENCH_SETTINGS_JSON");
const origin = process.env.SHAR_BENCH_ORIGIN ?? "http://localhost:3000";
const samples = integer("SHAR_BENCH_SAMPLES", 3, 1, 1000);
const issueOperations = integer("SHAR_BENCH_ISSUE_OPERATIONS", 100, 1, 100_000);
const actionCardinality = integer(
  "SHAR_BENCH_ACTION_CARDINALITY",
  1,
  1,
  issueOperations,
);
const concurrency = integer("SHAR_BENCH_CONCURRENCY", 1, 1, 256);
const clientWorkers = integer(
  "SHAR_BENCH_CLIENT_WORKERS",
  1,
  1,
  Math.min(16, concurrency),
);
const rssIntervalMs = integer("SHAR_BENCH_RSS_INTERVAL_MS", 50, 10, 1000);
const rssSources = Object.fromEntries(
  ["SHAR_BENCH_PID", "CAP_BENCH_PID"].map((pidName) => [
    pidName,
    rssSource(pidName),
  ]),
);
const runId = randomUUID();
const pinned = await manifest();
const httpAgent = new HttpAgent({
  keepAlive: true,
  maxSockets: concurrency,
  maxFreeSockets: concurrency,
  scheduling: "fifo",
});
const httpsAgent = new HttpsAgent({
  keepAlive: true,
  maxSockets: concurrency,
  maxFreeSockets: concurrency,
  scheduling: "fifo",
});

function requiredUrl(name, trailing = false) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol))
    throw new Error(`${name} must use HTTP(S)`);
  if (trailing && !url.pathname.endsWith("/")) url.pathname += "/";
  return url;
}
function requiredJson(name) {
  const value = process.env[name];
  if (!value)
    throw new Error(
      `${name} is required and must describe the live Cap site-key configuration`,
    );
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      throw new Error();
    return parsed;
  } catch {
    throw new Error(`${name} must be a JSON object`);
  }
}
function integer(name, fallback, min, max) {
  const value =
    process.env[name] === undefined ? fallback : Number(process.env[name]);
  if (!Number.isSafeInteger(value) || value < min || value > max)
    throw new Error(`${name} must be ${min}..${max}`);
  return value;
}
function rssSource(pidName) {
  const pid = process.env[pidName];
  const urlName = pidName.replace(/_PID$/, "_RSS_URL");
  const urlText = process.env[urlName];
  if (pid && urlText)
    throw new Error(`${pidName} and ${urlName} are mutually exclusive`);
  if (pid) {
    if (
      !/^\d+$/.test(pid) ||
      Number(pid) < 1 ||
      !Number.isSafeInteger(Number(pid))
    )
      throw new Error(`${pidName} must be a positive integer PID`);
    return { type: "local_procfs", pid: Number(pid) };
  }
  if (!urlText) return undefined;
  const url = new URL(urlText);
  if (!/^https?:$/.test(url.protocol))
    throw new Error(`${urlName} must use HTTP(S)`);
  const token = process.env.SHAR_BENCH_RSS_TOKEN;
  if (!token || token.length < 32)
    throw new Error(
      `SHAR_BENCH_RSS_TOKEN must contain at least 32 characters when ${urlName} is set`,
    );
  return { type: "remote_control", url, token };
}
async function jsonRequest(url, init, accepted = [200]) {
  const started = performance.now();
  const requestBody =
    init?.body === undefined ? undefined : Buffer.from(init.body);
  const headers = Object.fromEntries(new Headers(init?.headers));
  if (requestBody !== undefined && headers["content-length"] === undefined)
    headers["content-length"] = String(requestBody.byteLength);
  const transport = url.protocol === "https:" ? httpsRequest : httpRequest;
  const agent = url.protocol === "https:" ? httpsAgent : httpAgent;
  const response = await new Promise((resolve, reject) => {
    const request = transport(
      url,
      { method: init?.method ?? "GET", headers, agent },
      (incoming) => {
        const elapsed_ms = performance.now() - started;
        const chunks = [];
        incoming.on("data", (chunk) => chunks.push(chunk));
        incoming.once("end", () =>
          resolve({
            status: incoming.statusCode ?? 0,
            elapsed_ms,
            bytes: Buffer.concat(chunks),
          }),
        );
        incoming.once("error", reject);
      },
    );
    request.once("error", reject);
    request.end(requestBody);
  }).catch((cause) => {
    throw new Error(
      `${init?.method ?? "GET"} ${url.origin}${url.pathname} failed after ${(
        performance.now() - started
      ).toFixed(1)}ms`,
      { cause },
    );
  });
  const text = response.bytes.toString("utf8");
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { non_json_body: text.slice(0, 512) };
  }
  if (!accepted.includes(response.status)) {
    const error = new Error(`${url.pathname} returned ${response.status}`);
    error.result = { status: response.status, body, elapsed_ms: elapsed };
    throw error;
  }
  return {
    status: response.status,
    body,
    elapsed_ms: response.elapsed_ms,
    body_bytes: response.bytes.byteLength,
  };
}

function sharChallenge(index) {
  return jsonRequest(new URL("/v1/challenges", sharEndpoint), {
    method: "POST",
    headers: { "content-type": "application/json", origin },
    body: JSON.stringify({
      tenant: "benchmark",
      site_key: "benchmark",
      action:
        typeof index === "number"
          ? `issue-${runId}-${index % actionCardinality}`
          : `issue-${runId}-${index}`,
      origin,
    }),
  });
}
function capChallenge(headers = {}) {
  return jsonRequest(new URL("challenge", capEndpoint), {
    method: "POST",
    headers,
  });
}

function verifyCapSettings(challenge) {
  if (challenge.challenge) {
    const expected = {
      c: capSettings.challengeCount,
      s: capSettings.saltSize,
      d: capSettings.difficulty,
    };
    for (const [key, value] of Object.entries(expected)) {
      if (value !== undefined && challenge.challenge[key] !== value)
        throw new Error(
          `live Cap challenge ${key}=${challenge.challenge[key]}, declared setting is ${value}`,
        );
    }
    if (capSettings.rsw === true)
      throw new Error("live Cap response is SHA format but declared rsw=true");
    if (
      capSettings.instrumentation === true &&
      typeof challenge.instrumentation !== "string"
    )
      throw new Error("live Cap response lacks declared instrumentation");
    return "sha256-pow";
  }
  if (Array.isArray(challenge.challenges)) {
    const protocols = challenge.challenges.map((item) => item.protocol);
    if (capSettings.rsw === true && !protocols.includes("rsw"))
      throw new Error("live Cap response lacks declared RSW challenge");
    if (
      capSettings.instrumentation === true &&
      !protocols.includes("instrumentation")
    )
      throw new Error(
        "live Cap response lacks declared instrumentation challenge",
      );
    return "format-2";
  }
  throw new Error("unrecognized Cap challenge response");
}

function fnv1a(text) {
  let hash = 2166136261;
  for (let index = 0; index < text.length; index++) {
    hash ^= text.charCodeAt(index);
    hash +=
      (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return hash >>> 0;
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
function prng(seed, length) {
  let state = fnv1a(seed),
    output = "";
  while (output.length < length) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    output += state.toString(16).padStart(8, "0");
  }
  return output.slice(0, length);
}
function solveCapSha(challenge) {
  const { c, s, d } = challenge.challenge;
  const solutions = [];
  for (let index = 1; index <= c; index++) {
    const salt = prng(`${challenge.token}${index}`, s);
    const target = prng(`${challenge.token}${index}d`, d);
    let nonce = 0;
    while (
      !createHash("sha256")
        .update(`${salt}${nonce}`)
        .digest("hex")
        .startsWith(target)
    )
      nonce++;
    solutions.push(nonce);
  }
  return solutions;
}
function solveCapV2(challenge) {
  return challenge.challenges.map((item) => {
    if (item.protocol === "rsw") {
      const modulus = BigInt(`0x${item.payload.N}`);
      let value = BigInt(`0x${item.payload.x}`);
      for (let iteration = 0; iteration < item.payload.t; iteration++)
        value = (value * value) % modulus;
      return { y: value.toString(16) };
    }
    if (item.protocol === "sha256-pow") {
      let nonce = 0;
      while (
        !createHash("sha256")
          .update(`${item.payload.salt}${nonce}`)
          .digest("hex")
          .startsWith(item.payload.target)
      )
        nonce++;
      return { nonce };
    }
    throw new Error(
      `Node CPU reference cannot execute Cap protocol ${item.protocol}; use the browser harness`,
    );
  });
}
async function solveShar(challenge) {
  return {
    token: challenge.token,
    time_lock: solveTimeLock(challenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(challenge.render),
    },
  };
}

async function rss(pidName) {
  const source = rssSources[pidName];
  if (!source) return null;
  if (source.type === "local_procfs") {
    const status = await readFile(`/proc/${source.pid}/status`, "utf8");
    const match = /^VmRSS:\s+(\d+)\s+kB$/m.exec(status);
    if (!match) throw new Error(`cannot read RSS for ${pidName}=${source.pid}`);
    return Number(match[1]) * 1024;
  }
  const response = await fetch(source.url, {
    headers: { authorization: `Bearer ${source.token}` },
    signal: AbortSignal.timeout(2_000),
  });
  if (!response.ok)
    throw new Error(`${pidName} RSS controller returned ${response.status}`);
  const body = await response.json();
  if (!Number.isSafeInteger(body?.rss_bytes) || body.rss_bytes <= 0)
    throw new Error(`${pidName} RSS controller returned invalid evidence`);
  return body.rss_bytes;
}

async function sharMetricSnapshot() {
  const response = await fetch(new URL("/metrics", sharEndpoint));
  if (!response.ok) throw new Error(`Shar metrics returned ${response.status}`);
  const text = await response.text();
  const value = (name) => {
    const match = new RegExp(`^${name} ([0-9]+(?:\\.[0-9]+)?)$`, "m").exec(
      text,
    );
    if (!match) throw new Error(`Shar metrics omitted ${name}`);
    return Number(match[1]);
  };
  return {
    issued: value("shar_challenges_issued_total"),
    engine_seconds: value("shar_challenge_engine_duration_seconds_total"),
    handler_seconds: value("shar_challenge_handler_duration_seconds_total"),
  };
}

function metricDelta(before, after) {
  const issued = after.issued - before.issued;
  const engineSeconds = after.engine_seconds - before.engine_seconds;
  const handlerSeconds = after.handler_seconds - before.handler_seconds;
  if (
    issued !== issueOperations ||
    engineSeconds < 0 ||
    handlerSeconds + 1e-9 < engineSeconds
  )
    throw new Error("Shar issuance metric delta is inconsistent");
  return {
    issued,
    engine_seconds: engineSeconds,
    handler_seconds: handlerSeconds,
    mean_engine_ms: (engineSeconds * 1_000) / issued,
    mean_handler_ms: (handlerSeconds * 1_000) / issued,
  };
}

async function measureRss(pidName, operation) {
  const samples = [];
  let inFlight;
  let samplingError;
  const started = performance.now();
  const sample = () => {
    if (!rssSources[pidName]) return Promise.resolve();
    if (inFlight) return inFlight;
    inFlight = (async () => {
      try {
        const bytes = await rss(pidName);
        if (bytes !== null)
          samples.push({ elapsed_ms: performance.now() - started, bytes });
      } catch (error) {
        samplingError ??= error;
      } finally {
        inFlight = undefined;
      }
    })();
    return inFlight;
  };
  await sample();
  const timer = rssSources[pidName]
    ? setInterval(() => void sample(), rssIntervalMs)
    : undefined;
  let value;
  try {
    value = await operation();
  } finally {
    if (timer !== undefined) clearInterval(timer);
    await sample();
    if (samplingError) throw samplingError;
  }
  return { value, rss: rssSummary(samples) };
}

async function throughput(count, product, pidName) {
  const endpoint =
    product === "shar"
      ? new URL("/v1/challenges", sharEndpoint).href
      : new URL("challenge", capEndpoint).href;
  const partitions = partitionLoad(count, concurrency, clientWorkers);
  const workers = partitions.map((partition) =>
    loadWorker({ product, endpoint, ...partition }),
  );
  try {
    await Promise.all(workers.map((worker) => worker.ready));
    const measured = await measureRss(pidName, async () => {
      const started = performance.now();
      for (const worker of workers) worker.start();
      const results = (
        await Promise.all(workers.map((worker) => worker.result))
      ).flat();
      const elapsed = performance.now() - started;
      return summarizeThroughput(count, elapsed, results);
    });
    return { ...measured.value, rss: measured.rss };
  } finally {
    await Promise.all(workers.map((worker) => worker.terminate()));
  }
}

function summarizeThroughput(count, elapsed, results) {
  if (results.length !== count)
    throw new Error(
      `HTTP load workers returned ${results.length}/${count} results`,
    );
  return {
    operations: count,
    concurrency,
    elapsed_ms: elapsed,
    operations_per_second: (count * 1000) / elapsed,
    latency: distribution(results.map((result) => result.elapsed_ms)),
    response_body_bytes: numericDistribution(
      results.map((result) => result.body_bytes),
    ),
  };
}

function partitionLoad(count, totalConcurrency, workerCount) {
  const partitions = [];
  let offset = 0;
  for (let index = 0; index < workerCount; index++) {
    const operations =
      Math.floor(count / workerCount) + (index < count % workerCount ? 1 : 0);
    const workerConcurrency =
      Math.floor(totalConcurrency / workerCount) +
      (index < totalConcurrency % workerCount ? 1 : 0);
    partitions.push({ offset, operations, concurrency: workerConcurrency });
    offset += operations;
  }
  return partitions;
}

function loadWorker(partition) {
  const worker = new Worker(new URL("http-load-worker.mjs", import.meta.url), {
    workerData: {
      ...partition,
      origin,
      actionCardinality,
      runId,
    },
  });
  let readyResolve;
  let resultResolve;
  let readyReject;
  let resultReject;
  let readySettled = false;
  let resultSettled = false;
  const ready = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  const result = new Promise((resolve, reject) => {
    resultResolve = resolve;
    resultReject = reject;
  });
  // A failure before readiness rejects both promises. Attach a handler now so
  // the result rejection is not reported as unhandled while the caller is
  // still awaiting readiness.
  void result.catch(() => undefined);
  const fail = (error) => {
    if (!readySettled) {
      readySettled = true;
      readyReject(error);
    }
    if (!resultSettled) {
      resultSettled = true;
      resultReject(error);
    }
  };
  worker.on("message", (message) => {
    if (message?.type === "ready" && !readySettled) {
      readySettled = true;
      readyResolve();
    } else if (message?.type === "complete") {
      resultSettled = true;
      resultResolve(message.results);
    } else if (message?.type === "failed") fail(new Error(message.message));
  });
  worker.once("error", fail);
  worker.once("exit", (code) => {
    if (code !== 0 || !resultSettled)
      fail(new Error(`HTTP load worker exited with ${code}`));
  });
  return {
    ready,
    result,
    start: () => worker.postMessage({ type: "start" }),
    terminate: () => worker.terminate(),
  };
}

const rawProbeHeaders = { origin };
const browserProbeHeaders = {
  origin,
  "user-agent": "Mozilla/5.0 Shar-Cap-Benchmark/1.0",
  accept: "application/json",
};
async function probe(operation) {
  try {
    const result = await operation();
    return {
      status: result.status,
      body_shape: Object.keys(result.body).sort(),
    };
  } catch (error) {
    if (error.result) return error.result;
    throw error;
  }
}

const idleMemory = {
  shar_rss_bytes: await rss("SHAR_BENCH_PID"),
  cap_rss_bytes: await rss("CAP_BENCH_PID"),
};
const behavior = {
  shar_origin_request: await probe(() => sharChallenge("probe")),
  cap_raw_request: await probe(() => capChallenge(rawProbeHeaders)),
  cap_browser_like_request: await probe(() =>
    capChallenge(browserProbeHeaders),
  ),
};
const capShape = verifyCapSettings(
  (await capChallenge(browserProbeHeaders)).body,
);

const sharMetricsBefore = await sharMetricSnapshot();
const sharIssue = await throughput(issueOperations, "shar", "SHAR_BENCH_PID");
const sharMetricsAfter = await sharMetricSnapshot();
sharIssue.server_observed = metricDelta(sharMetricsBefore, sharMetricsAfter);
const issue = {
  shar: sharIssue,
  cap: await throughput(issueOperations, "cap", "CAP_BENCH_PID"),
};

const solve = { shar: [], cap: [] };
const redeem = { shar: [], cap: [] };
for (let index = 0; index < samples; index++) {
  const sharIssued = (await sharChallenge(`solve-${index}`)).body;
  const sharStarted = performance.now();
  const sharProof = await solveShar(sharIssued);
  solve.shar.push(performance.now() - sharStarted);
  redeem.shar.push(
    (
      await jsonRequest(new URL("/v1/challenges/redeem", sharEndpoint), {
        method: "POST",
        headers: { "content-type": "application/json", origin },
        body: JSON.stringify(sharProof),
      })
    ).elapsed_ms,
  );

  const capIssued = (await capChallenge(browserProbeHeaders)).body;
  verifyCapSettings(capIssued);
  if (capSettings.instrumentation === true) continue;
  const capStarted = performance.now();
  const solutions =
    capShape === "sha256-pow" ? solveCapSha(capIssued) : solveCapV2(capIssued);
  solve.cap.push(performance.now() - capStarted);
  redeem.cap.push(
    (
      await jsonRequest(new URL("redeem", capEndpoint), {
        method: "POST",
        headers: { "content-type": "application/json", ...browserProbeHeaders },
        body: JSON.stringify({ token: capIssued.token, solutions }),
      })
    ).elapsed_ms,
  );
}

const result = {
  schema: "shar-cap-live-reference-v1",
  environment: environment(),
  inputs: {
    shar_endpoint: sharEndpoint.origin,
    cap_endpoint_origin: capEndpoint.origin,
    cap: pinned,
    cap_declared_settings: capSettings,
    origin,
    samples,
    issue_operations: issueOperations,
    concurrency,
    http_client_workers: clientWorkers,
    http_client:
      "recorded Node worker pool with fixed total concurrency and per-worker HTTP/1.1 keep-alive agents; latency is request start through response headers",
    shar_action_cardinality: actionCardinality,
    rss_interval_ms: rssIntervalMs,
    rss_sources: Object.fromEntries(
      Object.entries(rssSources)
        .filter(([, source]) => source)
        .map(([name, source]) => [name, source.type]),
    ),
  },
  warnings: [
    "Node CPU reference solve times are not accelerated-browser or energy evidence.",
    "Live endpoint throughput includes loopback/network and configured storage latency.",
    `Shar issuance uses ${actionCardinality} action scope(s); set SHAR_BENCH_ACTION_CARDINALITY=${issueOperations} for the high-cardinality abuse profile.`,
    rssSources.SHAR_BENCH_PID?.type === "remote_control" &&
    rssSources.CAP_BENCH_PID?.type === "remote_control"
      ? "RSS samples come from the authenticated server-host controller; the enclosing isolated harness must validate server identity and stabilized idle memory."
      : "RSS samples use local Linux /proc VmRSS and are reference-process evidence, not a stabilized container memory limit or a multi-host benchmark.",
    ...(capSettings.instrumentation === true
      ? [
          "Cap redemption omitted: instrumentation must execute in the browser harness.",
        ]
      : []),
  ],
  behavior,
  idle_memory: idleMemory,
  issuance: issue,
  cpu_reference_solve: {
    shar: distribution(solve.shar),
    cap: distribution(solve.cap),
  },
  redemption: {
    shar: distribution(redeem.shar),
    cap: distribution(redeem.cap),
  },
  ga_gates: {
    accelerated_p95_and_energy: {
      status: "not_measured",
      reason: "requires reference-device browser and energy instrumentation",
    },
    attacker_cost_ratio: {
      status: "not_measured",
      reason: "requires calibrated attacker hardware cost inputs",
    },
    server_throughput_and_memory: {
      status:
        issue.shar.rss.sample_count > 0 && issue.cap.rss.sample_count > 0
          ? "reference_only"
          : "partial",
      reason:
        "production gate requires isolated containers, sustained load, matching stores, idle-memory stabilization, and the full native/JavaScript deployment matrix",
    },
  },
};
const output = process.env.SHAR_BENCH_OUTPUT
  ? new URL(process.env.SHAR_BENCH_OUTPUT, workspace)
  : new URL("results/local-live.json", import.meta.url);
await mkdir(new URL("./", output), { recursive: true });
await writeFile(
  output,
  await formatSource(JSON.stringify(result), { parser: "json" }),
);
console.log(JSON.stringify(result, null, 2));
