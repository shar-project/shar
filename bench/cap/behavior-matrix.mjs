import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { closeSync, existsSync, openSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { format as formatSource } from "prettier";
import { environment, manifest, workspace } from "./lib.mjs";

const root = fileURLToPath(workspace);
const capDirectory = resolve(root, ".bench/cap/source/standalone/standalone");
const redisUrl = requiredUrl("CAP_BENCH_REDIS_URL", ["redis:", "rediss:"]);
const port = integer("CAP_BENCH_PORT", 4210, 1, 65_535);
const endpoint = new URL(`http://127.0.0.1:${port}/`);
const origin = process.env.SHAR_BENCH_ORIGIN ?? "http://localhost:3000";
const output = new URL(
  process.env.CAP_BENCH_BEHAVIOR_OUTPUT ??
    "bench/cap/results/local-cap-behavior-matrix.json",
  workspace,
);
const browserHeaders = {
  origin,
  "user-agent": "Mozilla/5.0 Shar-Cap-Benchmark/1.0",
};

if (!existsSync(resolve(capDirectory, "node_modules")))
  throw new Error(
    "Cap Standalone dependencies are missing; install the prepared pinned source first",
  );

const logPath = resolve(root, ".bench/cap/behavior-matrix.log");
const cap = startProcess(
  "bun",
  ["src/index.js"],
  capDirectory,
  {
    ADMIN_KEY: "shar-cap-behavior-admin",
    REDIS_URL: redisUrl.href,
    REDIS_PREFIX: `shar-behavior:${randomUUID()}:`,
    SERVER_HOSTNAME: "127.0.0.1",
    SERVER_PORT: String(port),
    DISABLE_ERROR_LOGGING: "true",
    HIDE_RATELIMIT_IP_WARNING: "true",
  },
  logPath,
);

let result;
try {
  await waitForUrl(endpoint, cap);
  const authorization = await login();
  const cases = {};

  const sha = await createSite(authorization, {
    challengeCount: 2,
    difficulty: 1,
    instrumentation: false,
    blockAutomatedBrowsers: false,
    blockNonBrowserUA: false,
    ratelimitMax: 100,
    ratelimitDuration: 60_000,
    rsw: false,
  });
  const shaChallenge = await challenge(sha.siteKey, browserHeaders);
  requireStatus(shaChallenge, 200, "SHA challenge");
  const shaRedeem = await request(
    `${sha.siteKey}/redeem`,
    {
      token: shaChallenge.body.token,
      solutions: solveSha(shaChallenge.body),
    },
    browserHeaders,
  );
  requireStatus(shaRedeem, 200, "SHA redemption");
  const shaVerify = await request(`${sha.siteKey}/siteverify`, {
    secret: sha.secretKey,
    response: shaRedeem.body.token,
  });
  requireStatus(shaVerify, 200, "SHA site verification");
  const shaVerifyReplay = await request(`${sha.siteKey}/siteverify`, {
    secret: sha.secretKey,
    response: shaRedeem.body.token,
  });
  requireStatus(shaVerifyReplay, 404, "SHA site-verification replay");
  cases.sha_pow_and_single_use_siteverify = {
    challenge_status: shaChallenge.status,
    challenge_format: "sha256-pow",
    redemption_status: shaRedeem.status,
    siteverify_status: shaVerify.status,
    replay_status: shaVerifyReplay.status,
  };

  const rsw = await createSite(authorization, {
    instrumentation: false,
    blockAutomatedBrowsers: false,
    blockNonBrowserUA: false,
    ratelimitMax: 100,
    ratelimitDuration: 60_000,
    rsw: true,
    rswT: 10_000,
  });
  const rswChallenge = await challenge(rsw.siteKey, browserHeaders);
  requireStatus(rswChallenge, 200, "RSW challenge");
  const protocols = rswChallenge.body.challenges?.map((item) => item.protocol);
  if (!Array.isArray(protocols) || !protocols.includes("rsw"))
    throw new Error("Cap RSW challenge did not contain the RSW protocol");
  const rswRedeem = await request(
    `${rsw.siteKey}/redeem`,
    {
      token: rswChallenge.body.token,
      solutions: solveFormat2(rswChallenge.body),
    },
    browserHeaders,
  );
  requireStatus(rswRedeem, 200, "RSW redemption");
  const rswVerify = await request(`${rsw.siteKey}/siteverify`, {
    secret: rsw.secretKey,
    response: rswRedeem.body.token,
  });
  requireStatus(rswVerify, 200, "RSW site verification");
  cases.rsw_and_siteverify = {
    challenge_status: rswChallenge.status,
    protocols,
    iterations: 10_000,
    redemption_status: rswRedeem.status,
    siteverify_status: rswVerify.status,
  };

  const instrumented = await createSite(authorization, {
    challengeCount: 1,
    difficulty: 1,
    instrumentation: true,
    blockAutomatedBrowsers: true,
    blockNonBrowserUA: false,
    ratelimitMax: 100,
    ratelimitDuration: 60_000,
    rsw: false,
  });
  const instrumentedChallenge = await challenge(
    instrumented.siteKey,
    browserHeaders,
  );
  requireStatus(instrumentedChallenge, 200, "instrumented challenge");
  if (typeof instrumentedChallenge.body.instrumentation !== "string")
    throw new Error("Cap instrumented challenge omitted its program");
  const missingInstrumentation = await request(
    `${instrumented.siteKey}/redeem`,
    {
      token: instrumentedChallenge.body.token,
      solutions: solveSha(instrumentedChallenge.body),
    },
    browserHeaders,
  );
  requireStatus(missingInstrumentation, 403, "missing instrumentation");
  if (missingInstrumentation.body.reason !== "missing_instrumentation_response")
    throw new Error("Cap returned an unexpected instrumentation rejection");
  cases.instrumentation_policy_rejection = {
    challenge_status: instrumentedChallenge.status,
    instrumentation_present: true,
    redemption_status: missingInstrumentation.status,
    reason: missingInstrumentation.body.reason,
  };

  const userAgent = await createSite(authorization, {
    challengeCount: 1,
    difficulty: 1,
    instrumentation: false,
    blockAutomatedBrowsers: false,
    blockNonBrowserUA: true,
    ratelimitMax: 100,
    ratelimitDuration: 60_000,
    rsw: false,
  });
  const nonBrowser = await challenge(userAgent.siteKey, { origin });
  const browser = await challenge(userAgent.siteKey, browserHeaders);
  requireStatus(nonBrowser, 403, "non-browser user agent");
  requireStatus(browser, 200, "browser user agent");
  cases.user_agent_policy_rejection = {
    non_browser_status: nonBrowser.status,
    browser_status: browser.status,
  };

  const rateLimited = await createSite(authorization, {
    challengeCount: 1,
    difficulty: 1,
    instrumentation: false,
    blockAutomatedBrowsers: false,
    blockNonBrowserUA: false,
    ratelimitMax: 100,
    ratelimitDuration: 60_000,
    rsw: false,
  });
  const rateProbe = await challenge(rateLimited.siteKey, browserHeaders);
  requireStatus(rateProbe, 200, "rate-limit counter probe");
  const limit = Number(rateProbe.headers.xRateLimitLimit);
  const remaining = Number(rateProbe.headers.xRateLimitRemaining);
  if (!Number.isSafeInteger(limit) || !Number.isSafeInteger(remaining))
    throw new Error("Cap rate-limit response omitted integer counters");
  const currentCount = limit - remaining;
  await configureSite(authorization, rateLimited.siteKey, {
    challengeCount: 1,
    difficulty: 1,
    instrumentation: false,
    blockAutomatedBrowsers: false,
    blockNonBrowserUA: false,
    ratelimitMax: currentCount + 1,
    ratelimitDuration: 60_000,
    rsw: false,
  });
  const allowedRate = await challenge(rateLimited.siteKey, browserHeaders);
  const rejectedRate = await challenge(rateLimited.siteKey, browserHeaders);
  requireStatus(allowedRate, 200, "request at Cap rate limit");
  requireStatus(rejectedRate, 429, "request beyond Cap rate limit");
  cases.rate_limit_rejection = {
    request_at_limit_status: allowedRate.status,
    request_beyond_limit_status: rejectedRate.status,
  };

  const invalid = await createSite(authorization, {
    challengeCount: 2,
    difficulty: 1,
    instrumentation: false,
    blockAutomatedBrowsers: false,
    blockNonBrowserUA: false,
    ratelimitMax: 100,
    ratelimitDuration: 60_000,
    rsw: false,
  });
  const invalidChallenge = await challenge(invalid.siteKey, browserHeaders);
  requireStatus(invalidChallenge, 200, "invalid-proof challenge");
  const invalidRedemption = await request(
    `${invalid.siteKey}/redeem`,
    { token: invalidChallenge.body.token, solutions: [0, 0] },
    browserHeaders,
  );
  if (![400, 403].includes(invalidRedemption.status))
    throw new Error(`invalid proof returned ${invalidRedemption.status}`);
  const replacement = await challenge(invalid.siteKey, browserHeaders);
  requireStatus(replacement, 200, "replacement challenge after invalid proof");
  cases.invalid_proof_allows_replacement = {
    invalid_redemption_status: invalidRedemption.status,
    replacement_challenge_status: replacement.status,
  };

  result = {
    schema: "shar-cap-behavior-matrix-v1",
    environment: environment(),
    cap: await manifest(),
    settings: {
      standalone: "standalone@3.1.8",
      origin,
      isolated_redis_prefix: true,
    },
    cases,
    interpretation: {
      scope: "pinned Cap behavior evidence, not a Shar acceptance policy",
      shar_difference:
        "Shar permits transport backpressure and invalid-proof failure, but UA and instrumentation signals can only price future finite work and cannot reject a correct issued proof.",
    },
  };
} catch (error) {
  const log = await readFile(logPath, "utf8").catch(() => "");
  throw new Error(
    `${error instanceof Error ? (error.stack ?? error.message) : String(error)}${
      log ? `\nCap log:\n${log.slice(-8_192)}` : ""
    }`,
  );
} finally {
  await stopProcess(cap);
}

await mkdir(new URL("./", output), { recursive: true });
await writeFile(
  output,
  await formatSource(JSON.stringify(result), { parser: "json" }),
);
console.log(JSON.stringify(result, null, 2));

async function login() {
  const response = await request("auth/login", {
    admin_key: "shar-cap-behavior-admin",
  });
  requireStatus(response, 200, "Cap admin login");
  return `Bearer ${Buffer.from(
    JSON.stringify({
      token: response.body.session_token,
      hash: response.body.hashed_token,
    }),
  ).toString("base64")}`;
}

async function createSite(authorization, config) {
  const created = await request(
    "server/keys",
    {
      name: "Shar pinned behavior comparison",
      instrumentation: config.instrumentation,
      blockAutomatedBrowsers: config.blockAutomatedBrowsers,
      corsOrigins: [origin],
      rsw: config.rsw,
      ...(config.rswT ? { rswT: config.rswT } : {}),
    },
    { authorization },
  );
  requireStatus(created, 200, "Cap site creation");
  await configureSite(authorization, created.body.siteKey, config);
  return created.body;
}

async function configureSite(authorization, siteKey, config) {
  const configured = await request(
    `server/keys/${siteKey}/config`,
    {
      ...config,
      saltSize: undefined,
      obfuscationLevel: 3,
      corsOrigins: [origin],
      requiredHeaders: [],
    },
    { authorization },
    "PUT",
  );
  requireStatus(configured, 200, "Cap site configuration");
  if (configured.body.success !== true)
    throw new Error("Cap site configuration did not succeed");
}

function challenge(siteKey, headers) {
  return request(`${siteKey}/challenge`, undefined, headers);
}

async function request(path, body, headers = {}, method = "POST") {
  const response = await fetch(new URL(path, endpoint), {
    method,
    headers: {
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...headers,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { non_json_body: text.slice(0, 512) };
  }
  return {
    status: response.status,
    body: parsed,
    headers: {
      xRateLimitLimit: response.headers.get("x-ratelimit-limit"),
      xRateLimitRemaining: response.headers.get("x-ratelimit-remaining"),
    },
  };
}

function requireStatus(response, expected, label) {
  if (response.status !== expected)
    throw new Error(
      `${label} returned ${response.status}: ${JSON.stringify(response.body)}`,
    );
}

function fnv1a(text) {
  let hash = 2_166_136_261;
  for (let index = 0; index < text.length; index++) {
    hash ^= text.charCodeAt(index);
    hash +=
      (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return hash >>> 0;
}

function prng(seed, length) {
  let state = fnv1a(seed);
  let output = "";
  while (output.length < length) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    output += state.toString(16).padStart(8, "0");
  }
  return output.slice(0, length);
}

function solveSha(challenge) {
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

function solveFormat2(challenge) {
  return challenge.challenges.map((item) => {
    if (item.protocol !== "rsw")
      throw new Error(`unsupported Cap behavior protocol ${item.protocol}`);
    const modulus = BigInt(`0x${item.payload.N}`);
    let value = BigInt(`0x${item.payload.x}`);
    for (let iteration = 0; iteration < item.payload.t; iteration++)
      value = (value * value) % modulus;
    return { y: value.toString(16) };
  });
}

function startProcess(command, args, cwd, environmentVariables, log) {
  const descriptor = openSync(log, "a");
  let child;
  try {
    child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...environmentVariables },
      stdio: ["ignore", descriptor, descriptor],
    });
  } finally {
    closeSync(descriptor);
  }
  child.benchmarkLog = log;
  child.benchmarkError = undefined;
  child.once("error", (error) => {
    child.benchmarkError = error;
  });
  return child;
}

async function waitForUrl(url, child) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.benchmarkError) throw child.benchmarkError;
    if (child.exitCode !== null)
      throw new Error(`Cap exited before readiness with ${child.exitCode}`);
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {}
    await delay(100);
  }
  throw new Error("Cap behavior process did not become ready");
}

async function stopProcess(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  const exited = new Promise((resolveExit) => child.once("exit", resolveExit));
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
    throw new Error(`${name} must be ${minimum}..${maximum}`);
  return value;
}

function delay(milliseconds) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}
