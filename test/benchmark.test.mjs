import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  evaluateAllRunGate,
  relativeStandardDeviation,
  rssSummary,
} from "../bench/cap/lib.mjs";

async function json(path) {
  return JSON.parse(
    await readFile(new URL(`../${path}`, import.meta.url), "utf8"),
  );
}

test("Cap benchmark inputs are immutable release artifacts", async () => {
  const manifest = await json("bench/cap/manifest.json");
  assert.equal(manifest.standalone.tag, "standalone@3.1.8");
  assert.equal(
    manifest.standalone.commit,
    "1d4f246d29b691275ce0edbbc8290198ebf8bde8",
  );
  assert.equal(manifest.widget.tag, "widget@0.1.56");
  assert.equal(
    manifest.widget.commit,
    "7849efa7f9ee19694c6f5ba73d0e7f82d37d086f",
  );
  assert.equal(manifest.widget.package, "cap-widget@0.1.56");
  assert.match(manifest.widget.integrity, /^sha512-[A-Za-z0-9+/]+=*$/);
  assert.equal(manifest.wasm.package, "@cap.js/wasm@0.0.7");
  assert.match(manifest.wasm.integrity, /^sha512-[A-Za-z0-9+/]+=*$/);
  assert.doesNotMatch(JSON.stringify(manifest), /latest/i);
});

test("published local artifact evidence is internally consistent and scoped", async () => {
  const result = await json("bench/cap/results/local-artifact-bytes.json");
  assert.equal(result.schema, "shar-cap-artifact-bytes-v1");
  for (const encoding of ["raw", "gzip", "brotli"]) {
    assert.equal(
      result.shar[`${encoding}_total`],
      result.shar.javascript[encoding],
    );
    assert.equal(
      result.cap[`${encoding}_total`],
      result.cap.javascript[encoding] + result.cap.wasm[encoding],
    );
    assert.equal(
      result.shar_over_cap[encoding],
      result.shar[`${encoding}_total`] / result.cap[`${encoding}_total`],
    );
  }
  assert.equal(result.gate.observed, result.shar_over_cap.brotli);
  assert.equal(result.gate.pass, result.gate.observed <= result.gate.threshold);
  assert.match(result.gate.scope, /artifact-only/);
  assert.ok(result.method.exclusions.length > 0);
  assert.ok(result.shar.javascript.resources.length >= 1);
  assert.ok(
    result.shar.javascript.resources.some(
      (resource) => resource.name === "shar.js",
    ),
  );
  assert.ok(result.shar.optional_lazy_javascript.resources.length >= 1);
  assert.ok(
    result.shar.optional_lazy_javascript.resources.some((resource) =>
      resource.name.startsWith("trust-credits-"),
    ),
  );
});

test("Chromium cold-path evidence includes the observed eager Cap WASM request", async () => {
  const result = await json("bench/cap/results/local-browser-cold-path.json");
  assert.equal(result.schema, "shar-cap-browser-cold-path-v1");
  const sharPaths = result.shar.resources.map((resource) => resource.path);
  assert.ok(sharPaths.includes("/assets/shar/shar.js"));
  assert.equal(
    sharPaths.some((path) => /\/trust-credits-[^/]+\.js$/.test(path)),
    false,
  );
  assert.deepEqual(
    result.method.shar_resources.slice().sort(),
    sharPaths.sort(),
  );
  assert.deepEqual(
    result.cap.resources.map((resource) => resource.path).sort(),
    ["/assets/cap.js", "/assets/cap.wasm"],
  );
  assert.equal(result.shar.unexpected_requests.length, 0);
  assert.equal(result.cap.unexpected_requests.length, 0);
  assert.equal(
    result.shar_over_cap_encoded_body,
    result.shar.encoded_body_total / result.cap.encoded_body_total,
  );
  assert.equal(result.gate.pass, result.gate.observed <= result.gate.threshold);
  assert.match(result.gate.scope, /remaining browser\/device matrix/);
});

function assertRenderCalibration(result) {
  assert.equal(result.schema, "shar-render-browser-calibration-v1");
  assert.equal(result.plan.triangles, 256);
  assert.equal(result.plan.samples, 4096);
  assert.equal(result.plan.predicates_per_round, 1_048_576);
  assert.equal(result.gates.requested_backend.pass, true);
  assert.equal(result.gates.bounded_million_scale.pass, true);
  assert.equal(result.gates.identical_digest.pass, true);
  assert.equal(result.gates.accelerated_over_css.pass, true);
  assert.equal(result.gates.css_completion.pass, true);
  assert.equal(result.console.relevant_messages.length, 0);
  assert.deepEqual(result.method.repetitions, {
    cpu: 5,
    webgpu: 5,
    webgl2: 5,
    css: 1,
  });
  const digests = Object.values(result.results)
    .map((entry) => entry.digest)
    .filter(Boolean);
  assert.equal(new Set(digests).size, 1);
  return digests[0];
}

test("published render calibrations prove software, Intel, AMD, and Mali backends", async () => {
  const result = await json(
    "bench/render/results/local-browser-calibration.json",
  );
  const softwareDigest = assertRenderCalibration(result);
  assert.equal(result.environment.gpu_mode, "software renderer");
  assert.equal(result.gates.requested_backend.requested, "swiftshader");
  assert.equal(result.gates.requested_backend.observed, "swiftshader");
  assert.match(result.environment.gpu.renderer, /SwiftShader/);
  assert.equal(result.environment.gpu.vendor_id, 65_535);
  assert.equal(result.gates.accelerated_over_css.ga_scope_pass, false);
  assert.equal(result.gates.accelerated_latency.ga_scope_pass, false);

  const intel = await json(
    "bench/render/results/local-intel-iris-xe-calibration.json",
  );
  const intelDigest = assertRenderCalibration(intel);
  assert.equal(intelDigest, softwareDigest);
  assert.equal(intel.environment.gpu_mode, "physical hardware");
  assert.equal(intel.gates.requested_backend.requested, "physical");
  assert.equal(intel.gates.requested_backend.observed, "physical");
  assert.equal(intel.environment.gpu.vendor_id, 0x8086);
  assert.equal(intel.environment.gpu.device_id, 0x46a8);
  assert.match(intel.environment.gpu.renderer, /Intel.*Iris.*Xe/);
  assert.doesNotMatch(intel.environment.gpu.renderer, /SwiftShader/i);
  assert.equal(intel.environment.gpu.hardware_supports_vulkan, true);
  assert.equal(intel.environment.gpu.feature_status.webgl, "enabled");
  assert.equal(intel.environment.gpu.feature_status.webgpu, "enabled");
  assert.equal(intel.gates.accelerated_over_css.ga_scope_pass, true);
  assert.equal(intel.gates.accelerated_latency.ga_scope_pass, true);

  const llvmpipe = await json(
    "bench/render/results/local-llvmpipe-calibration.json",
  );
  const llvmpipeDigest = assertRenderCalibration(llvmpipe);
  assert.equal(llvmpipeDigest, softwareDigest);
  assert.equal(llvmpipe.environment.gpu_mode, "llvmpipe software renderer");
  assert.equal(llvmpipe.gates.requested_backend.requested, "llvmpipe");
  assert.equal(llvmpipe.gates.requested_backend.observed, "llvmpipe");
  assert.match(llvmpipe.environment.gpu.renderer, /llvmpipe/i);
  assert.doesNotMatch(llvmpipe.environment.gpu.renderer, /SwiftShader/i);
  assert.equal(llvmpipe.environment.gpu.feature_status.webgl, "enabled");
  assert.equal(llvmpipe.method.browser_mode, "headed");
  assert.match(llvmpipe.method.container_image, /v1\.62\.1-noble@sha256:/);
  assert.equal(llvmpipe.results.webgpu.error, "webgpu_unavailable");
  assert.equal(llvmpipe.gates.accelerated_over_css.ga_scope_pass, false);
  assert.equal(llvmpipe.gates.accelerated_latency.ga_scope_pass, false);

  const amd = await json(
    "bench/render/results/local-amd-steam-deck-calibration.json",
  );
  const amdDigest = assertRenderCalibration(amd);
  assert.equal(amdDigest, softwareDigest);
  assert.equal(amd.environment.gpu_mode, "physical hardware");
  assert.equal(amd.environment.browser_transport, "remote-cdp");
  assert.equal(amd.method.page_transport, "ssh-reverse-tunnel");
  assert.equal(amd.gates.requested_backend.requested, "physical");
  assert.equal(amd.gates.requested_backend.observed, "physical");
  assert.equal(amd.environment.gpu.vendor_id, 0x1002);
  assert.equal(amd.environment.gpu.device_id, 0x163f);
  assert.match(amd.environment.gpu.renderer, /AMD.*RADV VANGOGH/i);
  assert.doesNotMatch(amd.environment.gpu.renderer, /SwiftShader|llvmpipe/i);
  assert.equal(amd.environment.gpu.hardware_supports_vulkan, true);
  assert.equal(amd.environment.gpu.feature_status.webgl, "enabled_readback");
  assert.equal(amd.environment.gpu.feature_status.webgpu, "enabled_readback");
  assert.equal(amd.gates.accelerated_over_css.ga_scope_pass, true);
  assert.equal(amd.gates.accelerated_latency.ga_scope_pass, false);

  const mali = await json(
    "bench/render/results/local-android-mali-g710-calibration.json",
  );
  const maliDigest = assertRenderCalibration(mali);
  assert.equal(maliDigest, softwareDigest);
  assert.equal(mali.environment.gpu_mode, "physical hardware");
  assert.equal(mali.environment.browser_transport, "remote-cdp");
  assert.equal(mali.method.browser_mode, "headed");
  assert.equal(mali.method.page_transport, "adb-reverse");
  assert.equal(mali.gates.requested_backend.requested, "physical");
  assert.equal(mali.gates.requested_backend.observed, "physical");
  assert.equal(mali.environment.gpu.vendor_id, 0x13b5);
  assert.match(mali.environment.gpu.renderer, /Mali-G710/i);
  assert.doesNotMatch(mali.environment.gpu.renderer, /SwiftShader|llvmpipe/i);
  assert.equal(mali.environment.gpu.hardware_supports_vulkan, true);
  assert.equal(mali.environment.gpu.feature_status.webgl, "enabled");
  assert.equal(mali.environment.gpu.feature_status.webgpu, "enabled");
  assert.equal(mali.gates.accelerated_over_css.ga_scope_pass, true);
  assert.equal(mali.gates.accelerated_latency.ga_scope_pass, false);

  const source = await readFile(
    new URL("../bench/render/browser-calibration.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /await rename\(temporary, destination\)/);
  assert.match(source, /SHAR_BENCH_GPU_MODE/);
  assert.match(source, /SHAR_BENCH_CDP_ENDPOINT/);
  assert.match(source, /SHAR_BENCH_EXECUTION_ENVIRONMENT/);
  assert.match(source, /SHAR_BENCH_PAGE_TRANSPORT/);
  assert.match(source, /SystemInfo\.getInfo/);
  assert.match(source, /--disable-software-rasterizer/);
  assert.match(source, /--use-angle=swiftshader/);
  assert.match(source, /--use-angle=gl/);
  assert.match(source, /--disable-webgpu/);
  assert.match(source, /observedMode === requestedMode/);
  assert.match(source, /ga_scope_pass: physicalDetected/);
  assert.match(source, /render calibration gates failed:/);

  const playwrightConfig = await readFile(
    new URL("../playwright.config.mjs", import.meta.url),
    "utf8",
  );
  const packageDocument = await json("package.json");
  const physicalRunner = await readFile(
    new URL("../scripts/test-browser-physical.mjs", import.meta.url),
    "utf8",
  );
  assert.match(playwrightConfig, /SHAR_TEST_PHYSICAL_GPU/);
  assert.match(playwrightConfig, /chromium-physical/);
  assert.match(playwrightConfig, /--disable-software-rasterizer/);
  assert.equal(
    packageDocument.scripts["test:browser:physical"],
    "npm run build && node scripts/test-browser-physical.mjs",
  );
  assert.match(physicalRunner, /SHAR_TEST_PHYSICAL_GPU: "1"/);
  assert.match(physicalRunner, /--project=chromium-physical/);

  const llvmpipeRunner = await readFile(
    new URL("../scripts/bench-render-llvmpipe.sh", import.meta.url),
    "utf8",
  );
  assert.equal(
    packageDocument.scripts["bench:render:llvmpipe"],
    "npm run build && bash scripts/bench-render-llvmpipe.sh",
  );
  assert.match(llvmpipeRunner, /GALLIUM_DRIVER=llvmpipe/);
  assert.match(llvmpipeRunner, /SHAR_BENCH_GPU_MODE=llvmpipe/);
  assert.match(llvmpipeRunner, /SHAR_BENCH_HEADED=1/);
  assert.match(llvmpipeRunner, /v1\.62\.1-noble@sha256:/);
  assert.match(llvmpipeRunner, /run-isolated-xvfb\.sh/);
  const xvfbRunner = await readFile(
    new URL("../scripts/run-isolated-xvfb.sh", import.meta.url),
    "utf8",
  );
  assert.match(xvfbRunner, /-nolisten tcp -ac/);
  assert.match(xvfbRunner, /\[\[ -S "\$socket" \]\]/);
  assert.match(xvfbRunner, /kill -0 "\$xvfb_pid"/);
});

test("published time-lock calibration keeps the lifetime estimate conservative and locally scoped", async () => {
  const result = await json(
    "bench/timelock/results/local-solver-calibration.json",
  );
  assert.equal(result.schema, "shar-timelock-solver-calibration-v1");
  assert.equal(result.method.modulus_bits, 2048);
  assert.equal(
    result.method.implementation,
    "pure JavaScript BigInt solveTimeLock",
  );
  assert.equal(result.default_policy.iteration_allowance_per_second, 100_000);
  assert.equal(result.default_policy.maximum_lifetime_seconds, 63_072_000);
  assert.equal(result.gate.pass, true);
  assert.equal(result.gate.ga_scope_pass, false);
  assert.ok(result.iterations_per_second.min >= result.gate.threshold);
});

test("live benchmark refuses to manufacture unavailable GA evidence", async () => {
  const source = await readFile(
    new URL("../bench/cap/live.mjs", import.meta.url),
    "utf8",
  );
  const worker = await readFile(
    new URL("../bench/cap/http-load-worker.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /SHAR_BENCH_ENDPOINT/);
  assert.match(source, /CAP_BENCH_SETTINGS_JSON/);
  assert.match(source, /SHAR_BENCH_RSS_INTERVAL_MS/);
  assert.match(source, /SHAR_BENCH_ACTION_CARDINALITY/);
  assert.match(source, /SHAR_BENCH_CLIENT_WORKERS/);
  assert.match(source, /rssSummary/);
  assert.match(source, /response_body_bytes/);
  assert.match(source, /new Worker/);
  assert.match(source, /partitionLoad/);
  assert.match(worker, /keepAlive: true/);
  assert.match(worker, /JSON\.parse\(text\)/);
  assert.match(worker, /elapsed_ms: response\.elapsed_ms/);
  assert.match(worker, /body_bytes: response\.bytes\.byteLength/);
  assert.match(source, /keepAlive: true/);
  assert.match(source, /maxSockets: concurrency/);
  assert.match(source, /response\.bytes\.byteLength/);
  assert.match(source, /latency is request start through response headers/);
  assert.match(source, /sharMetricSnapshot/);
  assert.match(source, /mean_engine_ms/);
  assert.match(source, /mean_handler_ms/);
  assert.match(source, /url\.origin.*url\.pathname/);
  assert.match(
    source,
    /accelerated_p95_and_energy:\s*\{\s*status: "not_measured"/,
  );
  assert.match(source, /attacker_cost_ratio:\s*\{\s*status: "not_measured"/);
  assert.doesNotMatch(source, /Math\.random/);
});

test("standalone benchmark publishes only complete paired runs", async () => {
  const source = await readFile(
    new URL("../bench/cap/standalone-local.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /stagedOutputDirectory/);
  assert.match(
    source,
    /for \(const \{ variant, repetition, result \} of rows\)[\s\S]*local-standalone-comparison\.json/,
  );
  assert.match(source, /await rename\(temporaryPath, path\)/);
  assert.match(source, /http_client_workers: clientWorkers/);
  assert.match(source, /SHAR_BENCH_CLIENT_WORKERS/);
  assert.match(source, /CAP_BENCH_PROTOCOL/);
  assert.match(source, /rsw: capSettings\.rsw/);
});

test("native issuance profiler retains an in-process Euclidean derivation baseline", async () => {
  const source = await readFile(
    new URL("../crates/shar-core/examples/issue-profile.rs", import.meta.url),
    "utf8",
  );
  assert.match(source, /derive_timelock_input/);
  assert.match(source, /euclidean_timelock_input/);
  assert.match(source, /euclidean_timelock_input_derivations_per_second/);
  assert.match(source, /cose_signing_per_second/);
});

test("RSS benchmark summaries retain baseline, peak, and final samples", () => {
  assert.deepEqual(rssSummary([120, { bytes: 256 }, { bytes: 192 }]), {
    sample_count: 3,
    baseline_rss_bytes: 120,
    peak_rss_bytes: 256,
    final_rss_bytes: 192,
  });
  assert.deepEqual(rssSummary([]), {
    sample_count: 0,
    baseline_rss_bytes: null,
    peak_rss_bytes: null,
    final_rss_bytes: null,
  });
});

test("standalone benchmark gates use all-run bounds and report variance", () => {
  assert.deepEqual(evaluateAllRunGate([2, 2.5, 3], 2, "minimum"), {
    threshold: 2,
    direction: "minimum",
    status: "pass",
    pass: true,
    observed_min: 2,
    observed_median: 2.5,
    observed_max: 3,
  });
  assert.equal(
    evaluateAllRunGate([1.9, 2.1], 2, "minimum").status,
    "inconclusive",
  );
  assert.equal(evaluateAllRunGate([0.1, 0.5], 0.5, "maximum").status, "pass");
  assert.equal(relativeStandardDeviation([10, 10, 10]), 0);
  assert.ok(relativeStandardDeviation([1, 10, 100]) > 1);
});

test("published local standalone evidence retains every paired run and conservative gate", async () => {
  const summary = await json(
    "bench/cap/results/local-standalone-comparison.json",
  );
  assert.equal(summary.schema, "shar-cap-local-standalone-comparison-v1");
  assert.equal(summary.scope.status, "local_reference_only");
  assert.equal(summary.inputs.repetitions, 3);
  assert.equal(summary.inputs.issue_operations, 3_000);
  assert.equal(summary.inputs.http_client_workers, 1);
  assert.equal(summary.inputs.shar_action_cardinality, 1);
  assert.equal(summary.inputs.shar_state, "redis");
  assert.equal(summary.raw_results.length, 6);
  const nativeRatios = [];
  const nativeIdleRatios = [];
  for (const file of summary.raw_results) {
    const result = await json(`bench/cap/results/${file}`);
    assert.equal(result.schema, "shar-cap-live-reference-v1");
    assert.equal(
      result.inputs.issue_operations,
      summary.inputs.issue_operations,
    );
    assert.equal(result.inputs.concurrency, summary.inputs.concurrency);
    assert.equal(
      result.inputs.http_client_workers,
      summary.inputs.http_client_workers,
    );
    assert.equal(
      result.inputs.shar_action_cardinality,
      summary.inputs.shar_action_cardinality,
    );
    assert.match(
      result.inputs.http_client,
      /fixed total concurrency.*HTTP\/1\.1 keep-alive/,
    );
    assert.equal(result.issuance.shar.server_observed.issued, 3_000);
    assert.ok(
      result.issuance.shar.server_observed.mean_handler_ms >=
        result.issuance.shar.server_observed.mean_engine_ms,
    );
    if (file.startsWith("rust-")) {
      nativeRatios.push(
        result.issuance.shar.operations_per_second /
          result.issuance.cap.operations_per_second,
      );
      nativeIdleRatios.push(
        result.idle_memory.shar_rss_bytes / result.idle_memory.cap_rss_bytes,
      );
    }
  }
  assert.deepEqual(
    summary.local_native_thresholds.throughput_at_least_2x_cap,
    evaluateAllRunGate(nativeRatios, 2, "minimum"),
  );
  assert.deepEqual(
    summary.local_native_thresholds.idle_memory_at_most_half_cap,
    evaluateAllRunGate(nativeIdleRatios, 0.5, "maximum"),
  );
});

test("published RSW standalone evidence is separate and passes every native run", async () => {
  const summary = await json(
    "bench/cap/results/rsw/local-standalone-comparison.json",
  );
  assert.equal(summary.schema, "shar-cap-local-standalone-comparison-v1");
  assert.equal(summary.scope.status, "local_reference_only");
  assert.equal(summary.inputs.repetitions, 3);
  assert.equal(summary.inputs.issue_operations, 3_000);
  assert.equal(summary.inputs.concurrency, 32);
  assert.equal(summary.inputs.http_client_workers, 8);
  assert.equal(summary.inputs.cap_settings.rsw, true);
  assert.equal(summary.inputs.cap_settings.rswT, 75_000);
  assert.equal(summary.raw_results.length, 6);
  const nativeRatios = [];
  for (const file of summary.raw_results) {
    const result = await json(`bench/cap/results/rsw/${file}`);
    assert.equal(result.inputs.cap_declared_settings.rsw, true);
    assert.equal(result.inputs.cap_declared_settings.rswT, 75_000);
    if (file.startsWith("rust-"))
      nativeRatios.push(
        result.issuance.shar.operations_per_second /
          result.issuance.cap.operations_per_second,
      );
  }
  assert.deepEqual(
    summary.local_native_thresholds.throughput_at_least_2x_cap,
    evaluateAllRunGate(nativeRatios, 2, "minimum"),
  );
  assert.equal(
    summary.local_native_thresholds.throughput_at_least_2x_cap.status,
    "pass",
  );
});

test("published pinned Cap behavior matrix covers policy and verification modes", async () => {
  const result = await json("bench/cap/results/local-cap-behavior-matrix.json");
  assert.equal(result.schema, "shar-cap-behavior-matrix-v1");
  assert.equal(result.cap.standalone.tag, "standalone@3.1.8");
  assert.deepEqual(result.cases.sha_pow_and_single_use_siteverify, {
    challenge_status: 200,
    challenge_format: "sha256-pow",
    redemption_status: 200,
    siteverify_status: 200,
    replay_status: 404,
  });
  assert.deepEqual(result.cases.rsw_and_siteverify.protocols, ["rsw"]);
  assert.equal(result.cases.rsw_and_siteverify.siteverify_status, 200);
  assert.equal(
    result.cases.instrumentation_policy_rejection.reason,
    "missing_instrumentation_response",
  );
  assert.equal(
    result.cases.user_agent_policy_rejection.non_browser_status,
    403,
  );
  assert.equal(
    result.cases.rate_limit_rejection.request_beyond_limit_status,
    429,
  );
  assert.equal(
    result.cases.invalid_proof_allows_replacement.replacement_challenge_status,
    200,
  );
});

test("economics evaluator requires calibrated samples and evaluates every sustained tier", async () => {
  const directory = await mkdtemp(join(tmpdir(), "shar-economics-"));
  const calibrationPath = join(directory, "calibration.json");
  const outputPath = join(directory, "result.json");
  const calibration = {
    schema: "shar-cap-calibration-v1",
    environment: {
      run_id: "fixture",
      captured_at: "2026-08-02T00:00:00Z",
      methodology_url: "https://example.test/methodology",
    },
    default_benign: {
      cap: { device: "reference", samples: 30, p95_ms: 100, median_joules: 10 },
      shar: { device: "reference", samples: 30, p95_ms: 80, median_joules: 8 },
    },
    attacker_equal_benign: {
      target_joules: 10,
      normalization_method: "fixture exact match",
      cap: {
        hardware: "reference",
        samples: 30,
        observed_benign_joules: 10,
        cost_usd_per_accepted_request: 0.01,
      },
      shar: {
        hardware: "reference",
        samples: 30,
        observed_benign_joules: 10,
        cost_usd_per_accepted_request: 0.02,
      },
    },
    sustained_abuse: {
      revenue_usd_per_accepted_request: 0.015,
      sustained_start_tier: 30,
      tiers: [30, 31, 32].map((tier, index) => ({
        tier,
        attacker_cost_usd_per_accepted_request: 0.02 + index * 0.01,
        samples: 30,
      })),
    },
  };
  await writeFile(calibrationPath, JSON.stringify(calibration));
  const result = await executeEconomics(calibrationPath, outputPath);
  assert.equal(result.code, 0, result.stderr);
  const evidence = JSON.parse(await readFile(outputPath, "utf8"));
  assert.ok(Object.values(evidence.gates).every((gate) => gate.pass));
  assert.deepEqual(
    evidence.gates.sustained_abuse_economics.tiers.map((row) => row.tier),
    [30, 31, 32],
  );

  calibration.attacker_equal_benign.shar.observed_benign_joules = 12;
  await writeFile(calibrationPath, JSON.stringify(calibration));
  const rejected = await executeEconomics(calibrationPath, outputPath);
  assert.notEqual(rejected.code, 0);
  assert.match(rejected.stderr, /above 5%/);
});

function executeEconomics(calibration, output) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["bench/cap/economics.mjs"], {
      cwd: fileURLToPath(new URL("../", import.meta.url)),
      env: {
        ...process.env,
        SHAR_BENCH_CALIBRATION: calibration,
        SHAR_BENCH_OUTPUT: output,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.once("error", reject);
    child.once("exit", (code) => resolve({ code, stdout, stderr }));
  });
}
