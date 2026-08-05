import { createServer } from "node:http";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import { distribution, environment, workspace } from "../cap/lib.mjs";

const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const configuredPort = Number(process.env.SHAR_BENCH_PORT ?? "0");
if (
  !Number.isSafeInteger(configuredPort) ||
  configuredPort < 0 ||
  configuredPort > 65_535
)
  throw new Error("SHAR_BENCH_PORT must be an integer from 0 to 65535");
const types = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
]);
const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (pathname === "/favicon.ico") {
      response.writeHead(204, { "cache-control": "no-store" });
      response.end();
      return;
    }
    const path = resolve(
      root,
      decodeURIComponent(pathname).replace(/^\/+/, ""),
    );
    if (path !== root && !path.startsWith(`${root}${sep}`))
      throw new Error("path");
    const bytes = await readFile(path);
    response.writeHead(200, {
      "content-type": types.get(extname(path)) ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    response.end(bytes);
  } catch {
    response.writeHead(404, { "content-type": "text/plain" });
    response.end("not found");
  }
});
await new Promise((resolvePromise, reject) => {
  server.once("error", reject);
  server.listen(configuredPort, "127.0.0.1", resolvePromise);
});
const address = server.address();
if (!address || typeof address === "string") throw new Error("benchmark_bind");
const base = `http://127.0.0.1:${address.port}`;
const pageBase = process.env.SHAR_BENCH_PAGE_BASE ?? base;
let pageBaseUrl;
try {
  pageBaseUrl = new URL(pageBase);
} catch {
  throw new Error("SHAR_BENCH_PAGE_BASE must be an absolute HTTP(S) URL");
}
if (
  !new Set(["http:", "https:"]).has(pageBaseUrl.protocol) ||
  pageBaseUrl.username ||
  pageBaseUrl.password ||
  pageBaseUrl.search ||
  pageBaseUrl.hash ||
  (pageBaseUrl.pathname !== "/" && pageBaseUrl.pathname !== "")
)
  throw new Error("SHAR_BENCH_PAGE_BASE must be an HTTP(S) origin");
const cdpEndpoint = process.env.SHAR_BENCH_CDP_ENDPOINT;
const configuredPageTransport = process.env.SHAR_BENCH_PAGE_TRANSPORT;
if (
  configuredPageTransport !== undefined &&
  !/^[a-z0-9-]{1,64}$/.test(configuredPageTransport)
)
  throw new Error(
    "SHAR_BENCH_PAGE_TRANSPORT must be a bounded lowercase label",
  );
let executionEnvironment;
if (cdpEndpoint) {
  const encoded = process.env.SHAR_BENCH_EXECUTION_ENVIRONMENT;
  if (!encoded || encoded.length > 4_096)
    throw new Error(
      "SHAR_BENCH_EXECUTION_ENVIRONMENT is required and bounded for remote CDP",
    );
  try {
    executionEnvironment = JSON.parse(encoded);
  } catch {
    throw new Error("SHAR_BENCH_EXECUTION_ENVIRONMENT must be JSON");
  }
  if (
    !executionEnvironment ||
    typeof executionEnvironment !== "object" ||
    Array.isArray(executionEnvironment)
  )
    throw new Error("SHAR_BENCH_EXECUTION_ENVIRONMENT must be a JSON object");
}

const requestedMode = process.env.SHAR_BENCH_GPU_MODE ?? "swiftshader";
if (!new Set(["physical", "swiftshader", "llvmpipe"]).has(requestedMode))
  throw new Error(
    "SHAR_BENCH_GPU_MODE must be physical, swiftshader, or llvmpipe",
  );
const headed = process.env.SHAR_BENCH_HEADED === "1";
const launchArguments = {
  physical: [
    "--enable-unsafe-webgpu",
    "--use-angle=vulkan",
    "--enable-features=Vulkan",
    "--disable-vulkan-surface",
    "--ignore-gpu-blocklist",
    "--disable-software-rasterizer",
  ],
  swiftshader: [
    "--enable-unsafe-webgpu",
    "--use-angle=swiftshader",
    "--use-webgpu-adapter=swiftshader",
    "--enable-unsafe-swiftshader",
  ],
  llvmpipe: [
    "--disable-webgpu",
    "--use-angle=gl",
    "--use-gl=angle",
    "--ignore-gpu-blocklist",
    "--disable-software-rasterizer",
  ],
}[requestedMode];
const browser = cdpEndpoint
  ? await chromium.connectOverCDP(cdpEndpoint)
  : await chromium.launch({
      headless: !headed,
      args: launchArguments,
    });
let browserVersion;
let gpu;
let measurements;
let consoleMessages;
try {
  browserVersion = browser.version();
  const cdp = await browser.newBrowserCDPSession();
  ({ gpu } = await cdp.send("SystemInfo.getInfo"));
  const remoteContext = cdpEndpoint ? browser.contexts()[0] : undefined;
  if (cdpEndpoint && !remoteContext)
    throw new Error("remote CDP browser has no default context");
  const page = remoteContext
    ? await remoteContext.newPage()
    : await browser.newPage({ viewport: { width: 1280, height: 720 } });
  if (remoteContext) await page.setViewportSize({ width: 1280, height: 720 });
  consoleMessages = [];
  page.on("console", (message) => {
    if (message.type() === "info" && message.text().startsWith("shar-bench:"))
      process.stderr.write(`${message.text()}\n`);
    if (["warning", "error"].includes(message.type()))
      consoleMessages.push(`${message.type()}: ${message.text()}`);
  });
  page.on("pageerror", (error) =>
    consoleMessages.push(`pageerror: ${error.message}`),
  );
  await page.goto(`${pageBaseUrl.origin}/test/browser/render-harness.html`);
  measurements = await page.evaluate(async () => {
    const [{ base64url }, rendering, executors] = await Promise.all([
      import("/dist/packages/server/src/bytes.js"),
      import("/dist/packages/server/src/rendering.js"),
      import("/dist/packages/widget/src/render-executors.js"),
    ]);
    const plan = {
      version: "render-v1",
      seed: base64url(new Uint8Array(32).fill(3)),
      rounds: 1,
      triangles: rendering.DEFAULT_RENDER_TRIANGLES,
      samples: rendering.DEFAULT_RENDER_SAMPLES,
    };
    const run = async (name, solve, repetitions) => {
      console.info(`shar-bench: starting ${name}`);
      const times = [];
      let digest = "";
      for (let index = 0; index < repetitions; index++) {
        const started = performance.now();
        digest = await solve(plan);
        times.push(performance.now() - started);
      }
      console.info(`shar-bench: completed ${name}`);
      return { name, digest, times };
    };
    const results = [await run("cpu", rendering.solveRendering, 5)];
    for (const [name, solve, repetitions] of [
      ["webgpu", executors.solveRenderingWebGpu, 5],
      ["webgl2", executors.solveRenderingWebGl2, 5],
      ["css", executors.solveRenderingCss, 1],
    ]) {
      try {
        results.push(await run(name, solve, repetitions));
      } catch (error) {
        console.info(`shar-bench: unavailable ${name}`);
        results.push({
          name,
          error: error instanceof Error ? error.message : String(error),
          times: [],
        });
      }
    }
    return { plan, results };
  });
} finally {
  await browser.close();
  await new Promise((resolvePromise) => server.close(resolvePromise));
}

const ignoredWarnings = [
  "GPU stall due to ReadPixels",
  "No available adapters",
  "Failed to create WebGL context",
];
const relevantConsoleMessages = consoleMessages.filter(
  (message) => !ignoredWarnings.some((ignored) => message.includes(ignored)),
);
if (relevantConsoleMessages.length)
  throw new Error(
    `browser console errors: ${relevantConsoleMessages.join("; ")}`,
  );
const device = gpu.devices[0];
if (!device) throw new Error("Chromium reported no rendering device");
const renderer = `${device.deviceString ?? ""} ${device.driverVendor ?? ""}`;
const llvmpipeDetected = /llvmpipe/i.test(renderer);
const swiftShaderDetected = /swiftshader|swangle/i.test(renderer);
const softwareDetected = swiftShaderDetected || llvmpipeDetected;
const physicalDetected = !softwareDetected && device.vendorId !== 65_535;
const observedMode = physicalDetected
  ? "physical"
  : llvmpipeDetected
    ? "llvmpipe"
    : swiftShaderDetected
      ? "swiftshader"
      : "unknown";
const requestedBackendMatched = observedMode === requestedMode;
const results = Object.fromEntries(
  measurements.results.map((result) => [
    result.name,
    {
      ...result,
      distribution: distribution(result.times),
    },
  ]),
);
const digests = Object.values(results)
  .map((result) => result.digest)
  .filter(Boolean);
const accelerated = [results.webgpu, results.webgl2].filter(
  (result) => result.distribution.median_ms !== null,
);
const fastestAccelerated = accelerated.reduce(
  (fastest, result) =>
    !fastest || result.distribution.median_ms < fastest.distribution.median_ms
      ? result
      : fastest,
  null,
);
const cssMedian = results.css.distribution.median_ms;
const speedup =
  fastestAccelerated && cssMedian !== null
    ? cssMedian / fastestAccelerated.distribution.median_ms
    : null;
const acceleratedTarget = fastestAccelerated?.distribution.median_ms ?? null;
const output = {
  schema: "shar-render-browser-calibration-v1",
  environment: {
    ...(executionEnvironment ?? environment()),
    coordinator: cdpEndpoint ? environment() : undefined,
    browser: browserVersion,
    browser_transport: cdpEndpoint ? "remote-cdp" : "local-launch",
    gpu_mode:
      observedMode === "physical"
        ? "physical hardware"
        : observedMode === "llvmpipe"
          ? "llvmpipe software renderer"
          : observedMode === "swiftshader"
            ? "software renderer"
            : "unknown renderer",
    gpu: {
      vendor_id: device.vendorId,
      device_id: device.deviceId,
      vendor: device.vendorString,
      renderer: device.deviceString,
      driver_vendor: device.driverVendor,
      driver_version: device.driverVersion,
      display_type: gpu.auxAttributes.displayType,
      gl_implementation: gpu.auxAttributes.glImplementationParts,
      hardware_supports_vulkan: gpu.auxAttributes.hardwareSupportsVulkan,
      feature_status: {
        gpu_compositing: gpu.featureStatus.gpu_compositing,
        rasterization: gpu.featureStatus.rasterization,
        vulkan: gpu.featureStatus.vulkan,
        webgl: gpu.featureStatus.webgl,
        webgpu: gpu.featureStatus.webgpu,
      },
    },
  },
  method: {
    viewport: "1280x720",
    browser_mode: headed ? "headed" : "headless",
    page_transport:
      configuredPageTransport ??
      (cdpEndpoint
        ? "remote-cdp-origin"
        : pageBaseUrl.origin === base
          ? "local-loopback"
          : "configured-origin"),
    container_image: process.env.SHAR_BENCH_CONTAINER_IMAGE ?? null,
    repetitions: { cpu: 5, webgpu: 5, webgl2: 5, css: 1 },
    timing: "cold executor setup included in every repetition",
    caveat:
      "GPU strings come from a benchmark-only privileged CDP session, never from the privacy-mode widget or challenge transcript.",
  },
  plan: {
    ...measurements.plan,
    predicates_per_round:
      measurements.plan.triangles * measurements.plan.samples,
  },
  results,
  console: {
    ignored_driver_warnings: consoleMessages.length,
    relevant_messages: relevantConsoleMessages,
  },
  gates: {
    requested_backend: {
      requirement:
        "the observed Chromium GPU process exactly matches the requested physical, SwiftShader, or llvmpipe backend",
      requested: requestedMode,
      observed: observedMode,
      pass: requestedBackendMatched,
    },
    bounded_million_scale: {
      requirement: "default round evaluates at least one million predicates",
      observed: measurements.plan.triangles * measurements.plan.samples,
      pass:
        measurements.plan.triangles * measurements.plan.samples >= 1_000_000,
    },
    identical_digest: {
      requirement: "every available executor returns the same digest",
      observed: [...new Set(digests)],
      pass: digests.length >= 2 && new Set(digests).size === 1,
    },
    accelerated_over_css: {
      requirement: "fastest accelerated executor is at least 10x CSS-only",
      fastest_backend: fastestAccelerated?.name ?? null,
      observed: speedup,
      pass: speedup !== null && speedup >= 10,
      ga_scope_pass: physicalDetected && speedup !== null && speedup >= 10,
    },
    accelerated_latency: {
      requirement: "default accelerated median targets 8-16 ms",
      fastest_backend: fastestAccelerated?.name ?? null,
      observed_ms: acceleratedTarget,
      provisional_pass:
        acceleratedTarget !== null &&
        acceleratedTarget >= 8 &&
        acceleratedTarget <= 16,
      ga_scope_pass:
        physicalDetected &&
        acceleratedTarget !== null &&
        acceleratedTarget >= 8 &&
        acceleratedTarget <= 16,
    },
    css_completion: {
      requirement: "CPU-only CSS execution eventually completes",
      observed_ms: cssMedian,
      pass: cssMedian !== null && results.css.digest === digests[0],
    },
  },
};
const destination = process.env.SHAR_BENCH_OUTPUT
  ? new URL(process.env.SHAR_BENCH_OUTPUT, workspace)
  : new URL("results/local-browser-calibration.json", import.meta.url);
await mkdir(new URL("./", destination), { recursive: true });
const temporary = new URL(`${destination.pathname}.tmp`, destination);
await writeFile(temporary, `${JSON.stringify(output, null, 2)}\n`);
await rename(temporary, destination);
console.log(JSON.stringify(output, null, 2));
const failedGates = Object.entries(output.gates)
  .filter(([, gate]) => gate.pass === false)
  .map(([name]) => name);
if (failedGates.length)
  throw new Error(`render calibration gates failed: ${failedGates.join(", ")}`);
