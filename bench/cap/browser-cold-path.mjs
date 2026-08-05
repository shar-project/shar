import { createServer } from "node:http";
import { brotliCompressSync, constants } from "node:zlib";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { chromium } from "@playwright/test";
import { environment, inputs, manifest, workspace } from "./lib.mjs";
import { buildWidgetBundle } from "./widget-bundle.mjs";

const expected = await manifest();
const paths = {
  cap: new URL("extracted/widget/package/cap.min.js", inputs),
  wasm: new URL(`extracted/wasm/package/${expected.wasm.browserPath}`, inputs),
};
try {
  await readFile(paths.cap);
  await readFile(paths.wasm);
} catch {
  throw new Error(
    "Cap artifacts are not prepared; run npm run bench:cap:prepare first",
  );
}
const bundle = await buildWidgetBundle();
const sharPaths = bundle.eager.map(({ name }) => `/assets/shar/${name}`);
if (!sharPaths.includes("/assets/shar/shar.js"))
  throw new Error("Shar browser bundle entry is missing");

const quality = { [constants.BROTLI_PARAM_QUALITY]: 11 };
const assets = new Map();
for (const { name, bytes: raw } of [...bundle.eager, ...bundle.lazy]) {
  assets.set(`/assets/shar/${name}`, {
    raw,
    encoded: brotliCompressSync(raw, { params: quality }),
    type: "text/javascript; charset=utf-8",
  });
}
for (const [name, url, type] of [
  ["/assets/cap.js", paths.cap, "text/javascript; charset=utf-8"],
  ["/assets/cap.wasm", paths.wasm, "application/wasm"],
]) {
  const raw = await readFile(url);
  assets.set(name, {
    raw,
    encoded: brotliCompressSync(raw, { params: quality }),
    type,
  });
}
const csp =
  "default-src 'self'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; worker-src blob:; frame-src 'none'; base-uri 'none'";
function page(kind) {
  const scripts =
    kind === "shar"
      ? '<script type="module" src="/assets/shar/shar.js"></script>'
      : '<script src="/cap-config.js"></script><script src="/assets/cap.js"></script>';
  return `<!doctype html><html><head><meta charset="utf-8"><title>${kind}</title>${scripts}</head><body></body></html>`;
}
const server = createServer((request, response) => {
  const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
  if (path === "/shar/" || path === "/cap/") {
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": csp,
      "cache-control": "no-store",
    });
    response.end(page(path === "/shar/" ? "shar" : "cap"));
    return;
  }
  if (path === "/cap-config.js") {
    response.writeHead(200, {
      "content-type": "text/javascript; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end(
      'window.CAP_CUSTOM_WASM_URL="/assets/cap.wasm";window.CAP_SILENT=true;window.CAP_DISABLE_HAPTICS=true;',
    );
    return;
  }
  const asset = assets.get(path);
  if (asset) {
    response.writeHead(200, {
      "content-type": asset.type,
      "content-encoding": "br",
      "content-length": asset.encoded.length,
      "cache-control": "no-store",
      "timing-allow-origin": "*",
      vary: "accept-encoding",
    });
    response.end(asset.encoded);
    return;
  }
  response.writeHead(404).end();
});
await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});
const address = server.address();
if (!address || typeof address === "string")
  throw new Error("benchmark server did not bind TCP");
const base = `http://127.0.0.1:${address.port}`;

const browser = await chromium
  .launch({ headless: true })
  .catch(async (error) => {
    await new Promise((resolve) => server.close(resolve));
    await bundle.dispose();
    throw error;
  });
async function capture(kind, expectedPaths) {
  const context = await browser.newContext({ serviceWorkers: "block" });
  const page = await context.newPage();
  const observed = [];
  page.on("request", (request) =>
    observed.push(new URL(request.url()).pathname),
  );
  await page.goto(`${base}/${kind}/`, { waitUntil: "networkidle" });
  await page.waitForFunction(
    (paths) =>
      paths.every((path) =>
        performance
          .getEntriesByType("resource")
          .some((entry) => new URL(entry.name).pathname === path),
      ),
    expectedPaths,
  );
  const entries = await page.evaluate(
    (paths) =>
      performance
        .getEntriesByType("resource")
        .filter((entry) => paths.includes(new URL(entry.name).pathname))
        .map((entry) => ({
          path: new URL(entry.name).pathname,
          transfer_size: entry.transferSize,
          encoded_body_size: entry.encodedBodySize,
          decoded_body_size: entry.decodedBodySize,
          duration_ms: entry.duration,
        })),
    expectedPaths,
  );
  const external = observed.filter(
    (path) =>
      !["/shar/", "/cap/", "/cap-config.js", ...expectedPaths].includes(path),
  );
  if (external.length)
    throw new Error(`${kind} made unexpected requests: ${external.join(", ")}`);
  for (const path of expectedPaths) {
    if (!entries.some((entry) => entry.path === path))
      throw new Error(`${kind} did not load ${path}`);
  }
  await context.close();
  return {
    resources: entries,
    encoded_body_total: entries.reduce(
      (total, entry) => total + entry.encoded_body_size,
      0,
    ),
    transfer_total: entries.reduce(
      (total, entry) => total + entry.transfer_size,
      0,
    ),
    unexpected_requests: external,
  };
}

let shar, cap;
try {
  shar = await capture("shar", sharPaths);
  cap = await capture("cap", ["/assets/cap.js", "/assets/cap.wasm"]);
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
  await bundle.dispose();
}
const ratio = shar.encoded_body_total / cap.encoded_body_total;
const result = {
  schema: "shar-cap-browser-cold-path-v1",
  environment: {
    ...environment(),
    browser: "Chromium",
    playwright: JSON.parse(
      await readFile(
        new URL(
          "../../node_modules/@playwright/test/package.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ).version,
  },
  inputs: { cap_widget: expected.widget, cap_wasm: expected.wasm },
  method: {
    cache:
      "new browser context per product; Cache-Control no-store; service workers blocked",
    transport: "loopback HTTP with Brotli quality 11 and Resource Timing",
    shar_resources: sharPaths,
    cap_resources: [
      "published cap.min.js",
      "eagerly fetched published browser WASM",
    ],
    excluded: [
      "HTML",
      "benchmark-only Cap URL configuration script",
      "optional dynamically loaded Shar trust-credit chunks",
      "optional Shar locale entry points selected by the host application",
      "HTTP/2 or HTTP/3 framing",
    ],
  },
  shar,
  cap,
  shar_over_cap_encoded_body: ratio,
  gate: {
    requirement: "Shar default cold-path bytes <= 80% of Cap equivalent path",
    threshold: 0.8,
    observed: ratio,
    pass: ratio <= 0.8,
    scope:
      "cold-cache Chromium network capture; remaining browser/device matrix is still required",
  },
};
const output = process.env.SHAR_BENCH_OUTPUT
  ? new URL(process.env.SHAR_BENCH_OUTPUT, workspace)
  : new URL("results/local-browser-cold-path.json", import.meta.url);
await mkdir(new URL("./", output), { recursive: true });
await writeFile(output, `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify(result, null, 2));
