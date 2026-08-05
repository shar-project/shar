import { brotliCompressSync, constants, gzipSync } from "node:zlib";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { environment, inputs, manifest, sha256, workspace } from "./lib.mjs";
import { buildWidgetBundle } from "./widget-bundle.mjs";

const expected = await manifest();
const capWidgetPath = new URL("extracted/widget/package/cap.min.js", inputs);
const capWasmPath = new URL(
  `extracted/wasm/package/${expected.wasm.browserPath}`,
  inputs,
);
try {
  await readFile(capWidgetPath);
  await readFile(capWasmPath);
} catch {
  throw new Error(
    "Cap artifacts are not prepared; run npm run bench:cap:prepare first",
  );
}

function sizes(bytes) {
  return {
    raw: bytes.length,
    gzip: gzipSync(bytes, { level: 9 }).length,
    brotli: brotliCompressSync(bytes, {
      params: { [constants.BROTLI_PARAM_QUALITY]: 11 },
    }).length,
    sha256: sha256(bytes),
  };
}

function aggregate(resources) {
  const measured = resources.map(({ name, bytes }) => ({
    name,
    ...sizes(bytes),
  }));
  return {
    resources: measured,
    raw: measured.reduce((total, resource) => total + resource.raw, 0),
    gzip: measured.reduce((total, resource) => total + resource.gzip, 0),
    brotli: measured.reduce((total, resource) => total + resource.brotli, 0),
    sha256: sha256(
      Buffer.concat(
        resources.flatMap(({ name, bytes }) => [
          Buffer.from(`${name}\0`),
          bytes,
        ]),
      ),
    ),
  };
}

const bundle = await buildWidgetBundle();
let shar;
try {
  shar = {
    javascript: aggregate(bundle.eager),
    optional_lazy_javascript: aggregate(bundle.lazy),
  };
} finally {
  await bundle.dispose();
}
const [capJs, capWasm] = await Promise.all([
  readFile(capWidgetPath),
  readFile(capWasmPath),
]);
const cap = { javascript: sizes(capJs), wasm: sizes(capWasm) };
for (const encoding of ["raw", "gzip", "brotli"]) {
  shar[`${encoding}_total`] = shar.javascript[encoding];
  cap[`${encoding}_total`] = cap.javascript[encoding] + cap.wasm[encoding];
}
const ratio = Object.fromEntries(
  ["raw", "gzip", "brotli"].map((encoding) => [
    encoding,
    shar[`${encoding}_total`] / cap[`${encoding}_total`],
  ]),
);
const result = {
  schema: "shar-cap-artifact-bytes-v1",
  environment: environment(),
  inputs: {
    shar_version: JSON.parse(
      await readFile(new URL("package.json", workspace), "utf8"),
    ).version,
    cap_widget: expected.widget,
    cap_wasm: expected.wasm,
  },
  method: {
    shar: "Minified Rolldown production ESM bundle of @shar/widget; totals include every statically imported chunk and report optional dynamic chunks separately",
    cap: "Published cap-widget cap.min.js plus eagerly fetched @cap.js/wasm browser binary",
    compression:
      "gzip level 9 and Brotli quality 11, cold cache, response bodies only",
    exclusions: [
      "HTTP headers",
      "challenge and redemption payloads",
      "optional dynamically loaded trust-credit cryptography",
      "optional locale entry points selected by the host application",
      "instrumentation fallback pako download",
    ],
  },
  shar,
  cap,
  shar_over_cap: ratio,
  gate: {
    requirement: "Shar default cold-path bytes <= 80% of Cap equivalent path",
    encoding: "brotli",
    threshold: 0.8,
    observed: ratio.brotli,
    pass: ratio.brotli <= 0.8,
    scope: "artifact-only; browser network capture remains required for GA",
  },
};
const output = process.env.SHAR_BENCH_OUTPUT
  ? new URL(process.env.SHAR_BENCH_OUTPUT, workspace)
  : new URL("results/local-artifact-bytes.json", import.meta.url);
await mkdir(new URL("./", output), { recursive: true });
await writeFile(output, `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify(result, null, 2));
