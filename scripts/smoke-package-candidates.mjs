import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [installation, expectedVersion] = process.argv.slice(2);
if (
  !installation ||
  !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
    expectedVersion ?? "",
  )
)
  throw new Error(
    "usage: smoke-package-candidates.mjs INSTALLATION STABLE_VERSION",
  );

const modules = resolve(installation, "node_modules");
const definitions = [
  ["server", "@shar/server", {}],
  ["widget", "@shar/widget", { "@shar/server": expectedVersion }],
  ["cap-compat", "@shar/cap-compat", { "@shar/widget": expectedVersion }],
];

for (const [directory, name, dependencies] of definitions) {
  const manifest = JSON.parse(
    await readFile(
      resolve(modules, "@shar", directory, "package.json"),
      "utf8",
    ),
  );
  assert.equal(manifest.name, name);
  assert.equal(manifest.version, expectedVersion);
  assert.equal(manifest.license, "MIT");
  assert.equal(manifest.main, "./dist/index.js");
  assert.equal(manifest.types, "./dist/index.d.ts");
  for (const [dependency, version] of Object.entries(dependencies))
    assert.equal(manifest.dependencies?.[dependency], version);
  await readFile(resolve(modules, "@shar", directory, "LICENSE"), "utf8");
  await readFile(
    resolve(modules, "@shar", directory, "dist/index.d.ts"),
    "utf8",
  );
  if (name === "@shar/widget") {
    assert.equal(
      manifest.exports?.["./timelock.wasm"],
      "./wasm/shar_timelock.wasm",
    );
    await readFile(
      resolve(modules, "@shar", directory, "wasm/shar_timelock.wasm"),
    );
    assert.equal(
      manifest.exports?.["./trust-credits"]?.import,
      "./dist/trust-credits.js",
    );
    await readFile(
      resolve(modules, "@shar", directory, "dist/trust-credits.d.ts"),
    );
  }
  if (name === "@shar/server") {
    for (const entry of ["browser", "trust"]) {
      assert.equal(
        manifest.exports?.[`./${entry}`]?.import,
        `./dist/${entry}.js`,
      );
      await readFile(
        resolve(modules, "@shar", directory, `dist/${entry}.d.ts`),
      );
    }
  }
}

const server = await import(
  pathToFileURL(resolve(modules, "@shar/server/dist/index.js")).href
);
assert.equal(typeof server.createSharHandler, "function");
assert.equal(typeof server.solveRendering, "function");

const previousHTMLElement = globalThis.HTMLElement;
const previousCustomElements = globalThis.customElements;
globalThis.HTMLElement = class {};
globalThis.customElements = {
  get: () => undefined,
  define: () => undefined,
};
try {
  const widget = await import(
    pathToFileURL(resolve(modules, "@shar/widget/dist/index.js")).href
  );
  const trustCredits = await import(
    pathToFileURL(resolve(modules, "@shar/widget/dist/trust-credits.js")).href
  );
  const compatibility = await import(
    pathToFileURL(resolve(modules, "@shar/cap-compat/dist/index.js")).href
  );
  assert.equal(typeof widget.Shar.execute, "function");
  assert.equal(typeof widget.solveRenderingAdaptive, "function");
  assert.equal(typeof widget.instantiateTimeLockWasm, "function");
  assert.equal(typeof trustCredits.prepareTrustCreditIssuance, "function");
  assert.equal(typeof compatibility.CapWidgetCompatibility, "function");
} finally {
  if (previousHTMLElement === undefined) delete globalThis.HTMLElement;
  else globalThis.HTMLElement = previousHTMLElement;
  if (previousCustomElements === undefined) delete globalThis.customElements;
  else globalThis.customElements = previousCustomElements;
}

console.log(`installed package candidates passed for ${expectedVersion}`);
