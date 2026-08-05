import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { checkRelease } from "../scripts/check-release.mjs";

test("release metadata includes synchronized package and Cargo lockfiles", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );
  const tag = `v${manifest.version}`;
  assert.equal(
    await checkRelease(tag),
    `release metadata and lockfiles are consistent for ${tag}`,
  );
});

test("release metadata rejects non-stable or non-canonical tags", async () => {
  for (const tag of ["0.1.0", "v01.0.0", "v0.1.0-beta.1", "v0.1"])
    await assert.rejects(
      () => checkRelease(tag),
      /release tag must be a stable SemVer tag/,
    );
});

test("published WASM builds remap host paths before byte comparison", async () => {
  const script = await readFile(
    new URL("../scripts/build-widget-wasm.sh", import.meta.url),
    "utf8",
  );
  assert.match(script, /--remap-path-prefix=\$repo_root=\/src/);
  assert.match(script, /--remap-path-prefix=\$cargo_home=\/cargo/);
  assert.match(script, /CARGO_ENCODED_RUSTFLAGS="\$encoded_rustflags"/);
  assert.match(script, /CARGO_TARGET_DIR="\$repo_root\/target"/);
});

test("external store interop enables assurance only behind loopback trust", async () => {
  const script = await readFile(
    new URL("../test/standalone-external-interop.sh", import.meta.url),
    "utf8",
  );
  assert.equal(
    script.match(/SHAR_TRUSTED_PROXY_CIDRS=127\.0\.0\.1\/32/g)?.length,
    1,
  );
  assert.equal(script.match(/SHAR_ASSURANCE_MODE=trusted-header/g)?.length, 1);
  assert.equal(script.match(/"\$\{common_environment\[@\]\}"/g)?.length, 2);
});

test("container publication waits for npm publication", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );
  const containers = workflow.slice(workflow.indexOf("  containers:\n"));
  assert.match(containers, /needs: \[container-security, packages\]/);
  assert.doesNotMatch(containers, /needs: container-security(?:\n|$)/);
});
