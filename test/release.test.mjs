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
