import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, parse } from "node:path";
import test from "node:test";
import {
  canonicalAdminRoot,
  decodeAdminRelative,
  resolveAdminAsset,
} from "../standalone/js/admin-assets.mjs";

test("admin assets stay inside their canonical root", () => {
  const temporary = mkdtempSync(join(tmpdir(), "shar-admin-assets-"));
  try {
    const root = join(temporary, "admin");
    const outside = join(temporary, "outside.txt");
    mkdirSync(root);
    writeFileSync(join(root, "index.html"), "safe");
    writeFileSync(outside, "secret");
    symlinkSync(outside, join(root, "leak.txt"));

    const canonical = canonicalAdminRoot(root);
    assert.equal(
      resolveAdminAsset(canonical, "index.html"),
      join(root, "index.html"),
    );
    assert.equal(resolveAdminAsset(canonical, "../outside.txt"), undefined);
    assert.equal(resolveAdminAsset(canonical, "leak.txt"), undefined);
    assert.equal(resolveAdminAsset(canonical, "missing.txt"), undefined);
    assert.equal(decodeAdminRelative("/admin/%ZZ"), undefined);
    assert.throws(
      () => canonicalAdminRoot(join(temporary, "missing")),
      /cannot read SHAR_ADMIN_ASSETS/,
    );
    assert.throws(
      () => canonicalAdminRoot(parse(temporary).root),
      /must not be a filesystem root/,
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
