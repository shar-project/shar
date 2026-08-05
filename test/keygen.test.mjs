import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { base64url } from "../dist/packages/server/src/index.js";

const workspace = new URL("../", import.meta.url);

test("pure-JavaScript rotation preserves overlap material and site credentials", async () => {
  const directory = await mkdtemp(join(tmpdir(), "shar-keygen-test-"));
  const input = join(directory, "old.json");
  const output = join(directory, "next.json");
  const modulus = new Uint8Array(256);
  modulus[0] = 0x80;
  modulus[255] = 0x01;
  const old = {
    SHAR_SIGNING_SEED: base64url(new Uint8Array(32).fill(7)),
    SHAR_KEY_ID: base64url(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])),
    SHAR_RSW_MODULUS: base64url(modulus),
    SHAR_RSW_LAMBDA: base64url(new Uint8Array([1, 2, 3])),
    SHAR_RSW_ID: "rsw-old",
    SHAR_NETWORK_SECRET: base64url(new Uint8Array(32).fill(8)),
    SHAR_FALLBACK_SECRET: base64url(new Uint8Array(32).fill(9)),
    SHAR_ADMIN_SECRET: base64url(new Uint8Array(32).fill(10)),
    SHAR_SITEVERIFY_MASTER_SECRET: base64url(new Uint8Array(32).fill(11)),
    SHAR_TRUST_SEED: base64url(new Uint8Array(32).fill(13)),
    SHAR_TRUST_KEY_ID: base64url(new Uint8Array([13, 14, 15, 16])),
    SHAR_PREVIOUS_VERIFY_KEYS: JSON.stringify([
      { kid: "prior", x: base64url(new Uint8Array(32).fill(12)) },
    ]),
    SHAR_PREVIOUS_RSW_KEYS: JSON.stringify([
      { id: "rsw-prior", modulus: "AA", lambda: "AQ" },
    ]),
  };
  await writeFile(input, `${JSON.stringify(old)}\n`, { mode: 0o600 });
  await run(
    "standalone/js/keygen.mjs",
    "rotate",
    "--input",
    input,
    "--output",
    output,
  );
  const next = JSON.parse(await readFile(output, "utf8"));
  const previousVerify = JSON.parse(next.SHAR_PREVIOUS_VERIFY_KEYS);
  const previousRsw = JSON.parse(next.SHAR_PREVIOUS_RSW_KEYS);
  assert.equal(previousVerify[0].kid, old.SHAR_KEY_ID);
  assert.equal(previousVerify[1].kid, "prior");
  assert.equal(previousRsw[0].id, old.SHAR_RSW_ID);
  assert.equal(previousRsw[1].id, "rsw-prior");
  assert.equal(next.SHAR_NETWORK_SECRET, old.SHAR_NETWORK_SECRET);
  assert.equal(
    next.SHAR_SITEVERIFY_MASTER_SECRET,
    old.SHAR_SITEVERIFY_MASTER_SECRET,
  );
  const previousTrust = JSON.parse(next.SHAR_PREVIOUS_TRUST_KEYS);
  assert.deepEqual(previousTrust[0], {
    seed: old.SHAR_TRUST_SEED,
    key_id: old.SHAR_TRUST_KEY_ID,
  });
  assert.notEqual(next.SHAR_TRUST_SEED, old.SHAR_TRUST_SEED);
  assert.notEqual(next.SHAR_TRUST_KEY_ID, old.SHAR_TRUST_KEY_ID);
  if (process.platform !== "win32")
    assert.equal((await stat(output)).mode & 0o077, 0);
  await assert.rejects(
    () =>
      run(
        "standalone/js/keygen.mjs",
        "rotate",
        "--input",
        input,
        "--output",
        output,
      ),
    /EEXIST|already exists/,
  );
});

async function run(...argumentsList) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, argumentsList, {
      cwd: new URL(workspace),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(stderr || `keygen exited ${code}`));
    });
  });
}
