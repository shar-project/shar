import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  SHAR_TIMELOCK_WASM_SHA256,
  instantiateTimeLockWasm,
  loadTimeLockWasm,
} from "../packages/widget/dist/time-lock-wasm.js";

const artifact = await readFile(
  new URL("../packages/widget/wasm/shar_timelock.wasm", import.meta.url),
);

test("pinned Rust/WASM time-lock artifact matches JS sequential squaring", async () => {
  assert.equal(
    createHash("sha256").update(artifact).digest("hex"),
    SHAR_TIMELOCK_WASM_SHA256,
  );
  assert.ok(artifact.byteLength < 128 * 1024);
  const accelerator = await instantiateTimeLockWasm(artifact);
  const modulus = 1_000_036_000_099n;
  let expected = 123_456_789n;
  for (let iteration = 0; iteration < 37; iteration++)
    expected = (expected * expected) % modulus;
  const modulusBytes = new Uint8Array(8);
  let remaining = modulus;
  for (let index = modulusBytes.length - 1; index >= 0; index--) {
    modulusBytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  assert.equal(
    accelerator.squareChunk(modulusBytes, 123_456_789n, 37),
    expected,
  );
  assert.equal(accelerator.squareChunk(new Uint8Array([17]), 2n, 0), 2n);
  assert.throws(
    () => accelerator.squareChunk(new Uint8Array([17]), 17n, 1),
    /timelock_wasm_execution/,
  );
  assert.throws(
    () => accelerator.squareChunk(new Uint8Array([17]), 2n, 65_537),
    /timelock_wasm_bounds/,
  );
});

test("WASM remains opt-in and an unavailable runtime preserves JS fallback", async () => {
  assert.equal(await loadTimeLockWasm(false), undefined);
  assert.equal(await loadTimeLockWasm(undefined), undefined);
  const original = globalThis.WebAssembly;
  try {
    Object.defineProperty(globalThis, "WebAssembly", {
      configurable: true,
      value: undefined,
    });
    await assert.rejects(
      () => instantiateTimeLockWasm(artifact),
      /timelock_wasm_unavailable/,
    );
  } finally {
    Object.defineProperty(globalThis, "WebAssembly", {
      configurable: true,
      value: original,
    });
  }
});
