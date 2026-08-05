import { bigintToBytes, bytesToBigint } from "@shar/server/browser";

export const SHAR_TIMELOCK_WASM_SHA256 =
  "abfe1fde6d133526abe811ecd19cdc251e7595f5910cdad46d21800b2f20cde8";

export type TimeLockWasmOption = boolean | string | URL;

interface TimeLockWasmExports extends WebAssembly.Exports {
  memory: WebAssembly.Memory;
  shar_alloc(length: number): number;
  shar_dealloc(pointer: number, capacity: number): void;
  shar_square_chunk(
    modulusPointer: number,
    modulusLength: number,
    valuePointer: number,
    valueLength: number,
    iterations: number,
    outputPointer: number,
    outputCapacity: number,
  ): number;
}

export interface TimeLockWasmAccelerator {
  squareChunk(modulus: Uint8Array, value: bigint, iterations: number): bigint;
}

const instances = new Map<string, Promise<TimeLockWasmAccelerator>>();

/** Instantiate validated module bytes without filesystem or Node APIs. */
export async function instantiateTimeLockWasm(
  bytes: BufferSource,
): Promise<TimeLockWasmAccelerator> {
  if (typeof WebAssembly === "undefined")
    throw new Error("timelock_wasm_unavailable");
  const result = await WebAssembly.instantiate(bytes, {});
  const instance =
    result instanceof WebAssembly.Instance ? result : result.instance;
  const exports = instance.exports as unknown as Partial<TimeLockWasmExports>;
  if (
    !(exports.memory instanceof WebAssembly.Memory) ||
    typeof exports.shar_alloc !== "function" ||
    typeof exports.shar_dealloc !== "function" ||
    typeof exports.shar_square_chunk !== "function"
  )
    throw new Error("timelock_wasm_exports");
  const complete = exports as TimeLockWasmExports;
  return {
    squareChunk(modulus, value, iterations): bigint {
      if (
        modulus.length < 1 ||
        modulus.length > 512 ||
        value < 0n ||
        !Number.isSafeInteger(iterations) ||
        iterations < 0 ||
        iterations > 65_536
      )
        throw new Error("timelock_wasm_bounds");
      const valueBytes = bigintToBytes(value);
      if (valueBytes.length > modulus.length)
        throw new Error("timelock_wasm_bounds");
      const allocations: Array<readonly [number, number]> = [];
      const allocate = (length: number): number => {
        const pointer = complete.shar_alloc(length);
        if (!Number.isSafeInteger(pointer) || pointer <= 0)
          throw new Error("timelock_wasm_allocation");
        allocations.push([pointer, length]);
        return pointer;
      };
      try {
        const modulusPointer = allocate(modulus.length);
        const valuePointer = allocate(valueBytes.length);
        const outputPointer = allocate(modulus.length);
        new Uint8Array(
          complete.memory.buffer,
          modulusPointer,
          modulus.length,
        ).set(modulus);
        new Uint8Array(
          complete.memory.buffer,
          valuePointer,
          valueBytes.length,
        ).set(valueBytes);
        const outputLength = complete.shar_square_chunk(
          modulusPointer,
          modulus.length,
          valuePointer,
          valueBytes.length,
          iterations,
          outputPointer,
          modulus.length,
        );
        if (outputLength < 1 || outputLength > modulus.length)
          throw new Error("timelock_wasm_execution");
        return bytesToBigint(
          new Uint8Array(
            complete.memory.buffer,
            outputPointer,
            outputLength,
          ).slice(),
        );
      } finally {
        for (const [pointer, capacity] of allocations.reverse())
          complete.shar_dealloc(pointer, capacity);
      }
    },
  };
}

/** Best-effort opt-in loader. Failure always leaves the JS solver available. */
export async function loadTimeLockWasm(
  option: TimeLockWasmOption | undefined,
): Promise<TimeLockWasmAccelerator | undefined> {
  if (!option) return undefined;
  try {
    const url =
      option === true
        ? new URL("../wasm/shar_timelock.wasm", import.meta.url)
        : new URL(String(option), location.href);
    const key = url.href;
    let pending = instances.get(key);
    if (!pending) {
      pending = fetch(url, { credentials: "same-origin" })
        .then((response) => {
          if (!response.ok)
            throw new Error(`timelock_wasm_http_${response.status}`);
          return response.arrayBuffer();
        })
        .then(instantiateTimeLockWasm);
      instances.set(key, pending);
      void pending.catch(() => instances.delete(key));
    }
    return await pending;
  } catch {
    return undefined;
  }
}
