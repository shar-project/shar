import { concatBytes, utf8, utf8Decode } from "./bytes.js";

export type Cbor =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | Cbor[]
  | Map<Cbor, Cbor>;

export const MAX_CBOR_DEPTH = 64;
export const MAX_CBOR_ITEMS = 4_096;

function head(major: number, value: bigint): Uint8Array {
  if (value < 0n) throw new Error("negative_length");
  if (value < 24n) return new Uint8Array([(major << 5) | Number(value)]);
  let width: 1 | 2 | 4 | 8;
  let info: number;
  if (value <= 0xffn) {
    width = 1;
    info = 24;
  } else if (value <= 0xffffn) {
    width = 2;
    info = 25;
  } else if (value <= 0xffffffffn) {
    width = 4;
    info = 26;
  } else if (value <= 0xffffffffffffffffn) {
    width = 8;
    info = 27;
  } else throw new Error("cbor_integer_overflow");
  const out = new Uint8Array(1 + width);
  out[0] = (major << 5) | info;
  let current = value;
  for (let i = width; i > 0; i--) {
    out[i] = Number(current & 255n);
    current >>= 8n;
  }
  return out;
}

export function encodeCbor(value: Cbor): Uint8Array {
  if (value === null) return new Uint8Array([0xf6]);
  if (typeof value === "boolean") return new Uint8Array([value ? 0xf5 : 0xf4]);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("cbor_requires_integer");
    return value >= 0 ? head(0, BigInt(value)) : head(1, BigInt(-1 - value));
  }
  if (typeof value === "bigint")
    return value >= 0n ? head(0, value) : head(1, -1n - value);
  if (typeof value === "string") {
    const bytes = utf8(value);
    return concatBytes(head(3, BigInt(bytes.length)), bytes);
  }
  if (value instanceof Uint8Array)
    return concatBytes(head(2, BigInt(value.length)), value);
  if (Array.isArray(value))
    return concatBytes(head(4, BigInt(value.length)), ...value.map(encodeCbor));
  if (value instanceof Map) {
    const entries = Array.from(value, ([key, item]) => ({
      key: encodeCbor(key),
      item: encodeCbor(item),
    }));
    entries.sort(
      (a, b) => a.key.length - b.key.length || compare(a.key, b.key),
    );
    for (let index = 1; index < entries.length; index++) {
      const previous = entries[index - 1]!.key;
      const current = entries[index]!.key;
      if (
        previous.length === current.length &&
        compare(previous, current) === 0
      )
        throw new Error("duplicate_map_key");
    }
    return concatBytes(
      head(5, BigInt(entries.length)),
      ...entries.flatMap(({ key, item }) => [key, item]),
    );
  }
  throw new Error("unsupported_cbor_value");
}

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

export function decodeCbor(bytes: Uint8Array): Cbor {
  let offset = 0;
  let items = 0;
  function take(depth: number): Cbor {
    if (depth > MAX_CBOR_DEPTH) throw new Error("cbor_depth_exceeded");
    items++;
    if (items > MAX_CBOR_ITEMS) throw new Error("cbor_items_exceeded");
    if (offset >= bytes.length) throw new Error("truncated_cbor");
    const first = bytes[offset++] ?? 0;
    const major = first >>> 5;
    const info = first & 31;
    if (major === 7) {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      throw new Error("unsupported_cbor_simple");
    }
    const length = readLength(info);
    if (major === 0)
      return length <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(length)
        : length;
    if (major === 1) {
      const n = -1n - length;
      return n >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(n) : n;
    }
    if (length > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error("cbor_length_overflow");
    const size = Number(length);
    if (major === 2 || major === 3) {
      if (offset + size > bytes.length) throw new Error("truncated_cbor");
      const data = bytes.slice(offset, offset + size);
      offset += size;
      return major === 2 ? data : utf8Decode(data);
    }
    if (major === 4) {
      const out: Cbor[] = [];
      for (let i = 0; i < size; i++) out.push(take(depth + 1));
      return out;
    }
    if (major === 5) {
      const out = new Map<Cbor, Cbor>();
      let previousKey: Uint8Array | undefined;
      for (let i = 0; i < size; i++) {
        const keyStart = offset;
        const key = take(depth + 1);
        const encodedKey = bytes.slice(keyStart, offset);
        if (
          previousKey &&
          (previousKey.length > encodedKey.length ||
            (previousKey.length === encodedKey.length &&
              compare(previousKey, encodedKey) >= 0))
        )
          throw new Error("noncanonical_map");
        previousKey = encodedKey;
        out.set(key, take(depth + 1));
      }
      return out;
    }
    throw new Error("unsupported_cbor_major");
  }
  function readLength(info: number): bigint {
    if (info < 24) return BigInt(info);
    const width =
      info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
    if (!width || offset + width > bytes.length)
      throw new Error("invalid_cbor_length");
    let out = 0n;
    for (let i = 0; i < width; i++)
      out = (out << 8n) | BigInt(bytes[offset++] ?? 0);
    if (
      (width === 1 && out < 24n) ||
      (width === 2 && out <= 0xffn) ||
      (width === 4 && out <= 0xffffn) ||
      (width === 8 && out <= 0xffffffffn)
    )
      throw new Error("noncanonical_cbor");
    return out;
  }
  const value = take(0);
  if (offset !== bytes.length) throw new Error("trailing_cbor");
  return value;
}
