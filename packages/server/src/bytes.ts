const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
export function utf8Decode(value: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(value);
}

export function base64url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] ?? 0;
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;
    const n = (a << 16) | (b << 8) | c;
    out += B64.charAt((n >>> 18) & 63) + B64.charAt((n >>> 12) & 63);
    if (i + 1 < bytes.length) out += B64.charAt((n >>> 6) & 63);
    if (i + 2 < bytes.length) out += B64.charAt(n & 63);
  }
  return out;
}

export function fromBase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1)
    throw new Error("invalid_base64url");
  const out: number[] = [];
  let bits = 0;
  let buffer = 0;
  for (const char of value) {
    const digit = B64.indexOf(char);
    if (digit < 0) throw new Error("invalid_base64url");
    buffer = (buffer << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 255);
    }
  }
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0)
    throw new Error("invalid_base64url");
  return new Uint8Array(out);
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join(
    "",
  );
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return difference === 0;
}

export function bigintToBytes(value: bigint): Uint8Array {
  if (value < 0n) throw new Error("negative_bigint");
  if (value === 0n) return new Uint8Array([0]);
  const out: number[] = [];
  while (value > 0n) {
    out.push(Number(value & 255n));
    value >>= 8n;
  }
  out.reverse();
  return new Uint8Array(out);
}

export function bytesToBigint(value: Uint8Array): bigint {
  let out = 0n;
  for (const byte of value) out = (out << 8n) | BigInt(byte);
  return out;
}
