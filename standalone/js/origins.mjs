const ERROR =
  "SHAR_ALLOWED_ORIGINS must contain unique, canonical HTTPS origins or local HTTP origins";

export function parseAllowedOrigins(value) {
  if (typeof value !== "string") throw new Error(ERROR);
  const origins = value.split(",");
  if (origins.length === 0 || origins.some((origin) => origin.length === 0))
    throw new Error(ERROR);
  const unique = new Set();
  for (const origin of origins) {
    if (new TextEncoder().encode(origin).length > 512 || /\p{Cc}/u.test(origin))
      throw new Error(ERROR);
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      throw new Error(ERROR);
    }
    const localHttp =
      parsed.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
    if (
      parsed.origin !== origin ||
      (parsed.protocol !== "https:" && !localHttp) ||
      unique.has(origin)
    )
      throw new Error(ERROR);
    unique.add(origin);
  }
  return origins;
}
