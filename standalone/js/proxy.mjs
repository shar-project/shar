import { BlockList, isIP } from "node:net";

export function parseTrustedProxyCidrs(text = "") {
  const blockList = new BlockList();
  for (const raw of text.split(",")) {
    const cidr = raw.trim();
    if (!cidr) continue;
    const slash = cidr.lastIndexOf("/");
    if (slash < 1)
      throw new Error(
        "SHAR_TRUSTED_PROXY_CIDRS must contain comma-separated CIDRs",
      );
    const address = normalizeAddress(cidr.slice(0, slash));
    const family = isIP(address);
    const prefix = Number(cidr.slice(slash + 1));
    const maximum = family === 4 ? 32 : family === 6 ? 128 : -1;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > maximum)
      throw new Error("SHAR_TRUSTED_PROXY_CIDRS contains an invalid CIDR");
    blockList.addSubnet(address, prefix, family === 4 ? "ipv4" : "ipv6");
  }
  return blockList;
}

export function clientAddress(remoteAddress, forwardedFor, trustedProxies) {
  const remote = normalizeAddress(remoteAddress);
  if (!isTrusted(remote, trustedProxies) || !forwardedFor) return remote;
  const forwarded = forwardedFor
    .split(",")
    .map((part) => parseForwardedAddress(part.trim()));
  if (forwarded.some((address) => address === undefined)) return remote;
  let current = remote;
  for (let index = forwarded.length - 1; index >= 0; index--) {
    if (!isTrusted(current, trustedProxies)) break;
    current = forwarded[index];
  }
  return current;
}

function isTrusted(address, blockList) {
  const family = isIP(address);
  return (
    family !== 0 && blockList.check(address, family === 4 ? "ipv4" : "ipv6")
  );
}

export function isTrustedProxy(remoteAddress, trustedProxies) {
  return isTrusted(normalizeAddress(remoteAddress), trustedProxies);
}

function normalizeAddress(value) {
  let address = value.trim();
  const zone = address.indexOf("%");
  if (zone >= 0) address = address.slice(0, zone);
  if (address.startsWith("::ffff:")) {
    const mapped = address.slice(7);
    if (isIP(mapped) === 4) return mapped;
  }
  return address;
}
function parseForwardedAddress(value) {
  if (value.startsWith("[") && value.includes("]"))
    return valid(normalizeAddress(value.slice(1, value.indexOf("]"))));
  if (isIP(normalizeAddress(value))) return normalizeAddress(value);
  const colon = value.lastIndexOf(":");
  if (
    colon > 0 &&
    value.indexOf(":") === colon &&
    /^\d+$/.test(value.slice(colon + 1))
  )
    return valid(normalizeAddress(value.slice(0, colon)));
  return undefined;
}
function valid(address) {
  return isIP(address) ? address : undefined;
}
