import test from "node:test";
import assert from "node:assert/strict";
import {
  clientAddress,
  parseTrustedProxyCidrs,
} from "../standalone/js/proxy.mjs";

test("forwarded addresses are used only through a fully trusted proxy suffix", () => {
  const trusted = parseTrustedProxyCidrs(
    "127.0.0.0/8, 10.0.0.0/8, 2001:db8:1::/48",
  );
  assert.equal(
    clientAddress("203.0.113.5", "198.51.100.1", trusted),
    "203.0.113.5",
  );
  assert.equal(
    clientAddress("127.0.0.1", "198.51.100.7, 10.0.0.9", trusted),
    "198.51.100.7",
  );
  assert.equal(
    clientAddress("127.0.0.1", "192.0.2.44, 198.51.100.7, 10.0.0.9", trusted),
    "198.51.100.7",
  );
  assert.equal(
    clientAddress("2001:db8:1::9", "[2001:db8:2::4]", trusted),
    "2001:db8:2::4",
  );
  assert.equal(
    clientAddress("127.0.0.1", "not-an-address", trusted),
    "127.0.0.1",
  );
});

test("invalid trusted proxy configuration fails closed", () => {
  assert.throws(() => parseTrustedProxyCidrs("10.0.0.0/33"), /invalid CIDR/);
  assert.throws(
    () => parseTrustedProxyCidrs("not-a-cidr"),
    /comma-separated CIDRs/,
  );
});
