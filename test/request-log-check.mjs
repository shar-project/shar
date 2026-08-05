import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const paths = process.argv.slice(2);
assert.equal(paths.length, 2, "pass Rust and JavaScript standalone log paths");

for (const path of paths) {
  const events = (await readFile(path, "utf8"))
    .split("\n")
    .filter(Boolean)
    .flatMap((line) => {
      try {
        const value = JSON.parse(line);
        return value?.version === "request-observation-v1" ? [value] : [];
      } catch {
        return [];
      }
    });
  assert.ok(events.length > 0, `${path} has no request observations`);
  assert.ok(events.some(({ route }) => route === "/healthz"));
  assert.ok(events.some(({ route }) => route === "/readyz"));
  assert.ok(events.some(({ route }) => route === "/v1/challenges"));
  assert.ok(events.some(({ route }) => route === "unmatched"));
  for (const event of events) {
    assert.deepEqual(Object.keys(event).sort(), [
      "duration_ms",
      "method",
      "request_id",
      "route",
      "status",
      "version",
    ]);
    assert.match(event.request_id, /^[A-Za-z0-9_-]{22}$/);
    assert.ok(Number.isSafeInteger(event.duration_ms));
    assert.ok(event.duration_ms >= 0);
    assert.ok(Number.isSafeInteger(event.status));
    assert.equal(JSON.stringify(event).includes("localhost:3000"), false);
    assert.equal(JSON.stringify(event).includes("interop-site"), false);
    assert.equal(JSON.stringify(event).includes("private-tenant-name"), false);
    assert.equal(JSON.stringify(event).includes("must-not-appear"), false);
  }
}

console.log("privacy-safe standalone request observations passed");
