import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  listenHealthcheckUrl,
  parseListenAddress,
} from "../standalone/js/listen.mjs";

test("standalone listen parsing matches the language-neutral vectors", async () => {
  const vectors = JSON.parse(
    await readFile(
      new URL("../protocol/standalone-listen-vectors.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(vectors.version, "standalone-listen-v1");
  for (const vector of vectors.valid)
    assert.deepEqual(parseListenAddress(vector.input), {
      host: vector.host,
      port: vector.port,
    });
  for (const value of vectors.invalid)
    assert.throws(() => parseListenAddress(value), /SHAR_LISTEN/);
});

test("container healthcheck URLs follow the configured listener", () => {
  assert.equal(
    listenHealthcheckUrl("0.0.0.0:9180"),
    "http://127.0.0.1:9180/readyz",
  );
  assert.equal(listenHealthcheckUrl("[::]:9181"), "http://[::1]:9181/readyz");
  assert.equal(
    listenHealthcheckUrl("localhost:9182"),
    "http://localhost:9182/readyz",
  );
});
