import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parseAllowedOrigins } from "../standalone/js/origins.mjs";

test("standalone allowlists match the language-neutral origin vectors", async () => {
  const document = JSON.parse(
    await readFile(
      new URL("../protocol/allowed-origin-vectors.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(document.version, "allowed-origin-v1");
  for (const vector of document.vectors) {
    if (vector.valid)
      assert.deepEqual(
        parseAllowedOrigins(vector.input),
        vector.origins,
        vector.name,
      );
    else
      assert.throws(
        () => parseAllowedOrigins(vector.input),
        /SHAR_ALLOWED_ORIGINS/,
        vector.name,
      );
  }
});
