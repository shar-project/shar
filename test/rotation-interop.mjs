import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import {
  deriveSiteVerifySecret,
  fromBase64url,
  solveRendering,
  solveTimeLock,
} from "../dist/packages/server/src/index.js";

const mode = process.argv[2];
const endpoint = process.env.SHAR_ROTATION_ENDPOINT;
const challengePath = process.env.SHAR_ROTATION_CHALLENGE;
const origin = process.env.SHAR_TEST_ORIGIN ?? "http://localhost:3000";
if (!endpoint || !challengePath || !["prepare", "complete"].includes(mode))
  throw new Error(
    "usage: SHAR_ROTATION_ENDPOINT=... SHAR_ROTATION_CHALLENGE=... node test/rotation-interop.mjs prepare|complete",
  );

if (mode === "prepare") {
  const challenge = await request("/v1/challenges", {
    tenant: "rotation",
    site_key: "rotation-site",
    action: "rotation-check",
    origin,
  });
  await writeFile(challengePath, JSON.stringify(challenge));
  console.log("issued an unredeemed challenge before rotation");
} else {
  const challenge = JSON.parse(await readFile(challengePath, "utf8"));
  const redemption = await request("/v1/challenges/redeem", {
    token: challenge.token,
    time_lock: solveTimeLock(challenge.time_lock),
    rendering: {
      backend: "css",
      digest: await solveRendering(challenge.render),
    },
  });
  const keyFile = process.env.SHAR_KEY_FILE;
  if (!keyFile)
    throw new Error("SHAR_KEY_FILE is required for rotation completion");
  const keyDocument = JSON.parse(await readFile(keyFile, "utf8"));
  const secret = await deriveSiteVerifySecret(
    fromBase64url(keyDocument.SHAR_SITEVERIFY_MASTER_SECRET),
    "rotation",
    "rotation-site",
  );
  const verified = await request("/v1/siteverify", {
    token: redemption.token,
    secret,
    action: "rotation-check",
    origin,
  });
  assert.equal(verified.success, true);
  console.log(
    "rotated server honored the pre-rotation challenge and verification",
  );
}

async function request(path, body) {
  const response = await fetch(new URL(path, endpoint), {
    method: "POST",
    headers: { "content-type": "application/json", origin },
    body: JSON.stringify(body),
  });
  const value = await response.json();
  assert.equal(
    response.status,
    200,
    `${path} returned ${response.status}: ${JSON.stringify(value)}`,
  );
  return value;
}
