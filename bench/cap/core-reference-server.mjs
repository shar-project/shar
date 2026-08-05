import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { inputs } from "./lib.mjs";

const port = Number(process.env.CAP_BENCH_CORE_PORT ?? 4190);
if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
  throw new Error("CAP_BENCH_CORE_PORT is invalid");
const settings = process.env.CAP_BENCH_SETTINGS_JSON
  ? JSON.parse(process.env.CAP_BENCH_SETTINGS_JSON)
  : {
      challengeCount: 3,
      saltSize: 16,
      difficulty: 2,
      instrumentation: false,
      rsw: false,
    };
if (settings.instrumentation || settings.rsw)
  throw new Error(
    "core reference helper supports SHA-256 without instrumentation only; use Cap Standalone for other modes",
  );

const corePath = new URL("source/standalone/core/src/index.js", inputs);
let core;
try {
  core = await import(pathToFileURL(fileURLToPath(corePath)));
} catch (error) {
  throw new Error(
    "Cap core is not installed; run npm run bench:cap:prepare -- --install-core",
    { cause: error },
  );
}
const secret = "shar-cap-core-reference-secret-32-bytes";
const consumed = new Set();

function send(response, status, body) {
  const bytes = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(bytes),
    "cache-control": "no-store",
    "x-cap-benchmark-kind": "core-reference-not-standalone",
  });
  response.end(bytes);
}
async function body(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
    if (url.pathname === "/healthz")
      return send(response, 200, { status: "ok", kind: "core-reference" });
    const match = /^\/([^/]+)\/(challenge|redeem)$/.exec(url.pathname);
    if (request.method !== "POST" || !match)
      return send(response, 404, { error: "not_found" });
    const [, siteKey, operation] = match;
    if (operation === "challenge") {
      return send(
        response,
        200,
        await core.generateChallenge(secret, {
          challengeCount: settings.challengeCount,
          challengeSize: settings.saltSize,
          challengeDifficulty: settings.difficulty,
          scope: siteKey,
          expiresMs: 120_000,
        }),
      );
    }
    const result = await core.validateChallenge(secret, await body(request), {
      scope: siteKey,
      consumeNonce(signature) {
        if (consumed.has(signature)) return false;
        consumed.add(signature);
        return true;
      },
      signToken() {
        return `${siteKey}:${randomUUID()}:reference`;
      },
      tokenTtlMs: 300_000,
    });
    return send(
      response,
      result.success ? 200 : 403,
      result.success ? result : { error: result.reason },
    );
  } catch (error) {
    send(response, 500, {
      error: error instanceof Error ? error.message : String(error),
    });
  }
});
server.listen(port, "127.0.0.1", () =>
  console.error(
    `Cap ${settings.challengeCount}x${settings.difficulty} core reference (not Standalone) listening on 127.0.0.1:${port}`,
  ),
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => server.close(() => process.exit(0)));
