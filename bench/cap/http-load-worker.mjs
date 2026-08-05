import { Agent as HttpAgent, request as httpRequest } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { performance } from "node:perf_hooks";
import { parentPort, workerData } from "node:worker_threads";

if (!parentPort) throw new Error("HTTP load worker requires a parent port");

const {
  product,
  endpoint,
  origin,
  offset,
  operations,
  concurrency,
  actionCardinality,
  runId,
} = workerData;
const url = new URL(endpoint);
const httpAgent = new HttpAgent({
  keepAlive: true,
  maxSockets: concurrency,
  maxFreeSockets: concurrency,
  scheduling: "fifo",
});
const httpsAgent = new HttpsAgent({
  keepAlive: true,
  maxSockets: concurrency,
  maxFreeSockets: concurrency,
  scheduling: "fifo",
});

parentPort.postMessage({ type: "ready" });
parentPort.once("message", async (message) => {
  if (message?.type !== "start") throw new Error("invalid load-worker start");
  try {
    const results = await mapConcurrent(operations, concurrency, requestAt);
    parentPort.postMessage({ type: "complete", results });
  } catch (error) {
    parentPort.postMessage({
      type: "failed",
      message: error instanceof Error ? error.message : String(error),
    });
  } finally {
    httpAgent.destroy();
    httpsAgent.destroy();
  }
});

async function requestAt(localIndex) {
  const index = offset + localIndex;
  const body =
    product === "shar"
      ? Buffer.from(
          JSON.stringify({
            tenant: "benchmark",
            site_key: "benchmark",
            action: `issue-${runId}-${index % actionCardinality}`,
            origin,
          }),
        )
      : undefined;
  const headers =
    product === "shar"
      ? {
          "content-type": "application/json",
          "content-length": String(body.byteLength),
          origin,
        }
      : {
          origin,
          "user-agent": "Mozilla/5.0 Shar-Cap-Benchmark/1.0",
          accept: "application/json",
        };
  const started = performance.now();
  const transport = url.protocol === "https:" ? httpsRequest : httpRequest;
  const agent = url.protocol === "https:" ? httpsAgent : httpAgent;
  const response = await new Promise((resolve, reject) => {
    const request = transport(
      url,
      { method: "POST", headers, agent },
      (incoming) => {
        const elapsed_ms = performance.now() - started;
        const chunks = [];
        incoming.on("data", (chunk) => chunks.push(chunk));
        incoming.once("end", () =>
          resolve({
            status: incoming.statusCode ?? 0,
            elapsed_ms,
            bytes: Buffer.concat(chunks),
          }),
        );
        incoming.once("error", reject);
      },
    );
    request.once("error", reject);
    request.end(body);
  });
  const text = response.bytes.toString("utf8");
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${product} returned a non-JSON issuance response`);
  }
  if (response.status !== 200 || !parsed || typeof parsed !== "object") {
    const code =
      typeof parsed?.code === "string" && /^[a-z0-9_]{1,64}$/.test(parsed.code)
        ? ` (${parsed.code})`
        : "";
    throw new Error(`${product} issuance returned ${response.status}${code}`);
  }
  return {
    elapsed_ms: response.elapsed_ms,
    body_bytes: response.bytes.byteLength,
  };
}

async function mapConcurrent(count, limit, operation) {
  const values = new Array(count);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(count, limit) }, async () => {
      while (true) {
        const index = next++;
        if (index >= count) return;
        values[index] = await operation(index);
      }
    }),
  );
  return values;
}
