import assert from "node:assert/strict";

const phase = process.argv[2];
assert.ok(["healthy", "partitioned", "recovered"].includes(phase));
const endpoints = (process.env.SHAR_TEST_ENDPOINTS ?? "")
  .split(",")
  .filter(Boolean);
assert.equal(
  endpoints.length,
  2,
  "SHAR_TEST_ENDPOINTS must contain both standalones",
);

async function response(endpoint, path, init) {
  const url = new URL(path, endpoint);
  try {
    return await fetch(url, {
      ...init,
      signal: AbortSignal.timeout(10_000),
    });
  } catch (error) {
    throw new Error(`${phase} request to ${url.href} failed`, { cause: error });
  }
}

async function body(response) {
  const value = await response.json();
  assert.equal(response.headers.get("cache-control"), "no-store");
  return value;
}

async function assertHealthy(endpoint, index) {
  const live = await response(endpoint, "/healthz");
  assert.equal(live.status, 200);
  assert.deepEqual(await body(live), { status: "ok" });

  const ready = await response(endpoint, "/readyz");
  assert.equal(ready.status, 200);
  assert.deepEqual(await body(ready), { status: "ready" });

  const issued = await response(endpoint, "/v1/challenges", {
    method: "POST",
    headers: {
      origin: "http://localhost:3000",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      tenant: "partition-test",
      site_key: "partition-site",
      action: `${phase}-${index}`,
      origin: "http://localhost:3000",
    }),
  });
  assert.equal(issued.status, 200);
  assert.match((await body(issued)).token, /^shr1_/);
}

async function assertPartitioned(endpoint, index) {
  const live = await response(endpoint, "/healthz");
  assert.equal(live.status, 200);
  assert.deepEqual(await body(live), { status: "ok" });

  const ready = await response(endpoint, "/readyz");
  assert.equal(ready.status, 503);
  assert.equal(ready.headers.get("retry-after"), "1");
  assert.deepEqual(await body(ready), {
    code: "readiness_unavailable",
    retryable: true,
    next_action: "retry",
    retry_after: 1,
  });

  const issued = await response(endpoint, "/v1/challenges", {
    method: "POST",
    headers: {
      origin: "http://localhost:3000",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      tenant: "partition-test",
      site_key: "partition-site",
      action: `partitioned-${index}`,
      origin: "http://localhost:3000",
    }),
  });
  assert.equal(issued.status, 503);
  assert.equal(issued.headers.get("retry-after"), "1");
  assert.deepEqual(await body(issued), {
    code: "pricing_unavailable",
    retryable: true,
    next_action: "retry",
    retry_after: 1,
  });
}

if (phase === "partitioned") {
  await Promise.all(endpoints.map(assertPartitioned));
} else if (phase === "healthy") {
  await Promise.all(endpoints.map(assertHealthy));
} else {
  let lastError;
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      await Promise.all(endpoints.map(assertHealthy));
      lastError = undefined;
      break;
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  if (lastError) throw lastError;
}

console.log(`${phase} external-store contract passed for both standalones`);
