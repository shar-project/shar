import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const packageNames = ["server", "widget", "cap-compat"];

async function collectFiles(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const url = new URL(
      `${entry.name}${entry.isDirectory() ? "/" : ""}`,
      directory,
    );
    if (entry.isDirectory()) files.push(...(await collectFiles(url)));
    else files.push(url);
  }
  return files;
}

test("published package entry points target compiled JavaScript with declarations", async () => {
  for (const name of packageNames) {
    const directory = new URL(`../packages/${name}/`, import.meta.url);
    const manifest = JSON.parse(
      await readFile(new URL("package.json", directory), "utf8"),
    );
    assert.equal(manifest.main, "./dist/index.js");
    assert.equal(manifest.types, "./dist/index.d.ts");
    assert.equal(manifest.exports["."].import, "./dist/index.js");
    assert.equal(manifest.exports["."].types, "./dist/index.d.ts");
    if (name === "server")
      assert.equal(manifest.exports["."].default, "./dist/index.js");
    assert.match(
      await readFile(new URL("LICENSE", directory), "utf8"),
      /^MIT License/,
    );
    await readFile(new URL("dist/index.js", directory), "utf8");
    await readFile(new URL("dist/index.d.ts", directory), "utf8");
    if (name === "server") {
      for (const entry of ["browser", "trust"]) {
        assert.equal(
          manifest.exports[`./${entry}`].import,
          `./dist/${entry}.js`,
        );
        assert.equal(
          manifest.exports[`./${entry}`].types,
          `./dist/${entry}.d.ts`,
        );
        await readFile(new URL(`dist/${entry}.js`, directory), "utf8");
        await readFile(new URL(`dist/${entry}.d.ts`, directory), "utf8");
      }
    }
  }
});

test("package prepack scripts build internal workspace dependencies first", async () => {
  const manifests = Object.fromEntries(
    await Promise.all(
      packageNames.map(async (name) => [
        name,
        JSON.parse(
          await readFile(
            new URL(`../packages/${name}/package.json`, import.meta.url),
            "utf8",
          ),
        ),
      ]),
    ),
  );
  assert.equal(manifests.server.scripts.prepack, "npm run build");
  assert.equal(
    manifests.widget.scripts.prepack,
    "npm run build --workspace=@shar/server && npm run build",
  );
  assert.equal(
    manifests["cap-compat"].scripts.prepack,
    "npm run build --workspace=@shar/server && npm run build --workspace=@shar/widget && npm run build",
  );
});

test("widget package exports the reproducible optional time-lock accelerator", async () => {
  const directory = new URL("../packages/widget/", import.meta.url);
  const manifest = JSON.parse(
    await readFile(new URL("package.json", directory), "utf8"),
  );
  assert.ok(manifest.files.includes("wasm"));
  assert.equal(
    manifest.exports["./timelock.wasm"],
    "./wasm/shar_timelock.wasm",
  );
  assert.equal(
    manifest.exports["./trust-credits"].import,
    "./dist/trust-credits.js",
  );
  assert.equal(
    manifest.exports["./trust-credits"].types,
    "./dist/trust-credits.d.ts",
  );
  await readFile(new URL("dist/trust-credits.js", directory), "utf8");
  await readFile(new URL("dist/trust-credits.d.ts", directory), "utf8");
  const artifact = await readFile(
    new URL("wasm/shar_timelock.wasm", directory),
  );
  assert.ok(artifact.byteLength > 0);
  assert.ok(artifact.byteLength < 128 * 1024);

  const declarations = await readFile(
    new URL("dist/time-lock-wasm.d.ts", directory),
    "utf8",
  );
  assert.match(declarations, /SHAR_TIMELOCK_WASM_SHA256/);
  assert.match(declarations, /instantiateTimeLockWasm/);
  assert.match(declarations, /loadTimeLockWasm/);
});

test("widget package exports complete optional locale catalogs", async () => {
  const directory = new URL("../packages/widget/", import.meta.url);
  const manifest = JSON.parse(
    await readFile(new URL("package.json", directory), "utf8"),
  );
  assert.deepEqual(manifest.exports["./locales/*"], {
    types: "./dist/locales/*.d.ts",
    import: "./dist/locales/*.js",
  });

  const catalogs = [
    ["ar", "arTranslations"],
    ["de", "deTranslations"],
    ["es", "esTranslations"],
    ["fr", "frTranslations"],
    ["he", "heTranslations"],
    ["hi", "hiTranslations"],
    ["ja", "jaTranslations"],
    ["pt-br", "ptBrTranslations"],
    ["zh-cn", "zhCnTranslations"],
  ];
  const expectedKeys = [
    "expectedWork",
    "expired",
    "failed",
    "fallback",
    "pause",
    "paused",
    "preparing",
    "progressLabel",
    "ready",
    "resume",
    "resumed",
    "verificationLabel",
    "verified",
    "verify",
    "verifying",
  ];
  for (const [locale, exportName] of catalogs) {
    const javascript = new URL(`dist/locales/${locale}.js`, directory);
    const declarations = new URL(`dist/locales/${locale}.d.ts`, directory);
    await readFile(javascript, "utf8");
    await readFile(declarations, "utf8");
    const messages = (await import(javascript.href))[exportName];
    assert.deepEqual(Object.keys(messages).sort(), expectedKeys, locale);
    for (const [key, value] of Object.entries(messages)) {
      assert.equal(typeof value, "string", `${locale}.${key}`);
      assert.ok(value.trim().length > 0, `${locale}.${key}`);
      assert.ok(
        new TextEncoder().encode(value).byteLength <= 2_048,
        `${locale}.${key}`,
      );
      assert.doesNotMatch(value, /\p{Cc}/u, `${locale}.${key}`);
    }
    assert.equal(messages.verifying.split("{percent}").length, 2, locale);
    assert.equal(messages.expectedWork.split("{iterations}").length, 2, locale);
    assert.equal(messages.expectedWork.split("{rounds}").length, 2, locale);
  }
});

test("published pressure-store declaration requires atomic quote reservation", async () => {
  const declarations = await readFile(
    new URL("../packages/server/dist/types.d.ts", import.meta.url),
    "utf8",
  );
  assert.match(declarations, /priceAndRecord\(/);
  assert.doesNotMatch(declarations, /priceAndRecord\?\(/);
});

test("published servers expose the matching stored fallback assertion boundary", async () => {
  const declarations = await readFile(
    new URL("../packages/server/dist/fallback.d.ts", import.meta.url),
    "utf8",
  );
  assert.match(declarations, /MAX_STORED_FALLBACK_LIFETIME_SECONDS/);
  assert.match(declarations, /interface StoredFallbackAssertion/);
  assert.match(declarations, /interface FallbackAssertionStore/);
  assert.match(declarations, /class StoredFallbackVerifier/);

  const rust = await readFile(
    new URL("../crates/shar-core/src/lib.rs", import.meta.url),
    "utf8",
  );
  assert.match(rust, /pub struct StoredFallbackAssertion/);
  assert.match(rust, /pub trait FallbackAssertionStore/);
  assert.match(rust, /pub struct StoredFallbackVerifier/);
  assert.match(rust, /MAX_STORED_FALLBACK_LIFETIME_SECONDS/);
});

test("pure TypeScript server artifact has no forbidden runtime escape hatch", async () => {
  const roots = [
    new URL("../packages/server/dist/", import.meta.url),
    new URL("../node_modules/@noble/curves/", import.meta.url),
    new URL("../node_modules/@noble/hashes/", import.meta.url),
  ];
  const files = (
    await Promise.all(roots.map((directory) => collectFiles(directory)))
  ).flat();
  assert.equal(
    files.some((file) => /\.(?:node|wasm)$/.test(file.pathname)),
    false,
    "server dependency closure contains a native or WebAssembly artifact",
  );
  const source = (
    await Promise.all(
      files
        .filter((file) => /\.(?:js|mjs|cjs)$/.test(file.pathname))
        .map((file) => readFile(file, "utf8")),
    )
  ).join("\n");
  for (const forbidden of [
    /from ["']node:/,
    /import\(["']node:/,
    /from ["'](?:fs|fs\/promises|child_process|worker_threads|module)["']/,
    /require\s*\(/,
    /\.wasm\b/,
    /WebAssembly/,
    /\bBuffer\s*(?:\(|\.(?:alloc|allocUnsafe|byteLength|concat|from|isBuffer))/,
    /\bprocess\s*(?:\[|\.(?:argv|cwd|env|execPath|exit|platform|versions))/,
    /child_process/,
    /spawn\s*\(/,
    /execFile\s*\(/,
    /Deno\./,
    /Bun\./,
  ])
    assert.doesNotMatch(source, forbidden);

  const manifest = JSON.parse(
    await readFile(
      new URL("../packages/server/package.json", import.meta.url),
      "utf8",
    ),
  );
  assert.deepEqual(Object.keys(manifest.dependencies).sort(), [
    "@noble/curves",
    "@noble/hashes",
  ]);
  assert.equal(manifest.exports["."].browser, "./dist/index.js");
  assert.equal(manifest.exports["."].worker, "./dist/index.js");
  assert.deepEqual(manifest.engines, {
    node: ">=20",
    bun: ">=1.3",
    deno: ">=2",
  });
});

test("runtime smoke covers the restricted Fetch protocol lifecycle", async () => {
  const source = await readFile(
    new URL("runtime-smoke.mjs", import.meta.url),
    "utf8",
  );
  for (const required of [
    "disableGlobal(name)",
    '"WebAssembly"',
    '"unexpected outbound fetch"',
    "createSharHandler(service",
    '"/v1/challenges"',
    "solveTimeLock(originalChallenge.time_lock)",
    "solveRendering(originalChallenge.render)",
    '"/v1/siteverify"',
    "audit.flush()",
  ])
    assert.match(
      source,
      new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    );
});

test("compiled packages import independently without TypeScript source paths", async () => {
  const server = await import("../packages/server/dist/index.js");
  assert.equal(typeof server.createSharHandler, "function");
  assert.equal(typeof server.solveRendering, "function");

  const previousHTMLElement = globalThis.HTMLElement;
  const previousCustomElements = globalThis.customElements;
  globalThis.HTMLElement = class {};
  globalThis.customElements = { get: () => undefined, define: () => undefined };
  try {
    const widget = await import("../packages/widget/dist/index.js");
    const trustCredits =
      await import("../packages/widget/dist/trust-credits.js");
    const compatibility = await import("../packages/cap-compat/dist/index.js");
    assert.equal(typeof widget.Shar.execute, "function");
    assert.equal(typeof widget.solveRenderingAdaptive, "function");
    assert.equal(typeof widget.createRecaptchaAdapter, "function");
    assert.equal(typeof widget.createHcaptchaAdapter, "function");
    assert.equal(typeof widget.installRecaptchaAdapter, "function");
    assert.equal(typeof widget.installHcaptchaAdapter, "function");
    assert.equal(typeof trustCredits.prepareTrustCreditIssuance, "function");
    assert.equal(typeof compatibility.CapWidgetCompatibility, "function");
  } finally {
    if (previousHTMLElement === undefined) delete globalThis.HTMLElement;
    else globalThis.HTMLElement = previousHTMLElement;
    if (previousCustomElements === undefined) delete globalThis.customElements;
    else globalThis.customElements = previousCustomElements;
  }

  const widgetSource = await readFile(
    new URL("../packages/widget/dist/index.js", import.meta.url),
    "utf8",
  );
  assert.match(widgetSource, /from "@shar\/server\/browser"/);
  assert.match(widgetSource, /import\("\.\/trust-credits\.js"\)/);
  assert.doesNotMatch(widgetSource, /from "\.\/trust-credits\.js"/);
  assert.doesNotMatch(widgetSource, /server\/src|\.ts["']/);
});

test("scoped audit schemas stay bounded and privacy-filtered", async () => {
  const audit = JSON.parse(
    await readFile(
      new URL("../protocol/audit-event.schema.json", import.meta.url),
      "utf8",
    ),
  );
  const response = JSON.parse(
    await readFile(
      new URL("../protocol/admin-audit.schema.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(audit.properties.occurred_at.minimum, 0);
  assert.equal(audit.properties.tier.maximum, 32);
  assert.deepEqual(audit.properties.backend.enum, ["webgpu", "webgl2", "css"]);
  assert.equal(response.properties.events.maxItems, 100);
  assert.equal(response.properties.events.items.$ref, "audit-event.json");
  assert.equal(response.additionalProperties, false);
  assert.equal(audit.additionalProperties, false);
});

test("trust-credit schemas describe the versioned optional envelopes", async () => {
  const challenge = JSON.parse(
    await readFile(
      new URL("../protocol/challenge.schema.json", import.meta.url),
      "utf8",
    ),
  );
  const redeem = JSON.parse(
    await readFile(
      new URL("../protocol/redeem.schema.json", import.meta.url),
      "utf8",
    ),
  );
  const credit = JSON.parse(
    await readFile(
      new URL("../protocol/trust-credit.schema.json", import.meta.url),
      "utf8",
    ),
  );
  const evaluation = JSON.parse(
    await readFile(
      new URL("../protocol/trust-evaluation.schema.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(
    challenge.$defs.request.properties.trust_token.$ref,
    "trust-credit.json#/$defs/token",
  );
  assert.equal(
    challenge.$defs.response.properties.trust.$ref,
    "trust-credit.json#/$defs/plan",
  );
  assert.ok(challenge.$defs.response.required.includes("presence"));
  assert.ok(challenge.$defs.response.required.includes("fallback"));
  assert.deepEqual(challenge.$defs.presence.properties.mode.enum, [
    "none",
    "host",
  ]);
  assert.equal(challenge.$defs.fallback.properties.methods.maxItems, 16);
  assert.equal(challenge.$defs.fallback.properties.methods.uniqueItems, true);
  assert.equal(
    redeem.$defs.request.properties.trust_blinded.pattern,
    "^[A-Za-z0-9_-]{43}$",
  );
  assert.deepEqual(
    redeem.$defs.request.properties.rendering.properties.css_commitment
      .required,
    ["version", "digest"],
  );
  assert.equal(
    redeem.$defs.request.properties.rendering.properties.css_commitment
      .properties.version.const,
    "css-transcript-v1",
  );
  assert.equal(
    redeem.$defs.response.properties.trust_evaluation.$ref,
    "trust-evaluation.json",
  );
  assert.equal(credit.$defs.plan.properties.suite.const, "ristretto255-SHA512");
  assert.equal(evaluation.properties.version.const, "trust-evaluation-v1");
  assert.equal(evaluation.properties.proof.pattern, "^[A-Za-z0-9_-]{86}$");
});

test("container build stages install workspace dependencies after copying manifests", async () => {
  const javascriptDockerfile = await readFile(
    new URL("../deploy/docker/Dockerfile.javascript", import.meta.url),
    "utf8",
  );
  const workspaceCopy = javascriptDockerfile.indexOf(
    "COPY packages ./packages",
  );
  const install = javascriptDockerfile.indexOf("npm ci --ignore-scripts");
  assert.ok(workspaceCopy >= 0 && install > workspaceCopy);
  assert.match(javascriptDockerfile, /rm -rf .*node_modules\/npm/);
  assert.match(javascriptDockerfile, /node_modules\/corepack/);
  assert.match(javascriptDockerfile, /rm -f .*\/npm .*\/npx .*\/corepack/);
  const rustDockerfile = await readFile(
    new URL("../deploy/docker/Dockerfile.rust", import.meta.url),
    "utf8",
  );
  assert.match(
    rustDockerfile,
    /COPY --from=build \/etc\/ssl\/certs\/ca-certificates\.crt \/etc\/ssl\/certs\/ca-certificates\.crt/,
  );
  assert.doesNotMatch(
    rustDockerfile,
    /apt-get|apk add|dnf install|yum install/,
  );
  for (const name of ["Dockerfile.rust", "Dockerfile.javascript"]) {
    const dockerfile = await readFile(
      new URL(`../deploy/docker/${name}`, import.meta.url),
      "utf8",
    );
    assert.match(dockerfile, /USER 10001:10001/);
    assert.match(dockerfile, /HEALTHCHECK/);
    const baseImages = [...dockerfile.matchAll(/^FROM\s+(\S+)/gm)].map(
      (match) => match[1],
    );
    assert.ok(baseImages.length >= 2);
    for (const image of baseImages)
      assert.match(image, /^[^@\s]+@sha256:[0-9a-f]{64}$/);
  }
});

test("standalones apply bounded state deadlines to every durable adapter", async () => {
  const javascript = await readFile(
    new URL("../standalone/js/server.mjs", import.meta.url),
    "utf8",
  );
  for (const setting of [
    "connectionTimeoutMillis: stateTimeoutMilliseconds",
    "statement_timeout: stateTimeoutMilliseconds",
    "query_timeout: stateTimeoutMilliseconds",
    "lock_timeout: stateTimeoutMilliseconds",
    "commandOptions: { timeout: stateTimeoutMilliseconds }",
    "busyTimeoutMilliseconds: stateTimeoutMilliseconds",
  ])
    assert.match(javascript, new RegExp(setting.replace(/[{}]/g, "\\$&")));

  const rust = await readFile(
    new URL("../crates/shar-server/src/main.rs", import.meta.url),
    "utf8",
  );
  assert.match(rust, /connect_timeout\(state_timeout\)/);
  assert.match(rust, /spawn_blocking\(move \|\| load_stores/);
  assert.match(rust, /statement_timeout=\{timeout_ms\}/);
  assert.match(rust, /PostgresStore::from_clients_with_reconnect/);
  assert.match(
    rust,
    /RedisStore::from_client\(client, 10, 172_800, state_timeout\)/,
  );
  const redis = await readFile(
    new URL("../crates/shar-server/src/redis.rs", import.meta.url),
    "utf8",
  );
  assert.match(redis, /get_connection_with_timeout\(timeout\)/);
  assert.match(redis, /set_read_timeout\(Some\(timeout\)\)/);
  assert.match(redis, /set_write_timeout\(Some\(timeout\)\)/);
  const postgres = await readFile(
    new URL("../crates/shar-server/src/postgres.rs", import.meta.url),
    "utf8",
  );
  assert.match(postgres, /if client\.is_closed\(\)/);
  assert.match(postgres, /if client\.simple_query\("SELECT 1"\)\.is_ok\(\)/);
  assert.match(
    rust,
    /open_with_timeout\(&database, policy\.clone\(\), state_timeout\)/,
  );
  assert.match(
    javascript,
    /SHAR_REQUEST_BODY_TIMEOUT_MS[\s\S]*readRequestBody\(req\)/,
  );
  assert.match(
    rust,
    /SHAR_REQUEST_BODY_TIMEOUT_MS[\s\S]*tokio::time::timeout\(timeout, to_bytes/,
  );
});

test("standalones permit plaintext state services only in explicit development", async () => {
  const javascript = await readFile(
    new URL("../standalone/js/server.mjs", import.meta.url),
    "utf8",
  );
  assert.match(javascript, /plaintextPostgres/);
  assert.match(
    javascript,
    /plaintextPostgres &&\s+process\.env\.SHAR_INSECURE_DEVELOPMENT !== "1"/,
  );
  assert.match(
    javascript,
    /redisUrl\.protocol !== "rediss:" &&\s+process\.env\.SHAR_INSECURE_DEVELOPMENT !== "1"/,
  );

  const rust = await readFile(
    new URL("../crates/shar-server/src/main.rs", import.meta.url),
    "utf8",
  );
  assert.match(
    rust,
    /!postgres_tls\s+&& env::var\("SHAR_INSECURE_DEVELOPMENT"\)/,
  );
  assert.match(
    rust,
    /!url\.starts_with\("rediss:\/\/"\)\s+&& env::var\("SHAR_INSECURE_DEVELOPMENT"\)/,
  );
});
