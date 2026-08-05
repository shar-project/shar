# Shar

Shar is a self-hosted anti-abuse protocol where suspicion changes the price of
verification, never the outcome. Every supported, syntactically valid client
can obtain finite work. Every correct, unexpired issued proof is honored.

This repository currently contains the executable v1 protocol foundation:

- a language-neutral protocol and threat-model specification;
- deterministic work pricing and `render-v1` reference programs;
- independent Rust and pure-TypeScript implementations;
- canonical CBOR / COSE Sign1 challenge envelopes;
- replay-safe challenge redemption and site verification state machines;
- a runtime-neutral Fetch handler plus in-memory and SQLite WAL storage adapters;
- browser time-lock plus static WebGPU, WebGL2, and CSS-engine rendering solvers;
- an opt-in, reproducibly built Rust/WASM browser time-lock accelerator with an
  always-available pure-JavaScript fallback;
- opt-in reCAPTCHA/hCaptcha-shaped browser adapters over the canonical widget;
- separately publishable compiled server, widget, and Cap-compatibility packages;
- SQLite WAL, PostgreSQL, and Redis-compatible atomic storage adapters in both servers;
- a shared responsive policy-administration UI served by both standalone servers;
- shared deterministic conformance fixtures and strict Draft 2020-12 validation
  of real protocol exchanges from both servers.

It does **not** claim GA status. The full hardware/browser matrix, managed-store
failover/partition/TLS and separate-host validation, the external RFC 9578
trust-credit profile, isolated reproduction of the locally passing
protocol-matched native Cap throughput gate, remaining reference-device
performance/energy benchmarks, target trace-storage retention/access-control
validation, accessibility certification, and independent reviews remain tracked
release gates in `docs/roadmap.md`.

## Development

```sh
npm test
cargo test --workspace
```

An isolated PostgreSQL/Redis environment can additionally run
`npm run test:stores:live` followed by
`npm run test:standalone-external-interop`; the latter exercises both optimized
servers, cross-process replay races, and process restart with shared durable
state. See [`docs/operations.md`](docs/operations.md) for the required test-only
URLs and TLS warning.

`npm run test:browser` runs the rendered Chromium, Firefox, and WebKit projects.
Install their Playwright-managed binaries and OS dependencies first with
`npx playwright install --with-deps chromium firefox webkit`; the CI workflow
runs each engine independently.

When host browser libraries are unavailable, the same exact suite can run one
engine at a time in the digest-pinned Playwright 1.62.1 image through Podman or
Docker:

```sh
npm run test:browser:container -- webkit
```

Set `SHAR_CONTAINER_RUNTIME=docker` to prefer Docker when both runtimes are
installed. The container uses host networking only for the loopback test server
and mounts the repository as its working tree.

The widget uses pure JavaScript `BigInt` for time-lock work by default. Hosts
may opt into the package's bounded Rust/WASM accelerator with
`timeLockWasm: true` or `<shar-challenge timelock-wasm>`; any load or execution
failure resumes the exact chunk in JavaScript. See
[`packages/widget/README.md`](packages/widget/README.md) for CSP and packaging
details. The release gate rebuilds and byte-compares the committed artifact
with pinned Rust 1.94.0.

Local-only standalone smoke tests use an explicitly insecure, tiny RSW key:

```sh
npm run build
SHAR_INSECURE_DEVELOPMENT=1 SHAR_ALLOWED_ORIGINS=http://localhost:3000 node standalone/js/server.mjs
SHAR_INSECURE_DEVELOPMENT=1 SHAR_ALLOWED_ORIGINS=http://localhost:3000 cargo run --bin shar-server
```

Production startup instead requires a base64url Ed25519 seed/key id, a
protected 2048-bit RSW modulus/lambda, and a separate 32-byte daily-network
pseudonym secret through `SHAR_SIGNING_SEED`, `SHAR_KEY_ID`,
`SHAR_RSW_MODULUS`, `SHAR_RSW_LAMBDA`, `SHAR_RSW_ID`, and
`SHAR_NETWORK_SECRET`. Final site verification additionally uses the separate
`SHAR_SITEVERIFY_MASTER_SECRET`. The standalone servers refuse partial production key
configuration. During signing-key rotation, `SHAR_PREVIOUS_VERIFY_KEYS` accepts
a JSON array of `{ "kid": "base64url", "x": "base64url-public-key" }`
entries. During RSW rotation, `SHAR_PREVIOUS_RSW_KEYS` accepts a JSON array of
`{ "id": "...", "modulus": "base64url", "lambda": "base64url" }` entries.
Both implementations validate current and overlapping trapdoors against real
sequential squaring before binding a listener; inconsistent key material is a
fatal startup error rather than a risk to already quoted work.
Optional blinded trust credits use `SHAR_TRUST_SEED` and
`SHAR_TRUST_KEY_ID`; rotation preserves prior issuer pairs in
`SHAR_PREVIOUS_TRUST_KEYS`. See [`docs/trust-credits.md`](docs/trust-credits.md)
for the versioned profile and retention controls.
Rotate both signing and RSW material into a new mode-0600 bundle. Each tool
preserves the old verification key and trapdoor in the overlap lists, while
keeping network, fallback, admin, and site-verification secrets stable:

```sh
cargo run --release --bin shar-keygen -- rotate --input shar-keys.json --output shar-keys-next.json
npm run keygen:js -- rotate --input shar-keys.json --output shar-keys-next.json
```

Deploy the new bundle alongside the old one until every old challenge and
verification token has expired; the live interoperability test exercises this
handoff before accepting the new bundle.

Generate a new protected production key bundle without printing secrets to the
terminal. The command refuses to overwrite an existing file and uses mode 0600
on Unix:

```sh
cargo run --release --bin shar-keygen -- --output shar-keys.json
```

The pure-JavaScript distribution provides the same operation without a Rust
binary:

```sh
npm run build
npm run keygen:js -- --output shar-keys.json
```

Pass that file directly as `SHAR_KEY_FILE=/run/secrets/shar-keys.json`. Both
standalone servers refuse a Unix key file with group or other permissions;
individual environment variables can override file entries during rotation.
Derive the backend-only credential for each tenant/site pair with either
implementation:

```sh
cargo run --release --bin shar-keygen -- site-secret --key-file shar-keys.json --tenant tenant-a --site-key site-a
npm run site-secret -- --key-file shar-keys.json --tenant tenant-a --site-key site-a
```

Send that `shrs1_...` value as `secret` with `/v1/siteverify`; never expose it
to browser JavaScript. A credential is valid only for its encoded tenant/site,
and failed authentication cannot consume a verification token.

The generated bundle also contains the independent `SHAR_ADMIN_SECRET`. Open
`/admin/` over TLS and enter that base64url value to edit scoped work policies;
the browser retains it only in the current tab's memory.

The Rust and pure-JavaScript images are separate, non-root distributions. A
hardened single-node Rust example is in
`deploy/docker/compose.yaml`; switch its Dockerfile to
`Dockerfile.javascript` to run the independent JavaScript implementation.
The [Kubernetes scaffold](deploy/kubernetes/README.md) demonstrates distinct
liveness/readiness probes and shared PostgreSQL/Redis state for two replicas;
it is not a substitute for the open target-environment failover tests.
Deployment and key-handling notes are in `docs/operations.md`.
Host passkey, email, authenticated-session, and support fallback integrations
should use the exact-binding stored-assertion boundary in
[`docs/fallback.md`](docs/fallback.md); the privileged fallback secret never
belongs in the widget or browser application.
Current verified gates and explicit release blockers are recorded in
`docs/release-status.md`.

The TypeScript server has no native, WebAssembly, filesystem, subprocess, or
Node-specific runtime dependency. It prefers WebCrypto and loads the pinned MIT
pure-TypeScript Ed25519 fallback only when needed. The Rust server is a separate
implementation and never executes the TypeScript implementation.
CI runs the compiled server's complete issue/redeem/siteverify lifecycle
unchanged in Node, Bun, and no-permission Deno, while package inspection covers
the complete pinned runtime dependency closure.

## Non-negotiable behavior

Signals can only affect a future quote. User agent, IP/ASN reputation,
automation signals, rendering backend, and completion time are never proof
validity inputs. Invalid, expired, or replayed work fails only that redemption;
the client can always request another finite quote.

Licensed under the [MIT License](LICENSE).
