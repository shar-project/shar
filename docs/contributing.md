# Contributing

Shar is one protocol implemented independently in Rust and TypeScript. Keep a
change small enough to review, preserve the no-policy-rejection invariant, and
add equivalent coverage to both implementations when behavior crosses the
shared protocol boundary.

## Repository map

| Path                      | Purpose                                                           |
| ------------------------- | ----------------------------------------------------------------- |
| `crates/shar-core`        | Rust protocol engine                                              |
| `crates/shar-server`      | Rust storage adapters, native server, and key generator           |
| `crates/shar-widget-wasm` | Optional bounded time-lock accelerator                            |
| `packages/server`         | Pure-TypeScript engine, Fetch handler, and runtime-neutral stores |
| `packages/widget`         | Browser widget and rendering executors                            |
| `packages/cap-compat`     | Cap-compatible custom element                                     |
| `standalone/js`           | JavaScript HTTP server, durable adapters, and key tools           |
| `protocol`                | Schemas and deterministic cross-language vectors                  |
| `test`                    | TypeScript, interoperability, browser, and live-store tests       |
| `bench`                   | Cap, rendering, time-lock, and native benchmark harnesses         |
| `deploy`                  | Containers, Kubernetes, and observability examples                |

## Baseline checks

```sh
npm ci
npm test
cargo test --locked --workspace
npm run format:check
```

CI also treats Rust warnings as errors through Clippy. Before publishing a Rust
change, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets -- -D warnings
```

## Choose tests by change

- **Protocol, envelopes, pricing, or errors:** update the shared files in
  `protocol/`; run both main language suites.
- **Widget or rendering:** run `npm run test:browser`; use physical hardware
  only through `npm run test:browser:physical`.
- **Standalone transport:** run `npm run test:standalone-interop`.
- **PostgreSQL or Redis:** run `npm run test:stores:live`,
  `npm run test:standalone-external-interop`, and
  `npm run test:standalone-store-partition` against disposable services.
- **Containers or workflows:** run `npm run check:deployments`,
  `npm run check:base-images`, and `npm run check:workflows`.
- **Cap comparison:** use the relevant command in the
  [Cap benchmark guide](../bench/cap/README.md).
- **Documentation:** run `npm run format:check` and `npm run check:docs`.

Live-store commands require isolated test databases and may create the `shar_*`
schema. Exact environment variables and TLS warnings are in
[operations](operations.md).

## Protocol rules for reviewers

- A valid unexpired proof cannot be rejected by policy or signals.
- A quote cannot become more expensive after issuance.
- Backend choice and completion time are not proof-validity inputs.
- Replays fail atomically, while losing clients may request fresh work.
- State failure is retryable operational unavailability, never a bot verdict.
- TypeScript protocol code remains free of Node-only, native, WASM, subprocess,
  and filesystem dependencies.
- Rust-only or TypeScript-only protocol features do not ship.

## Generated and pinned artifacts

Do not casually update lockfiles, action SHAs, base-image digests, Cap fixtures,
or the committed time-lock WASM. Use the corresponding validation script and
record why the pin changed. `scripts/build-widget-wasm.sh --check` rebuilds and
byte-compares the WASM artifact with the pinned Rust toolchain.

## Evidence versus product documentation

Put stable user behavior in the README or a focused guide. Put normative wire
requirements in [protocol.md](protocol.md). Put benchmark runs, hardware
captures, and release-gate proof in [release-status.md](release-status.md).
Avoid making onboarding depend on the evidence ledger.

Security reports should follow [SECURITY.md](../SECURITY.md), not a public issue.
