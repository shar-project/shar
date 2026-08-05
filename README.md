# Shar

Shar is self-hosted anti-abuse where suspicion changes the cost of verification,
never whether correct work is accepted.

A supported client always receives a finite proof-of-work quote. Once Shar signs
that quote, completing it correctly before expiry succeeds even if traffic,
reputation, browser signals, or infrastructure pressure change afterward. There
are no image puzzles, hidden bot scores, or permanent CAPTCHA bans.

> Shar is under active development and does **not** claim GA status. The protocol
> and both server implementations are executable, but independent review and
> parts of the production hardware, accessibility, performance, and managed-store
> matrix remain open. See [Project status](#project-status).

## How it works

1. The browser asks Shar for a challenge bound to the site, action, and origin.
2. Shar prices finite work from current pressure and signs that exact quote.
3. The widget runs a sequential time-lock and the same rendering program through
   WebGPU, WebGL2, or a CSS/CPU path.
4. Shar verifies the promised work and returns a short-lived verification token.
5. The application's backend atomically verifies that token with `/v1/siteverify`.

Signals may make a **future** quote more expensive. They cannot invalidate work
Shar has already promised. Missing GPU acceleration, headless execution, a slow
solve, an unusual network, or a software renderer is never a rejection reason.

[Read the architecture overview](docs/architecture.md) or the
[normative protocol](docs/protocol.md).

## What is in this repository

- independent Rust and pure-TypeScript server implementations;
- separate native and JavaScript standalone distributions;
- a runtime-neutral Fetch handler for Node, Bun, Deno, Workers, and similar
  WebCrypto environments;
- `<shar-challenge>` plus programmatic, reCAPTCHA-shaped, hCaptcha-shaped, and
  Cap-compatible browser APIs;
- WebGPU, WebGL2, and CSS-engine executors for one canonical rendering challenge;
- SQLite WAL, PostgreSQL, and Redis-compatible state adapters;
- shared schemas, deterministic vectors, conformance tests, and an admin UI;
- MIT licensing for the complete project.

Rust and TypeScript are first-class implementations. A feature is not complete
until the shared behavior is covered in both.

## Try it from source

Requirements: Node.js 22 or 24 and npm. Rust 1.94.0 is needed only for the
native server path.

```sh
git clone https://github.com/shar-project/shar.git
cd shar
npm ci
npm run build
node test/runtime-smoke.mjs
```

The smoke program runs a complete in-memory issue → solve → redeem → siteverify
lifecycle using the pure-TypeScript server. It also proves that later pressure
does not reprice an already issued quote.

For a standalone server, browser widget, backend verification example, and the
equivalent Rust commands, continue with the [source quickstart](docs/quickstart.md).
The `@shar/*` packages are not published yet, so current installation examples
use this repository checkout rather than pretending an npm release exists.

## Documentation

Start at the [documentation index](docs/index.md). Common destinations:

- [Quickstart](docs/quickstart.md) — run both servers and integrate a form;
- [Architecture](docs/architecture.md) — components, request flow, and state;
- [Widget guide](packages/widget/README.md) — custom element and browser APIs;
- [Operations](docs/operations.md) — keys, configuration, storage, and deployment;
- [Protocol](docs/protocol.md) — normative wire and state-machine behavior;
- [Threat model](docs/threat-model.md) — what Shar does and does not defend;
- [Release gates](docs/roadmap.md) — concise list of work still required for GA.

The long [release evidence ledger](docs/release-status.md) is for maintainers and
reviewers. It is deliberately not the normal onboarding path.

## Development

Run the main language suites:

```sh
npm test
cargo test --locked --workspace
```

Browser, durable-store, interoperability, benchmark, and release commands are
organized in the [contributor guide](docs/contributing.md).

## Project status

Shar's core protocol, dual servers, browser executors, storage adapters, and
cross-language conformance suite are implemented. Current retained hardware
evidence includes Intel Iris Xe, AMD Van Gogh, Mali-G710, SwiftShader, llvmpipe,
and GPU-disabled CSS execution.

GA is still blocked on the remaining device/browser and energy matrix,
replicated managed-store failover and production TLS validation, external
cryptographic/privacy/rendering/accessibility review, production fallback-host
integrations, and release publication verification. The authoritative concise
list is [docs/roadmap.md](docs/roadmap.md); completed evidence and exact caveats
are recorded in [docs/release-status.md](docs/release-status.md).

## Non-negotiable behavior

- Every syntactically valid, supported request can obtain finite work.
- Every correct, unexpired issued proof is honored at its signed price.
- Signals affect future cost only; Shar does not return a bot probability.
- Invalid, expired, forged, or replayed work fails that attempt, not the client.
- Operational overload is a retryable service error, not a suspicion verdict.
- Privacy mode stores no raw IP, stable device identifier, or third-party beacon.

Licensed under the [MIT License](LICENSE).
