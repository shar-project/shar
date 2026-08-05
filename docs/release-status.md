# Release status

Last updated: 2026-08-05. This is implementation evidence, not a GA claim.

GitHub's public-repository configuration now has an active semantic release-tag
ruleset for `v*.*.*`: only organization administrators may create, update, or
delete matching tags, and their target commits must have verified signatures.
The `release` deployment environment requires explicit approval from the
repository owner and accepts only the same tag pattern. Release workflow runs
are serialized without cancellation, and GHCR publication cannot begin until
the tested npm candidates have published successfully. No release tag has been
created yet; the initial npm namespace and trusted-publisher bootstrap remains
an external prerequisite.

## Passing local gates

On x86_64 with Rust/Cargo 1.94.0 and Node 26.3.0:

- `npm test` passes strict TypeScript compilation, protocol/state-machine tests,
  SQLite persistence, pressure-scope isolation, and restart replay tests;
- `cargo test --workspace --offline` passes the independent Rust protocol,
  cryptographic-vector, SQLite, HTTP, rotation, pressure, and replay suites;
- `cargo clippy --workspace --offline --all-targets -- -D warnings`,
  `cargo fmt --all -- --check`, JavaScript syntax checks, and
  `git diff --check` pass;
- current dependency advisories are clean: npm reports zero vulnerabilities,
  and cargo-audit 0.22.2 scanned all 221 locked Rust dependencies against 1,189
  RustSec advisories at database commit `6d7aef354b4144c1ede046034adfd00246d3b0c0`
  with `--deny warnings` and returned success;
- `npm run test:standalone-interop` generates a fresh protected 2048-bit RSW and
  Ed25519/VOPRF key bundle, starts the optimized Rust and JavaScript standalones
  on one SQLite WAL database, compares discovery documents, reverses issuance
  and authenticated final verification, races both operations simultaneously
  across the two processes to require exactly one success, exercises the
  cross-language blinded trust-credit exchange, and obtains and completes
  replacement work. It also rotates through both keygen implementations while
  unredeemed challenges and trust issuer overlap are present. It passes locally
  and is a pinned CI job;
- the complete deterministic challenge envelope, canonical CBOR, Ed25519 public
  key, RSW input, daily network pseudonym, and rendering digest vectors match in
  Rust and TypeScript. The shared work-price fixture covers baseline, network
  capping, debt/velocity, exact two-minute Tier-0 expiry, and Tier-32 lifetime
  behavior. The fresh-install default uses a measured 15-second CSS-round
  allowance and two-year ceiling; its 43,984,411-second Tier-32 estimate does
  not hit that ceiling. Signing-key and
  RSW-trapdoor overlap tests honor work issued before rotation, overflow vectors
  fail without wrapping, and both policy validators reject zero base lifetimes
  before durable-store writes;
- all eleven public JSON schemas now compile together in strict Draft 2020-12
  mode with URI formats enabled. Broken filename-based references were replaced
  with their published `$id` targets. The complete TypeScript
  issue/redeem/siteverify/fallback/audit/error lifecycle validates against the
  applicable definitions, and the real dual-standalone harness validates every
  Rust and JavaScript success/error exchange. Negative tests reject private
  pricing fields, cross-envelope values, invalid backends, and non-canonical
  error actions. Ajv and its format plugin are exact dev-only dependencies and
  are pruned from the JavaScript production image;
- bounded identifiers and bindings now use the same UTF-8 byte counts and full
  Unicode control-character rejection in both cores. Shared multibyte/C0/C1
  vectors cover exact and one-byte-over tenant, region, session, and network
  boundaries. The public schemas enforce matching `x-shar-*Utf8Bytes` and
  `x-shar-noControlCharacters` extensions rather than relying on JSON Schema's
  UTF-16-independent character count alone;
- both standalone processes reject the same invalid region and trust-retention
  configuration matrix with `EX_CONFIG`. A language-neutral listener corpus
  requires identical hostname, IPv4, bracketed IPv6, canonical port, and
  invalid-address behavior. Occupied listeners produce concise startup errors
  rather than a Rust panic or JavaScript stack trace.
  Both internal container healthchecks follow the configured listener and
  translate wildcard IPv4/IPv6 binds to loopback probes. The native probe also
  resolves hostnames, and its direct loopback test is an explicit pinned CI
  step;
- both CBOR/COSE decoders enforce matching 64-level and 4,096-item limits. A
  shared hostile corpus covers non-canonical forms, invalid UTF-8/simple types,
  length overflow, 16 KiB-class recursive nesting, and item exhaustion. Both
  cores prove every invalid token returns `invalid_challenge` without nonce,
  pressure, or audit mutation;
- WebCrypto Ed25519 is preferred, with a pinned MIT pure-TypeScript
  `@noble/curves` fallback for unsupported runtimes. The fallback's Ed25519
  implementation is in the scope lineage of the library's independent Cure53
  review; forced-fallback tests prove byte-identical public keys and COSE
  signatures plus strict RFC 8032 verification;
- a single compiled-package lifecycle test runs unchanged in Node, Bun, and
  no-permission/no-prompt Deno. It masks process/runtime globals and outbound
  fetch where the host permits, proves a correctly issued Tier-0 quote remains
  valid after later pressure raises a new quote, and covers replay protection,
  authenticated `siteverify`, compatibility scoring, metrics, and graceful
  audit draining. Package inspection recursively checks Shar plus both pinned
  Noble dependencies for Node built-ins, filesystem/subprocess APIs, native or
  WebAssembly artifacts, and runtime-global escape hatches;
- trusted-proxy parsing walks only configured CIDR suffixes, rejects malformed
  chains, normalizes IPv4-mapped peers, and leaves untrusted forwarding headers
  unused. Network pseudonyms are daily and tenant/site scoped.
- both standalone entrypoints validate the same language-neutral canonical
  browser-origin corpus and reject the full configuration with `EX_CONFIG` on
  wildcard, path, credentials, whitespace, duplicate, empty-segment,
  non-local HTTP, or non-canonical port/host forms. The pure Fetch handler
  validates an explicit allowlist identically; an omitted handler allowlist
  intentionally leaves browser issuance disabled.
- optional trusted deployment-region bindings can be selected with
  `SHAR_REGION` (or the Fetch handler's region callback), are signed into both
  language implementations, and round-trip through final verification without
  changing the no-region vectors.
- browser challenge bodies cannot choose a session-debt scope. Both HTTP
  implementations discard `session_binding` from the body; trusted server
  callbacks or a trusted-proxy `X-Shar-Session-Binding` header are the only
  injection paths, with matching signed-claim regression tests.
- optional assurance pricing now has the same explicit standalone boundary in
  Rust and JavaScript. Privacy mode defaults it off;
  `SHAR_ASSURANCE_MODE=trusted-header` refuses startup without a configured
  trusted proxy CIDR, accepts only canonical tiers 0–32 from that immediate
  peer, and ignores browser-body or untrusted header values. Cross-server tests
  require identical tier-six quotes, stable malformed-header errors, and
  browser attempts to remain tier zero. Raw behavioral fields remain upstream,
  and redemption/final verification never consult the header;
- the public `SignalProvider` and `FallbackVerifier` contracts are now active
  integration boundaries in both cores rather than declaration-only types.
  Signal output can only raise a new quote, invalid or unavailable output fails
  before pricing mutation, and later provider failure cannot affect the signed
  proof. Fallback rejection and outage occur before assertion consumption, so a
  corrected or recovered provider can retry the same id. Optional provider
  health checks feed readiness. Shared language-neutral vectors and lifecycle
  tests cover merge, failure, retry, replay, and immutable-quote behavior;
- `render-v1` derives every triangle program from a fifteen-word canonical CSS
  transcript. The real CSS executor checks quantized cascade, nested
  size/style-query, grid/flex, transform, writing-mode, topology, clipping,
  stacking, and hit-test intermediates before it can complete. The widget emits
  the resulting commitment for CSS work and both servers reject a malformed or
  well-formed-but-wrong commitment without consuming the challenge. Four
  language-neutral vectors bind the transcript, final digest, and commitment.
  The current Playwright 1.62.1 run passes all 21 rendered/admin cases in
  Chromium 151 and all 20 applicable cases in Firefox 153 and WebKit 26.5; the
  live WebGPU/WebGL2 loss injection is Chromium-only. Chromium and Firefox ran
  through their managed host binaries; WebKit ran through the repository's
  reproducible digest-pinned
  `mcr.microsoft.com/playwright:v1.62.1-noble` container because its Ubuntu
  fallback build requires library versions unavailable on this host.
  Besides strict CSP, CPU/GPU/CSS identity,
  forced fallback, CSS redemption, and widget/Cap interactions, this executed
  matrix now covers navigation resume/cleanup, stale-owner protection,
  concurrent widget isolation, native form lifecycle, successful-token expiry,
  reCAPTCHA/hCaptcha adapters, complete blinded-credit earn/store/spend,
  keyboard-only widget and admin operation, modal/mobile-navigation focus
  containment and restoration, 400%-equivalent reflow, reduced motion, and
  forced colors. Widget controls retain 44 CSS-pixel targets and visible focus
  under the deployed strict CSP.
  A new opt-in physical Chromium project disables software rasterization. On
  Intel Iris Xe it passes all 21 browser cases, including full executor identity
  and a real loss sequence:
  round one completes through WebGPU, `GPUDevice.destroy()` loses the device on
  round two, `WEBGL_lose_context` then loses WebGL2, and CSS completes the same
  signed work while retaining the finished round. The same loss regression
  also passes under forced SwiftShader;
  It also loads the packaged Rust/WASM time-lock accelerator, requires its
  output to match the canonical JavaScript proof, substitutes a malformed WASM
  response, and requires the same quote to complete through JavaScript without
  changing proof bytes.
  This is cross-engine desktop software-renderer evidence; physical Intel
  evidence is recorded below, while the broader GPU, mobile,
  assistive-technology, and shipping-version matrix remains open;
- the default rendering round is now 256 triangles by 4,096 samples, or
  1,048,576 exact predicates. Pure TypeScript uses proven-safe `Number` integer
  arithmetic for its guarded 20-bit coordinates instead of `BigInt`, reducing
  this host's Node reference median from roughly 370 ms to roughly 15 ms without
  changing any digest. A hardened calibration now verifies the actual Chromium
  GPU process through a benchmark-only CDP query and fails mislabeled runs.
  On the host's physical Intel Iris Xe ADL GT2 through Mesa 26.0.8 and ANGLE
  Vulkan, five full-setup samples measured a 14.0 ms WebGL2 median, 24.8 ms
  WebGPU median, and 10.77 s CSS completion with identical output, a 769×
  fastest-accelerated/CSS separation. The matching forced-SwiftShader run
  measured a 70.0 ms WebGPU median, 195.9 ms WebGL2 median, and 8.94 s CSS
  completion with the same digest. The local bounds,
  digest, CSS completion, physical 8–16 ms latency, and 10× separation gates
  pass. A digest-pinned Playwright container now also forces headed Chromium
  through ANGLE OpenGL and verifies the actual Mesa llvmpipe renderer rather
  than accepting any software backend. CPU, llvmpipe WebGL2, and CSS produced
  the same digest. WebGPU was deliberately disabled so the run could not mix
  llvmpipe with the host's Intel Vulkan adapter. Five full-setup llvmpipe
  samples measured a 28.6 ms WebGL2 median and 14.31 s CSS completion, a 500×
  separation. A separate Chromium run with GPU APIs disabled
  visibly completed the same harness digest through CPU, CSS, and adaptive CSS
  fallback with no relevant console messages. A loopback-only remote-CDP run on
  a physical Steam Deck then verified AMD Van Gogh (`1002:163f`) through
  RADV/ANGLE Vulkan rather than trusting its configured label. Five full-setup
  samples measured a 17.0 ms WebGL2 median, 19.7 ms WebGPU median, and 14.79 s
  CSS completion with the same digest, an 870× separation. Backend,
  bounded-work, digest, CSS-completion, and 10× gates pass; the device honestly
  misses the aspirational 8–16 ms latency band by 1 ms. All software artifacts
  remain non-GA-scoped. A headed Android Chrome 150 run on a physical Pixel 7
  Pro then verified Arm Mali-G710 (`13b5`) and its r54p3 driver through CDP.
  CPU, WebGPU, WebGL2, and CSS produced the same digest; five full-setup samples
  measured a 39.7 ms WebGPU median, 66.3 ms WebGL2 median, and 12.11 s CSS
  completion, a 305× separation. Correctness and speedup gates pass while the
  mobile device honestly misses the 8–16 ms latency band. The temporary ADB
  mappings and test tabs were removed after capture. The full reference-device
  matrix is still a GA gate;
- the reproducible pure-JavaScript time-lock calibration uses a retained public
  modulus from a generated 2048-bit RSW semiprime, without retaining or
  distributing its trapdoor. Five 100,000-iteration samples measured a local
  minimum of 189,581 and median of 223,026 sequential squarings per second,
  exceeding the fresh-install 100,000/s lifetime allowance. The artifact is
  explicitly local-only and leaves browser/device, energy, and Tier-32
  completion evidence open;
- `@shar/server`, `@shar/widget`, and `@shar/cap-compat` build as independent
  JavaScript/declaration artifacts with package-local MIT licenses. Isolated
  tarball installation and compiled-entry smoke tests pass, including the
  widget's exported WASM subpath and binary. Widget pause/resume, fallback,
  cleanup, and Cap hidden-token/event contracts pass in Chromium;
- `@shar/widget` now includes an explicitly opt-in 68,751-byte Rust/WASM
  sequential-squaring accelerator while preserving pure JavaScript `BigInt` as
  the universal/default path. Each call is bounded to 65,536 iterations and a
  512-byte integer, reuses the exact signed plan, checkpoints only at the same
  chunk boundary, and restores the pre-chunk value before JavaScript fallback.
  The artifact SHA-256 is
  `abfe1fde6d133526abe811ecd19cdc251e7595f5910cdad46d21800b2f20cde8`.
  Rust 1.94.0 `wasm32-unknown-unknown` rebuilds remap the repository and Cargo
  registry to canonical paths before code generation, preventing dependency
  panic locations from making the binary host-specific. CI and tagged-release
  preflight rebuild and compare the committed binary before packaging. Node
  tests cover ABI bounds, digest, output identity, and an unavailable
  WebAssembly runtime. The default browser cold path and the pure-TypeScript
  server remain WASM-free;
- `@shar/widget` now exports separate reCAPTCHA- and hCaptcha-shaped browser
  adapters. Browser coverage proves rendered and invisible/v3-style execution,
  conventional response field names, callbacks, response/reset/removal state,
  and opt-in global installation that refuses to overwrite an existing SDK.
  Both adapters delegate to canonical Shar execution rather than introducing a
  compatibility-only proof or score path;
- browser execution now checkpoints an exact issued quote, sequential-squaring
  state, and completed rendering-round digests in a scope-bound, 4 MiB-capped
  same-tab record. Compare-before-write ownership prevents stale cancelled work
  from damaging a successor; completion/reset clear the record and
  malformed/expired records fail closed to fresh issuance. The browser matrix
  contains a pause/navigation/resume test that requires one issuance and the
  same eventual CSS proof, plus corruption, expiry, reset, cleanup, and stale
  owner cases. The storage validator honors the protocol's inclusive boundary:
  a checkpoint remains resumable at `now == expires_at` and is removed one
  second later;
- the form-associated widget now implements native reset, disabled, and form
  state-restore callbacks. It never restores a browser-cached single-use token,
  updates fallback submission names, disables its controls with a disabled
  form/fieldset, and forwards `Shar.render()` signals and event callbacks. The
  browser matrix includes native `FormData`, rename, fieldset, reset, and
  history-state cases;
- successful widget responses now age out at the server-reported inclusive
  expiry, clear both native and Cap-compatible form values, update the live
  status, and emit one expiration event. Synchronous `getResponse()` deadline
  checks prevent background timer throttling from exposing stale tokens; the
  browser matrix includes a deterministic expired-success case;
- `<cap-widget>` now explicitly owns one compatibility hidden field instead of
  also participating through Shar's native form value. Field renames,
  disabled-state exclusion, reset, and expiry remain synchronized without
  duplicate `shar-token`/`cap-token` submission; a browser form-data case guards
  the contract;
- rendered widgets now own independent execution controllers and scoped
  checkpoint reset behavior. Starting, pausing, resetting, or superseding one
  element cannot cancel another form's proof; global `Shar` controls retain
  latest-execution semantics. The browser matrix pauses two CSS solvers,
  requires the second to survive a first-widget reset, and redeems its original
  quote, while the ordinary checkpoint suite protects cross-scope records;
- the widget now completes the optional blinded trust-credit lifecycle rather
  than ignoring server trust plans. It creates a fresh Ristretto255-SHA512
  blind, verifies and finalizes the returned VOPRF proof, stores one credit per
  exact endpoint/tenant/site/action/origin scope in a bounded same-tab wallet,
  and attaches it to the next challenge. Same-page claims prevent duplicate
  local offers; an explicit invalid/replayed/expired/unknown-key response clears
  the credit and retries once without it, while operational failure retains it.
  Deterministic tests cover transcript alteration, binding, exact expiry,
  consumption, corruption, storage denial, retry, and outage behavior. Every
  trust-path failure remains isolated from ordinary work and verification;
- the trust-credit envelope no longer uses a server-selected per-challenge
  nonce/input. Browsers generate the hidden 32-byte token nonce, while both
  cores bind public scope and exact lifetime into the VOPRF input and consume a
  stable key-id/output replay identifier. Shared vectors cover the metadata
  digest and replay id; both core suites reject lifetime rewrapping, and widget
  tests prove equal issuer plans produce different blinded inputs and client
  nonces. Lifetime metadata is rounded into a shared bucket no larger than one
  hour or 1/24 of configured retention, avoiding an exact per-challenge tag
  while preserving at least 23/24 of validity. This closes serialized-token
  replay bypass and direct per-challenge protocol-value linkage. Root rotation
  keys also derive distinct tenant/site/action/origin issuer child keys in both
  languages; shared public-key vectors and laundering regressions prove a blind
  evaluated under one scope cannot validate under another. These tests are not
  a substitute for the still-required independent RFC 9578/profile and privacy
  review;
- the widget has an extensible translation catalog with built-in English plus
  opt-in, separately bundled Arabic, German, Spanish, French, Hebrew, Hindi,
  Japanese, Brazilian Portuguese, and Simplified Chinese catalogs. It
  visibly retains the exact quoted sequential-step/render-round work and
  localizes live status, controls, number formatting, text direction, and its
  group/progress accessibility labels without restarting the proof. Chromium
  exercises every catalog and dynamic RTL relocalization; package tests enforce
  complete, bounded messages and exact placeholders. Professional linguistic
  review remains open;
- Rust and TypeScript PostgreSQL adapters share atomic nonce, pressure, policy,
  and outstanding-work semantics. Pricing and outstanding-work reservation now
  occur under one row-locking transaction, so simultaneous requests cannot all
  observe the same pre-reservation pressure. Both standalone servers select PostgreSQL
  through `SHAR_POSTGRES_URL`, use ten connections, require certificate-verified
  TLS, and accept an optional custom CA.
- Rust and TypeScript Redis-compatible adapters share hashed, action-sharded
  keys and atomic scripts for nonce consumption, velocity, outstanding work,
  failure/assurance decay, and outcome updates. Both standalones can use Redis
  for nonce/pressure state while retaining SQLite or PostgreSQL configuration;
  exact integer pressure-tier boundaries and inclusive nonce-expiry markers
  match SQL and memory stores, and outstanding cleanup retains quotes at the
  inclusive expiry second. Both adapters reject a one-second marker at the
  JavaScript/Redis exact-integer ceiling. Lua deadline arithmetic is rejected
  before a timestamp can exceed its exact IEEE-754 integer range; non-TLS Redis is
  allowed only in explicit insecure-development mode. Atomic quote pricing and
  reservation use one five-key script; the servers precompute all 33 finite,
  overflow-checked expiries and the script selects the exact quoted tier.
  Redis audit persistence now groups the bounded worker batch by privacy-safe
  action hash slot and coalesces up to 128 events over a bounded 10 ms window in
  both languages. Each Lua invocation allocates one contiguous sequence range
  with `INCRBY` and performs one multi-member `ZADD`, rather than two Redis
  calls per event. Live TypeScript race/reconnect coverage and the Rust adapter
  profiler verify that byte-identical events remain distinct and read back in
  descending order against Redis.
  The Rust Redis and accepted-HTTP sockets explicitly disable Nagle; a
  back-to-back local adapter profile improved from 1,854 to 21,699 atomic
  quotes/second after the Redis fix, while retaining the same Lua and key
  semantics. The atomic script now also treats missing hash fields as their
  protocol zero/now defaults and refreshes each TTL only once, instead of
  running redundant existence, initialization, and expiry commands on every
  quote. On the current 32-way, network-scoped profile this improved atomic
  pricing from 10,156 to 16,392 quotes/second and complete Redis/SQLite-config/
  trust/signing/JSON issuance from 6,835 to 14,210 quotes/second. These are
  diagnostic results against local Redis, not the end-to-end GA gate;
- both Redis-compatible adapters now retain only the most recent complete
  policy/current-second table of all 33 overflow-checked quote expiries. Every
  policy field participates in invalidation, the Rust lock is released before
  Redis I/O, and the Lua reservation script and exact expiry values are
  unchanged. They also retain at most 1,024 exact action/session/network key
  derivations, using read-concurrent lookup in Rust and bounded FIFO eviction
  in TypeScript. This avoids repeated SHA-256/WebCrypto derivation without
  weakening full-scope equality or retaining anything at rest. Shared tests
  prove reuse, time/policy/binding invalidation, bounded eviction, existing key
  vectors, and expiry equality with independent pricing for every tier. These
  changes remove repeated hot-path cryptographic/pricing allocation work but
  are not yet reflected in the retained three-run throughput artifact;
- in-memory and SQLite pricing also combine pressure observation and issuance
  reservation atomically. Exact 64-request concurrency tests require the full
  logarithmic tier multiset in both languages and against live PostgreSQL and
  Redis, rather than merely checking that all requests returned. The public
  Rust trait and TypeScript interface now require the combined operation; the
  JavaScript service also rejects non-atomic custom adapters during construction.
- both SQLite implementations retain individual outstanding rows for inclusive
  expiry and outcome removal while database triggers maintain the per-scope
  count in the same transaction. Pricing therefore remains constant-time as
  outstanding work grows instead of rescanning every live row or issuing split
  application-side counter updates. Existing databases seed the counter from
  authoritative rows at startup, with matching migration tests.
- all pressure-store outcome contracts now carry the signed challenge expiry.
  Memory, SQLite, PostgreSQL, and Redis remove one exact-expiry outstanding
  entry rather than whichever quote was oldest, preserving correct future
  tiers when a later, longer-lived quote completes first. Rust and TypeScript
  memory/SQLite tests cover out-of-order success and expiry; Redis script and
  PostgreSQL query contracts require exact-score/exact-row selection. The
  unsupported-modulus failure transition is also aligned across both cores;
- Rust engines cache the expanded Ed25519 signing key, canonical protected
  COSE header, and fixed Sig_structure prefix. TypeScript services retain their imported WebCrypto signing key,
  and the standalone retains its configured network-pseudonym HMAC key; the
  public one-shot cryptographic helpers remain available. Tokens and
  deterministic vectors are unchanged. The Rust issuer now writes the fixed
  challenge map and COSE Sign1 shape directly into pre-sized canonical buffers
  instead of allocating and sorting generic CBOR trees. Ed25519 hashes the
  immutable Sig_structure prefix and payload incrementally, avoiding a second
  challenge-sized message allocation. Boundary tests compare every direct byte
  and signature to the generic canonical reference across payload/key/map
  option sizes;
- the Rust core now exports the same named rendering, presence, fallback,
  signal-provider, and fallback-verifier contracts as `@shar/server`, including
  typed rendering backends and optional CSS transcript commitments. Shared
  serialized shapes remain unchanged, exact commitment verification is
  implemented in both engines, and native/TypeScript tests consume the same
  language-neutral transcript vectors.
- in-memory, SQLite, PostgreSQL, and Redis-compatible pressure/nonce adapters
  reject negative timestamps and expiries before state mutation, keeping the
  Rust `u64` and TypeScript numeric contracts aligned.
- redemption, final verification, and host fallback fail closed with the same
  retryable `clock_unavailable` error when an injected TypeScript clock is
  negative or outside the safe integer range; no proof is classified or
  consumed under an invalid clock.
- both servers implement an optional privileged host fallback endpoint with a
  separate 32-byte bearer secret, bound method/origin/action fields, and atomic
  assertion-id replay exclusion. It returns a direct fallback result and never
  mislabels fallback as completed proof-of-work. Challenge responses now carry
  required, matching `PresencePlan` and `FallbackPlan` objects. Both
  standalones validate the same bounded, unique `SHAR_FALLBACK_METHODS` list,
  reject methods outside it, and advertise no fallback when the secret is
  absent. The widget hides its fallback control until a quote advertises at
  least one method, then emits that exact list and host-presence mode;
- direct Rust and TypeScript core calls now also reject fallback completion when
  their advertised plan is unavailable, closing a guard that previously relied
  on the standalone HTTP bearer layer. Both cores export matching stored host
  assertion verifiers with idempotent store/health contracts, exact binding
  checks, a five-minute maximum lifetime, and fail-closed clock/store handling.
  Shared vectors cover valid, missing, expired, future-dated, overlong,
  mismatched, and corrupt records; integration tests cover operational retry
  before nonce consumption and replay after success. The host still owns the
  actual WebAuthn, email, authenticated-session, or support method. The Fetch
  handler also compares its privileged endpoint configuration with the core's
  browser-visible plans at construction time, so it cannot advertise a method
  the core will reject or silently expose a completion route the challenge did
  not advertise;
- both standalone servers expose the same four privacy-safe, unlabeled success
  counters, two cumulative issuance phase-duration counters, and
  `shar_audit_events_dropped_total` at `/metrics`; process
  liveness remains separate at `/healthz`, and
  `/readyz` performs read-only probes of the configuration, pressure, and nonce
  dependencies. Rust/TypeScript core, HTTP, adapter, and standalone interop
  tests cover the matching readiness contract; audit remains best-effort.
- deployable Prometheus alert rules and a provisionable Prometheus/Loki Grafana
  operations dashboard cover scrape availability, successful protocol rates,
  mean issuance phases, audit loss, and privacy-safe request observations.
  Static validation derives the metric set
  from both Rust and TypeScript expositions, requires dashboard coverage for
  every metric, rejects unknown alert metrics and privacy-sensitive query
  dimensions, and checks the Kubernetes scrape annotations. Readiness remains
  an independent probe and alerts never affect proof validity.
- both standalone servers attach fresh request IDs and emit the same
  `request-observation-v1` JSON completion shape. It contains only a normalized
  method/route, status, duration, and random correlation id; standalone interop
  parses both real logs and rejects extra or request-derived fields. The Fetch
  handler exposes the same header and a failure-isolated observation callback.
  A separate namespace-scoped Alloy deployment watches only the Shar container,
  drops malformed and non-observation lines, retains correlation fields as
  structured metadata rather than indexed labels, and forwards to a
  secret-configured Loki gateway. It uses a digest-pinned multi-architecture
  image, least-privilege Role, non-root/read-only security context, and exact
  source/ConfigMap equality checks. The official Alloy validator passes locally
  and is a CI/release preflight gate. Target Loki retention, authentication, and
  access-control verification remain open;
- both standalones and the runtime-neutral Fetch handler enforce a bounded
  aggregate in-flight protocol/admin gate. Saturation returns matching CORS-safe
  retryable `capacity_unavailable` responses without pressure mutation, while
  liveness/readiness/metrics remain available. The real Rust/JavaScript interop
  run holds a partial request at a one-request limit, verifies rejection, then
  releases it and verifies immediate recovery on each implementation.
- the Rust HTTP boundary dispatches all synchronous engine and
  SQLite/PostgreSQL/Redis operations through Tokio blocking workers, while the
  aggregate request gate bounds submitted work and readiness is single-flight.
  Initial synchronous store construction and PostgreSQL/Redis connection-pool
  creation also run on a blocking worker, preventing the synchronous
  PostgreSQL client from attempting a nested runtime during async startup.
  A current-thread regression holds a blocking operation and proves the async
  worker continues to schedule, while preserving the original stable error.
- both standalones validate one 100–60,000 ms state deadline and apply it to
  SQLite lock waits, PostgreSQL connect/query/statement/lock/session/TCP waits,
  and Redis connect/command or socket I/O. Adapter/source regression tests
  cover every wiring point. Deadline failures remain retryable operational
  errors and do not introduce a client proof-completion timeout.
- both final-verification endpoints require the same stateless `shrs1_`
  credential derived from an independent master and bound to one tenant/site.
  Authentication precedes atomic token consumption, preventing unauthenticated
  token-consumption denial of service; Rust/TypeScript vectors and compatibility
  form tests cover the credential and tamper rejection.
- both cores implement the optional blinded trust-credit flow documented in
  `docs/trust-credits.md`: shared RFC 9497/Ristretto255 transcript vectors,
  scoped canonical-CBOR `shrtrust1_` tokens, overlapping issuer keys, seeded
  proof randomness, atomic single-use consumption, and bounded retention. An independently reviewed
  RFC 9578 deployment profile and production assurance-retention review remain
  open; trust credits are disabled unless their issuer keys are configured.
- Rust and pure-JavaScript keygen tools generate fresh protected bundles and
  atomically preserve overlapping signing/RSW material. The live standalone
  test rotates through both tools while unredeemed challenges are outstanding
  and proves each new server honors them. Both cores now consume shared RSW-key
  validation vectors and compare deterministic sequential squaring with
  trapdoor evaluation before accepting current or overlapping keys. The live
  test corrupts a freshly generated 2048-bit lambda and proves both standalone
  processes refuse to bind. Both generators apply 64 randomized Miller–Rabin
  rounds to each 1024-bit factor; independent review of key generation remains
  an explicit release gate.
- the shared live-store harness passed 64-way nonce races plus pressure,
  exact atomic quote-price/reservation tiers, assurance, failure, and success
  transitions against PostgreSQL 16 Alpine and Redis 7.4 Alpine on this host.
  It reconnects each client/pool and proves the
  first consumed nonce remains rejected after restart. A second live harness
  starts the optimized Rust and JavaScript processes together with PostgreSQL
  configuration and Redis atomic state, races redemption/final verification
  across processes, restarts both, and honors work issued before restart. The
  CI job pins both service images by digest. Rust Redis pool entries now discard
  a connection after any command error and reconnect on the next independent
  request without replaying the ambiguous failed command; a real loopback TCP
  regression drops the first socket and proves exactly one failure followed by
  recovered readiness. The JavaScript standalone explicitly bounds reconnect
  backoff with offline queuing disabled, and its adapter test proves no command
  replay. Rust PostgreSQL pool entries also replace closed clients before use;
  a live PostgreSQL regression terminates the actual backend PID, proves the
  observing probe fails without replay, and proves the next probe succeeds on a
  newly configured client. Managed-service failover,
  partition, TLS, and genuinely separate-host races remain open.
- both standalone servers expose the same scoped work-policy API behind an
  independent 32-byte admin bearer secret and serve responsive React policy,
  operations, and privacy-filtered scoped audit views at `/admin/`. Rust and
  TypeScript tests cover authentication, finite
  Tier-32 validation, persistence, and new-quote application. Playwright covers
  unlock failure/success, exact BigInt previews, save and JSON flows, CSP,
  operations counters, desktop layout, keyboard-only unlock and navigation,
  modal focus cycling/restoration, a narrow 400%-equivalent CSS viewport,
  reduced motion, and forced colors. The secret remains tab-memory-only;
  broader admin authorization, target trace-storage controls, and
  independent accessibility/security review remain release gates.
- both language cores now emit best-effort `audit-v1` events for issued,
  redeemed, verified, and fallback work. SQLite, PostgreSQL, Redis-compatible,
  and in-memory stores retain only tenant/site/action, outcome, tier, backend,
  and timestamp metadata with a 24-hour audit retention window; origins,
  session bindings, network pseudonyms, addresses, user agents, and device
  identifiers are excluded. Each standalone places writes behind a bounded
  4,096-event queue, coalesces batch-capable stores into at most 128 events,
  and reports queue overflow or storage loss through the unlabeled dropped
  counter. SQLite persists each batch and retention prune in one transaction.
  Audit write failures never affect proof validity. Graceful shutdown now stops
  HTTP admission, drains accepted requests, flushes every accepted audit event,
  and only then closes the underlying state clients. TypeScript tests cover
  in-flight writes, storage failure, idempotent close, and post-close drops;
  Rust additionally proves a blocked store cannot exceed its reserved
  five-second final audit budget. Both standalones now enforce the same
  configurable 6–300 second total shutdown deadline (25 seconds by default),
  reserve its final five seconds for cleanup, and exit nonzero after a forced
  drain. Compose and Kubernetes allow 30 seconds for the default. The real
  dual-standalone SIGTERM/rotation suite passes with this ordering.
- local loopback smoke tests started each real standalone against SQLite and
  the compiled production dashboard. Both returned the same default policy,
  liveness/readiness results, request-id contract, no-cache HTML, and strict
  same-origin CSP/security headers. The dual-standalone lifecycle now also
  requires every dynamic response to be `no-store` and `nosniff`, and proves an
  early oversized challenge retains the stable 413 body, allowed-origin CORS,
  exposed request id, and security headers in both transports.
  A partial-body socket test now requires both transports to return the same
  no-store, CORS-enabled, retryable 408 after the configured intake deadline;
  the deadline ends before pricing or nonce-consuming verification begins and
  therefore cannot invalidate correctly submitted work.
- Podman rebuilt both current x86_64 images on supported, immutable Debian 13
  manifest digests and ran each as UID/GID 10001 with a mode-0400 secret volume
  and ephemeral data volume. Rust measured 91.3 MB and JavaScript 251.0 MB
  locally. Both real images returned ready after the base upgrade. The final
  JavaScript image removes npm, npx, and Corepack because they are build tools,
  not serving dependencies. A checksum-verified Grype 0.110.0 scan matching the
  workflow's pinned engine found no high/critical vulnerability with an
  available fix in either amd64 image. Complete upstream-unfixed findings
  remain visible rather than being described as clean. The workflow now builds
  both amd64 and arm64 inputs as explicit Docker archives on matching native
  GitHub-hosted runners and scans all four image/platform pairs before the
  publication job receives credentials. Each image/platform pair has a distinct
  GitHub Actions cache scope, avoiding the backend's default cross-matrix cache
  overwrite. A
  registry-backed contract checks that every digest is an OCI index with both
  required Linux architectures. This caught and replaced three initially
  selected amd64 child-manifest digests: the corrected local arm64 attempt now
  pulls an actual arm64 Node binary and stops at the expected missing host
  emulation boundary instead of silently producing relabeled x64 output. The
  QEMU-backed publication build, completed multi-architecture output, and
  registry publication remain open.
  The protected release now extracts BuildKit's attached SPDX document for
  each published platform, rather than asking a second scanner to interpret an
  ambiguous multi-architecture index. Both documents and their shared checksum
  manifest are independently signed before becoming release assets.
- the deployment examples now include hardened single-node Compose and a
  two-replica Kubernetes scaffold with distinct startup, liveness, and
  readiness probes, a disruption budget, and external PostgreSQL/Redis state.
  It remains scaffolding until the exact target cluster, proxy, and managed
  stores pass the open failover and partition gates.
- CI and protected-tag release jobs run deployment and workflow contract
  checkers that fail if non-root/read-only execution, owner-only key staging,
  capability drops, loopback binding, readiness/liveness paths, external HA
  state, overload/state-deadline settings, immutable base/action pins, RustSec
  auditing, or pre-publication vulnerability gates regress.
- pinned GitHub workflows define Node 22/24, Bun, Deno, Chromium, Firefox,
  WebKit, Rust tests, a fresh pinned Cap behavior matrix,
  live PostgreSQL/Redis adapter and dual-process restart tests, package
  inspection, and workflow linting. A protected-tag workflow is defined
  for OIDC npm publication, npm provenance, signed amd64/arm64 Rust and
  JavaScript images, SBOMs, checksums, Sigstore bundles, and GitHub build
  attestations. An unprivileged preflight now verifies both lockfiles and exact
  internal package versions, stages the npm tarballs/SBOMs once, and checksums
  them with relocatable paths. Every credential-bearing publisher waits for
  preflight and all four platform vulnerability scans; the npm publisher signs
  and promotes the exact tested candidates without a source rebuild. Each
  privileged job immediately verifies new Sigstore bundles against the exact
  tagged workflow identity and GitHub OIDC issuer. Container publication also
  verifies the immutable index signature and registry-backed GitHub provenance
  before extracting and identity-verifying both platform SBOM bundles. The
  CI workflow downloads actionlint 1.7.12 by immutable release URL and verifies
  its published SHA-256 before use. Both workflows pass that exact actionlint,
  release-metadata, runtime smoke, exact
  candidate staging/checksum/isolated-install, and package dry-run checks.
  Artifact transfer, Docker/QEMU/Buildx/build-push, and build-provenance actions
  are pinned to their current Node 24-runtime majors. CI has passed on both pull
  requests and `main`, including native amd64 and arm64 container scans. The
  protected-tag workflow remains intentionally unexercised until the npm
  namespace and trusted-publisher bootstrap are ready; its protected release
  environment and semantic-tag rules are configured.
- the Cap harness pins `standalone@3.1.8` and `widget@0.1.56` to exact commits
  and verifies npm integrity for the widget and its eagerly fetched WASM. A
  cold-cache Chromium capture observed no unexpected requests and measured
  15,723 Brotli body bytes for Shar versus 19,947 for Cap (78.82%), satisfying
  the <=80% cold-path byte threshold on this browser. This includes every eager
  ESM chunk; the optional trust-credit VOPRF code is dynamically loaded only
  when a stored credit exists or a quote advertises issuance, and non-English
  locale entry points are host-selected. Both are excluded explicitly rather
  than counted as default traffic. Raw inputs, exclusions, transfer sizes,
  hashes, and machine metadata are committed under `bench/cap`.
  The runner separately labels CPU reference/live-endpoint timings, can sample
  Linux `/proc` RSS during issuance when server PIDs are supplied, and refuses
  to infer energy or attacker economics from unlike work units. The standalone
  orchestrator runs fresh Cap/Rust and Cap/JavaScript pairs, alternates order,
  checks action cardinality and settings, stages every raw result until the
  complete paired run succeeds, applies native gates to every repetition, and
  now records decoded response-body sizes alongside latency. Both products use
  the same recorded worker pool, fixed total concurrency, and per-worker
  HTTP/1.1 keep-alive agents, so an implicit runtime-global connection pool
  cannot determine the result. The retained run uses one worker to avoid
  competing with the servers on this same host. Each Shar run also records
  server-observed engine and complete-handler duration deltas. Rust and pure
  TypeScript now avoid a redundant 2048-bit Euclidean step while deriving the
  time-lock input; the optimized Rust core profile increased time-lock input
  derivation from 16,471/s to 59,862/s and complete in-memory construction from
  4,214/s to 25,943/s without changing the protocol vectors. The refreshed
  core now reduces the modulus once and uses binary GCD on digest-width values;
  the pure-TypeScript implementation uses the same rejection-sampling
  algorithm. A later same-process fresh-modulus diagnostic measured 135,874
  binary derivations/s versus 42,247/s through the retained Euclidean reference
  (3.22x), with 22,512 trust-enabled complete core issues/s. Fixed challenge and
  COSE shapes also use byte-proven direct canonical encoders. A non-retained
  four-worker HTTP diagnostic raised absolute load-generator capacity and
  produced one native/Cap ratio of 1.56x, but one noisy run is not release
  evidence and remains below the 2x threshold. Subsequent non-retained prepared-
  signer diagnostics with four and eight client workers measured 6,996 and
  7,261 native issues/s versus 5,320 and 5,785 Cap issues/s (1.32x and 1.26x).
  The matching in-process Redis profile measured 15,854 atomic reservations/s
  and 12,514 complete trust-enabled issues/s, locating the remaining gap at the
  full HTTP path and comparative workload. The historical three-run SHA-PoW
  artifact and its failed gate remain unchanged: that run compares Shar's
  mandatory RSW issuance against Cap with `rsw: false`. Its refreshed
  matching-Redis run used a fresh non-persistent Redis instance. Native Shar
  issued 2,499-3,554 challenges/s versus Cap's 2,687-4,118/s (Rust RSD 0.15;
  paired Cap RSD 0.18). Its per-run throughput ratio ranged from 0.811x to
  1.101x with a 0.930x median, so the native 2x gate still fails. Native idle
  RSS remained 0.072x-0.074x of Cap and passes the half-memory gate. A separate
  staged three-run artifact under `bench/cap/results/rsw/` configures pinned Cap
  with its 2048-bit RSW mode and default 75,000 iterations. Native Shar issued
  6,514-7,719 challenges/s versus Cap's 725-735/s; every per-run ratio passed at
  8.98x-10.50x, with Rust RSD 0.071 and Cap RSD 0.006. Native idle RSS was
  0.069x-0.070x of Cap. The pure-TypeScript pairing also exceeded Cap RSW in
  every run at 2.35x-2.68x, though it publishes a separate platform benchmark
  rather than inheriting the native gate. The
  JavaScript pairing exceeded the variance warning because one Cap sample was
  an outlier, so it supports no comparative throughput conclusion. All results
  are retained as local reference evidence, not a production or multi-host
  benchmark; the protocol-matched local RSW gate passes, but throughput must still
  be repeated on an isolated load-generator/server setup before GA.
- a separate fresh-process Cap behavior matrix now covers SHA and RSW challenge
  redemption, single-use final site verification, instrumentation rejection,
  non-browser UA rejection, configured rate limiting, invalid-proof failure,
  and replacement challenge issuance. The evidence makes Cap's policy-rejection
  behavior explicit without importing it into Shar's no-rejection protocol.

## Container evidence

Both Dockerfiles now build on x86_64 with Podman and run as UID/GID 10001 with
a read-only mode-0400 key mount and writable `/data` SQLite volume. Their
health endpoints and dashboard security headers pass, and both stop cleanly
within a five-second SIGTERM grace period. The local uncompressed image sizes
are 91.3 MB for Rust and 251.0 MB for JavaScript; these are implementation
evidence, not published benchmark results.

The Rust and JavaScript standalones now canonicalize the required admin bundle
root during startup and constrain each final asset path to that root. Shared
regression coverage confirms that an in-tree symlink cannot disclose an
outside file; malformed JavaScript URL escapes fail closed rather than reaching
the generic error path.

The Rust image uses digest-pinned `rust:1.94-trixie` only as its builder and a
digest-pinned Debian 13 slim runtime. It copies the CA bundle from that pinned
builder and resolves no mutable runtime packages. The JavaScript image uses digest-pinned
`node:24-trixie-slim`, not the host Node version used for local tests, and its
final stage excludes npm/Corepack. Full reports and fail-closed actionable
high/critical scans are wired before any release job receives registry or OIDC
authority. Docker itself and the protected multi-architecture release workflow
remain unverified; the local Podman build and scan covered only `linux/amd64`.

## Public repository security evidence

The repository became public on 2026-08-05 only after a checksum-verified
Gitleaks 8.30.1 scan covered all 17 commits reachable through the main, review,
and Dependabot refs. Its four alerts were reviewed as intentional fixtures: one
published deterministic VOPRF test-vector scalar and three synthetic `shr1_`
browser-test tokens. Separate scans of pull-request bodies, reviews, comments,
issues, and commit comments found no secrets. A manual pattern pass also found
no private infrastructure address, ADB pairing detail, SSH endpoint, local home
path, private key, or provider credential in the tree or its three authored
commits.

GitHub provider secret scanning, push protection, vulnerability alerts,
Dependabot security updates, and private vulnerability reporting are enabled.
GitHub reports non-provider pattern scanning and validity checks as disabled for
this repository, so the one-time generic full-history scan is publication
evidence rather than a substitute for a future continuous generic-secret gate.

## Open release blockers

The authoritative incomplete list is in `roadmap.md`. Current rendering
evidence covers three desktop engine families, SwiftShader, Mesa llvmpipe, one
physical Intel Iris Xe, and one physical AMD Van Gogh Steam Deck, but not the
required NVIDIA, Apple, Adreno, wider mobile, and shipping-browser version
matrix. PostgreSQL
and Redis have no multi-host/failover test in
this environment (the single-service race now passes), and the external RFC
9578 trust-credit profile remains unreviewed. Production method-specific host
fallback deployments, the first externally verified SBOM/signing publication,
a passing isolated Cap native-throughput result, reference-device
latency/energy/attacker-cost benchmarks, and independent cryptographic,
privacy, rendering, and accessibility reviews also remain open.
