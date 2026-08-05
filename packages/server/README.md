# @shar/server

Pure TypeScript Shar protocol server and Fetch API handler. It depends only on
standard JavaScript and BigInt. WebCrypto is preferred; the audited, MIT-licensed
pure-TypeScript `@noble/curves` implementation provides Ed25519 when a runtime's
WebCrypto does not. It does not load Rust, native addons, WebAssembly,
subprocesses, the filesystem, or Node-specific APIs.

The same restricted-runtime lifecycle test runs in Node, Bun, and Deno. It
imports the compiled package with Node/process, WebAssembly, and outbound fetch
unavailable where the host permits those globals to be masked, then exercises
Fetch-based challenge issuance, future-quote pressure escalation, completion of
the original quote, replay rejection, authenticated `siteverify`, metrics, and
audit draining. Deno runs with no granted filesystem, network, environment,
subprocess, native-plugin, or FFI permissions and with prompting disabled. The
published dependency closure is also scanned for Node built-ins, `Buffer`,
native modules, WebAssembly, subprocesses, and runtime-specific filesystem
escape hatches. Browser, worker, import, and default export conditions all point
to the same runtime-neutral implementation.

`BufferedAuditStore` keeps best-effort persistence off the proof path. A host
that owns the process lifecycle should stop request admission, await
`bufferedAuditStore.flush()`, and only then close the wrapped state client.
`flush()` immediately drains every accepted event, counts storage failures
through the configured dropped-event callback, and closes the buffer to new
events; it never changes proof validity.

Construction validates current and overlapping RSW trapdoors by comparing
deterministic sequential squaring with protected trapdoor evaluation. Invalid
material or a modulus-id collision fails before the service can issue work.

See the repository README and protocol documentation for deployment,
configuration, and the no-policy-rejection invariant.

The Fetch handler exposes `/healthz` for process liveness and `/readyz` for
read-only configuration, pressure, and nonce dependency checks. Readiness
failures are retryable operational errors and never proof classifications.
Every response includes `X-Shar-Request-Id`; the optional `observeRequest`
callback receives only the normalized route/method, status, duration, and that
identifier. Observer failure is ignored.

Protocol/admin concurrency is capped at 256 requests per handler instance by
default and can be set from 1 through 65,536 with `maxConcurrentRequests`.
Saturation returns retryable `capacity_unavailable`; health, readiness, and
metrics remain available, and no pressure state is changed.

## Host providers

`SharService` accepts optional `signals` and `fallbackVerifier` providers. A
signal provider returns a trusted tier from 0 through 32 while a new quote is
being priced. Its value is combined with any existing trusted assurance tier by
taking the maximum; it can never make work easier. Provider failure or an
out-of-range result returns retryable `pricing_unavailable` before pressure
state, randomness, or trust credits are touched. The provider is never called
during redemption or final verification, so a correctly completed issued quote
remains valid if the provider later changes or fails.

The fallback verifier receives the configured method and complete bound
fallback request before the assertion nonce is consumed. Rejection returns
`fallback_not_verified`; provider failure returns retryable
`fallback_unavailable`. Neither consumes the assertion, so the host can retry
the same id after a transient outage or corrected verification. Verifiers
should therefore make their lookup idempotent by `assertion_id`. Optional
provider health probes participate in `/readyz`; they do not affect liveness or
already-issued proof verification.
