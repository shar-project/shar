# Shar protocol v1

## Normative invariant

For every supported and syntactically valid challenge request, the work pricer
returns a finite quote unless required pricing state is unavailable or the
service is under operational capacity backpressure. Neither condition is a
policy verdict. Once a challenge is signed, its exact finite work and expiry
are immutable. A correct, unexpired proof of that work MUST succeed exactly
once regardless of any signal observed before or after issuance.

Malformed/oversized messages, unsupported versions, bad signatures, incorrect
work, expired tokens, and replay attempts fail. All such clients remain
eligible to request new work. Implementations MUST NOT contain IP, ASN, country,
UA, webdriver, GPU, timing, or device denial lists.

The JSON documents under [`protocol/`](../protocol) are normative Draft
2020-12 schemas. Their cross-document references resolve through each schema's
published `$id`, not repository-relative filenames. Strict Ajv validation runs
over real TypeScript lifecycle documents and every successful/error response in
the dual Rust/JavaScript standalone exchange. Tests also require adversarial
cross-envelope fields, invalid backends, invalid error codes, and unsupported
next actions to be rejected by the schemas.

Bounded protocol text is measured in UTF-8 bytes, matching canonical CBOR and
both server cores, and Unicode control characters are rejected. The schemas
carry the `x-shar-minUtf8Bytes`, `x-shar-maxUtf8Bytes`, and
`x-shar-noControlCharacters` vocabulary extensions where standard JSON Schema
character counts are insufficient. Shar's strict conformance validator
implements those extensions; third-party validators must do the same before
claiming full request conformance. Multibyte and C0/C1 control boundaries are
frozen in [`bounded-text-vectors.json`](../protocol/bounded-text-vectors.json).

The first-class standalone distributions also consume
[`standalone-listen-vectors.json`](../protocol/standalone-listen-vectors.json).
It freezes their shared hostname, IPv4, bracketed IPv6, and canonical port
syntax. Port zero is excluded because a separately invoked readiness probe
cannot rediscover the ephemeral port.

## State machine

```text
request --price--> issued --correct proof + atomic consume--> redeemed
                       |                       |
                       | expired/invalid       +-- signed verification token
                       v
                     failed (a new request is always allowed)

verification token --atomic consume--> accepted exactly once
```

Challenge issuance is stateless after reading pressure. Only nonce consumption,
pressure debt, configuration, aggregate metrics, and privacy-filtered audit
events need durable storage. Audit records use `audit-v1`, retain only tenant,
site, action, outcome code, tier, rendering backend, and timestamp, and default
to a 24-hour retention window. They never contain origins, session bindings,
network pseudonyms, addresses, user agents, or device identifiers. Audit
storage is best-effort and cannot affect proof validity.

PostgreSQL pressure scopes use the versioned `v1:` form with each tenant,
site, action, session binding, and network pseudonym encoded as URL-safe
base64 components. Rust and TypeScript derive the same ASCII keys; this avoids
database-forbidden NUL delimiters without storing raw session or network
identifiers in PostgreSQL scope rows.

The privileged `GET /v1/admin/audit` view accepts an exact tenant/site/action
scope and a limit from 1 through 100. It returns newest-first events only for
that scope; implementations MUST reject broader or unbounded audit reads.

## Pricing (`work-price-v1`)

Inputs are non-negative integer tiers:

- base tier (site/action policy), velocity, and outstanding challenge pressure;
- network pressure, capped at four tiers in aggregate;
- failure and assurance debt;
- unlinkable trust credits.

`debt = max(0, failure + assurance - trust)` and
`tier = min(32, base + velocity + outstanding + min(4, network) + debt)`.
All additions are saturating and checked. Trust never reduces base, velocity,
outstanding, or network pressure. Pressure stores decay accumulated debt by one
tier per configured quiet window.

Expiry is inclusive at the signed second: `now == expires_at` is still
unexpired. Atomic nonce stores must retain a consumed marker through that
boundary so Redis, SQL, and in-memory adapters have identical replay behavior.
Outstanding-work pressure uses the same inclusive boundary; cleanup removes
only quotes with `expires_at < now`.

Velocity and outstanding counts use the tenant/site/action scope. Failure and
assurance debt use the optional host session-binding scope. HTTP handlers MUST
ignore a browser-supplied `session_binding`; a trusted host may inject the
binding through server context (the standalone servers accept
`X-Shar-Session-Binding` only from a configured trusted proxy). When no session
is available but a daily network pseudonym is, failures accrue only to the
network scope and therefore remain inside the four-tier network cap; one shared
network must not inherit another network's debt. Assurance without a session
affects the current quote but is not persisted into an anonymous shared scope.

`iterations = base_iterations * 2^tier` and
`render_rounds = base_rounds * 2^min(tier, 8)`. Both values are unsigned 64-bit
integers and MUST be overflow checked. Tier 0 expires after exactly the
configured two-minute base lifetime. Higher tiers add
`ceil((iterations - base_iterations) / iteration_allowance)` seconds and
`(render_rounds - base_rounds) * round_allowance_seconds`, capped only by the
configured maximum lifetime. The expiry is signed and never shortened. The
default 100,000-iteration/second estimate, 15-second CSS-round allowance, and
two-year maximum leave the default Tier-32 estimate uncapped; deployments MUST
calibrate those values to their slowest supported clients rather than use the
maximum as policy rejection.

Pressure stores derive the logarithmic velocity and outstanding tiers with an
exact integer threshold walk (`1, 2, 4, ...`) capped at Tier 32. They MUST NOT
use floating-point logarithms, so power-of-two boundaries produce identical
tiers in Rust, TypeScript, SQLite, PostgreSQL, and Redis Lua.

Observing pricing state, calculating the quote, and reserving its outstanding
work MUST be one atomic pressure-store operation. A split read followed by a
later reservation is non-conforming because concurrent issuers could all
receive the tier calculated before any of their reservations became visible.
If that atomic operation is unavailable, challenge issuance returns the
retryable `pricing_unavailable` operational error and emits no token.

Each successful or expired-proof outcome carries the signed challenge expiry
back to the pressure store. The store MUST remove exactly one outstanding entry
with that expiry, not the oldest entry. Quotes for one action may have different
lifetimes as pressure changes; removing a different row would retain the wrong
lifetime and corrupt a later outstanding tier. Equal-expiry quotes are
interchangeable, but only one row/member is removed. Invalid and replayed proofs
change failure debt without removing an otherwise unexpired quote.

The language-neutral pricing cases and expected JSON quotes are frozen in
[`protocol/work-price-vectors.json`](../protocol/work-price-vectors.json); the
Rust and TypeScript test suites consume that same fixture.

The RSW input is derived by hashing the challenge nonce plus a big-endian
counter, reducing modulo the advertised modulus, and selecting the first value
greater than one whose public GCD with the modulus is one. This guarantees that
trapdoor exponent reduction and sequential client squaring agree for every
issued challenge, not merely with overwhelming probability.

Before accepting current or overlapping RSW material, both cores perform the
same deterministic trapdoor-consistency test. Three public coprime bases are
sequentially squared beyond the modulus bit length and compared with protected
trapdoor exponent reduction. A structural or consistency failure prevents
startup, so a server cannot issue a quote with key material it already knows it
cannot honor. Reusing one modulus id with different modulus or trapdoor material
is also invalid. The language-neutral cases are frozen in
[`rsw-key-validation-vectors.json`](../protocol/rsw-key-validation-vectors.json).
This startup check detects corruption and deployment mistakes; it does not
replace protected key generation, storage, backup, or independent review of the
RSW construction.

## Envelope

Browser challenge tokens are `shr1_` followed by base64url without padding of a
canonical CBOR COSE_Sign1 structure. Protected headers contain algorithm
EdDSA (`1: -8`) and the rotation key id (`4: bstr`). Challenge claims bind:

1. protocol and policy versions;
2. tenant, site, action, deployment region, and origin/hostname;
3. issued-at and expiry times;
4. tier, exact time-lock iterations and exact rendering rounds;
5. challenge nonce, rendering seed, RSW modulus id;
6. optional host session-binding hash.

The COSE signature input is the canonical CBOR `Sig_structure` described by
RFC 9052. `GET /.well-known/shar/v1` publishes overlapping Ed25519 public keys
and active RSW modulus identifiers. Redemption selects the protected trapdoor
by the signed modulus identifier, so a rotation cannot invalidate unexpired
issued work.

Every JSON challenge response also carries a required `PresencePlan` and
`FallbackPlan`. Presence is either `none` or host-owned `host`; it never affects
proof validity. Fallback is either unavailable with an empty method list, or
available with 1–16 unique method identifiers. The standalone transports derive
availability from the privileged fallback secret, reject inconsistent startup
configuration, and accept completion only for an advertised method. These
plans are browser/host capability metadata outside the signed proof claims: a
client cannot use them to change the signed quote, and TLS plus trusted host
configuration protects their delivery.

Canonical CBOR decoding is bounded to 64 nested values and 4,096 total values
per decoded object. These limits are far above every v1 envelope but prevent a
bounded HTTP token from becoming a stack or item-exhaustion attack. Exceeding a
limit is an invalid token, never a pressure signal, and occurs before nonce,
pressure, or audit state mutation. Both implementations consume the shared
[`malformed-cbor-vectors.json`](../protocol/malformed-cbor-vectors.json)
corpus, including an 11,001-byte nesting case that fits inside the HTTP token
body budget after base64url encoding, plus an item-limit case.

Successful challenge redemption creates a separately signed, five-minute
verification token. `/v1/siteverify` requires a `secret` credential scoped to
the token's tenant and site, then atomically consumes the token and returns the
bindings and work receipt; it never returns a bot probability. The credential
is `shrs1_` plus a versioned tenant/site body and HMAC-SHA-256 tag derived from
the independent site-verification master. Authentication and all optional
binding checks happen before nonce consumption, so an unauthorized request
cannot invalidate a legitimate host's token. JSON, reCAPTCHA, and hCaptcha form
aliases use the same rule.

`/v1/fallback/complete` is a server-to-server completion path, not an easier
proof quote. When configured, the host authenticates with a separate 32-byte
bearer secret and submits the already-verified method, bindings, and a unique
assertion id. Shar atomically consumes the assertion id and returns a direct
bound fallback result. It does not fabricate a work receipt. Replays fail, and
the host can create a new assertion after performing another fallback. The
widget keeps its fallback control hidden unless the issued response advertises
at least one method, then emits the exact method list for host-owned UI.

The Rust crate and pure-TypeScript package expose matching public protocol
contracts for `WorkQuote`, `WorkReceipt`, `TimeLockPlan`, `TimeLockProof`,
`RenderingProofPlan`, `CanonicalCssTranscript`, `CssTranscriptCommitment`, `TriangleProgram`,
`RenderingBackend`, `RenderingProof`, `PresencePlan`, `TrustTokenPlan`, and
`FallbackPlan`. Their host integration boundaries likewise expose
`NonceStore`, `PressureStore`, `ConfigStore`, `SignalProvider`, and
`FallbackVerifier`. Rust provider methods are synchronous because the native
server dispatches them on bounded blocking workers; TypeScript providers return
promises for Fetch/WebCrypto runtimes. Both forms have the same policy role:
signals can only quote future work, while fallback verification produces a
separate bound completion and cannot override proof validation.

The two cores actively wire these contracts into issuance and fallback
completion. A configured signal provider's 0–32 tier is combined with existing
trusted assurance using `max`, so it cannot lower a quote. Failure or invalid
output produces retryable `pricing_unavailable` before pressure reservation;
the provider is never consulted during redemption or site verification. A
configured fallback verifier runs before atomic assertion consumption. A false
result produces `fallback_not_verified` with `next_action: fallback`, while an
operational failure produces retryable `fallback_unavailable`; neither consumes
the assertion id. Provider health probes participate in readiness, and verifier
lookups must be idempotent because a storage failure after a successful lookup
can require a retry. The merge, error, state-mutation, and nonce behavior is
shared in
[`host-provider-vectors.json`](../protocol/host-provider-vectors.json).

Both cores also ship a matching `StoredFallbackVerifier` reference boundary.
It reads an idempotent host-owned `fallback-assertion-v1` record, permits at
most five minutes between verification and expiry, and requires exact method,
assertion-id, tenant, site, action, origin, region, and session bindings before
Shar consumes its replay nonce. Missing or mismatched records reject without
consumption; malformed store data or clock failure is retryable operational
unavailability. Direct core calls reject `fallback_not_configured` when the
advertised plan is unavailable, rather than relying solely on an HTTP bearer
guard. The integration sequence and both language examples are documented in
[`fallback.md`](fallback.md).

The reference standalones expose assurance only through the opt-in trusted
proxy boundary. Browser-body `assurance_tier` values are always discarded.
`SHAR_ASSURANCE_MODE=trusted-header` accepts a canonical 0–32
`X-Shar-Assurance-Tier` only from an immediate peer covered by
`SHAR_TRUSTED_PROXY_CIDRS`; the mode refuses to start without that boundary.
Raw behavioral fields remain upstream and are neither part of the protocol nor
stored by Shar. The numeric contribution prices the new quote and, when paired
with an opaque trusted session binding, its decaying future pressure. It is not
read during redemption or final verification, so later signal changes cannot
invalidate signed work.

## Browser compatibility adapters

`@shar/widget` exports reCAPTCHA- and hCaptcha-shaped adapters for migrations
that use the common programmatic browser APIs. Both expose `ready`, `render`,
`execute`, `reset`, `getResponse`, and `remove`. Rendered integrations preserve
the `callback`, `expired-callback`, and `error-callback` hooks and submit through
the conventional `g-recaptcha-response` or `h-captcha-response` field name.
The string-site-key `execute(sitekey, { action })` form supports the common
invisible/v3-shaped flow.

Global installation is opt-in and refuses to overwrite an existing
`grecaptcha` or `hcaptcha` object. The adapters inject no scripts, frames, or
stylesheets and do not emulate provider risk scores in the browser. Every path
delegates to the same `Shar.execute` or `<shar-challenge>` state machine, so the
signed rendering rounds, sequential work, expiry, and atomic replay rules are
unchanged.

After successful redemption the form-associated widget tracks the signed
verification-token expiry reported by the server. Expiry remains inclusive at
the protocol second; the browser clears its response immediately after that
second ends, removes the value from `FormData`, updates its live status, and
emits exactly one `expired` event. `getResponse()` checks the deadline
synchronously as well as through a timer, so background timer throttling cannot
expose a stale response. Reset, re-execution, and disconnection cancel pending
timers, while reconnection reschedules the same absolute deadline. Compatibility
adapter expiration callbacks use this same event path.

## Rendering (`render-v1`)

A challenge contains data, not executable source. The canonical reference
program first derives a `css-transcript-v1` from its 32-byte seed. The
transcript is encoded as fifteen unsigned 32-bit big-endian words in this
order: chain width, layout height, first and second grid widths, first and
second flex widths, intrinsic width, size-query branch, style-query branch, nested-query branch,
transform X and Y, vertical-writing branch, hit-test winner, and topology
depth. For seed bytes `s[0..10]`, the values are:

```text
chain_width       = 64 + s[0] mod 64
layout_height     = 48 + s[1] mod 48
grid_first        = 16 + s[2] mod 32
grid_second       = chain_width - grid_first
flex_first        = 4 + s[3] mod (grid_first - 8)
flex_second       = grid_first - flex_first
intrinsic_width    = 8 + s[11] mod 24
query_branch      = 12 + s[4] mod 32
style_branch      = 12 + s[5] mod 32
nested_branch     = 1
transform_x       = 4 + s[6] mod 24
transform_y       = 4 + s[7] mod 24
vertical_writing  = s[8] & 1
hit_id            = 1 + (s[9] & 1)
topology_depth    = 3 + s[10] mod 6
```

`program_root = SHA-256("shar/render-v1/css-program\0" || seed ||
transcript_words)`. Independently seeded rounds derive bounded integer
triangles and sample points from that root. For each sample the program selects
the highest covering triangle using signed integer edge predicates and reduces
triangle id, sample id, and coverage through SHA-256. Round digests are reduced
once more. The normative cross-language cases, including transcript words,
rendering digests, and commitment digests, are in
`protocol/render-v1-vectors.json`.

The CSS executor constructs a challenge-selected dependency topology under a
closed, inert shadow root using one static stylesheet. Before executing triangle
rounds it measures integer-quantized cascade/`calc()`/`min()`/`max()`/`clamp()`
results, nested size and style queries, grid/flex dimensions, transforms,
writing mode, and clipped stacking/hit testing. A mismatch makes that executor
unavailable; it never obtains easier work. The widget commits the transcript as
`SHA-256("shar/css-transcript-v1\0" || seed || rounds || triangles || samples
|| transcript_words)` when CSS completes. Both servers independently derive
and verify any supplied commitment. This is execution conformance, not browser
attestation: an independent client may implement the public integer algorithm.

All executors MUST implement that same program:

- WebGPU with static WGSL and integer storage buffers;
- WebGL2 with a static integer-compatible fragment pipeline;
- contained CSS triangle elements with deterministic sample hit testing.

The chosen backend and elapsed time are receipt metadata, not validity inputs.
The normative bounds are 512 triangles, 4,096 samples, 16 MiB working memory,
and 65,536 independently seeded rounds per challenge. Each round retains the
same resource cap; implementations checkpoint only between rounds and may
switch executor after loss without changing the quote.

The browser widget also keeps a best-effort navigation checkpoint in
same-tab `sessionStorage`. It is scoped to the normalized challenge endpoint,
tenant, site key, action, and origin and contains only the already-issued signed
challenge, the current sequential-squaring value and iteration count, and the
contiguous list of completed round digests and last rendering backend. A
per-execution owner prevents cancelled asynchronous work from overwriting or
deleting a successor's checkpoint. The record is capped at 4 MiB, is cleared on
successful redemption or explicit reset, and is rejected and removed when its
shape, canonical encodings, scope, or expiry is invalid. Storage denial or
quota exhaustion only causes recomputation. On the next `execute()` call the
widget resumes the exact signed quote; it never requests reduced work.

Sequential squaring always has a pure-JavaScript `BigInt` implementation. The
widget additionally offers an explicit, optional Rust/WASM accelerator that
processes at most 65,536 iterations per call and 512 bytes per integer. It
receives only the signed modulus, current value, and bounded iteration count;
it cannot alter the quote or verification rule. Every accelerated chunk has a
saved pre-chunk value. If fetching, compiling, allocating, or executing WASM
fails, the widget restores that value and repeats the exact chunk in JavaScript.
The accelerator therefore changes only local execution speed: proof bytes,
progress, checkpoints, pause/resume behavior, and all server inputs remain
canonical. It is absent from the default cold path and from the independent
pure-TypeScript server dependency closure.

Rendered widgets own independent in-memory pause, resume, cancellation, and
reset controls, so concurrent forms cannot cancel one another. The bounded
privacy design retains only one same-tab navigation record: concurrent solvers
remain correct, while the most recently persisted owner is the one that can
resume after navigation. A scoped reset cannot remove another action's record.
Global `Shar` controls apply only to the most recently started execution.

The reference element exposes native buttons and progress semantics, an atomic
polite status region, and an `aria-busy` solving state. Keyboard focus remains
visible, interactive targets are at least 44 CSS pixels, and the controls
reflow without horizontal page overflow at a 320 CSS-pixel viewport (the
400%-zoom equivalent used by the browser harness). A static constructed shadow
stylesheet honors reduced motion and forced colors under strict CSP; documented
`::part` names let hosts restyle controls without generated or inline CSS. The
contained rendering subtree remains absent from the accessibility tree.

When a challenge includes `trust-voprf-v1`, the reference widget also performs
the blinded-credit lifecycle described in `docs/trust-credits.md`. The blind is
fresh per completed challenge and covers a client-generated secret nonce; both
remain in memory only until the issuer evaluation has been verified and
finalized. The issuer never supplies or observes the unblinded token input. The
root issuer secret derives a distinct child VOPRF key for the complete scope,
so hidden input cannot be evaluated in one scope and spent in another. The
resulting single-use token is
held in a separate bounded same-tab wallet, scoped to endpoint, tenant, site,
action, and origin. Explicit credit rejection causes one issuance retry without
the credit; transport or pricing failure retains it. Trust-path failure never
changes proof validity, work acceptance, or the returned verification token.

This checkpoint is an availability optimization, not proof state trusted by
the verifier. Modified intermediate values or round digests still fail the
canonical server proof check. It creates no cookie, persistent identifier, or
cross-tab state and sends no additional request. Hosts should treat same-origin
script access to the issued challenge exactly as they treat any in-flight
widget token.

The protocol default is 256 triangles and 4,096 samples: 1,048,576 exact
point-in-triangle predicates per round, while retaining the same fixed memory
and DOM caps. JavaScript evaluates the reference edge predicate with `Number`:
guarded 20-bit coordinate differences make each product smaller than 2^40 and
each difference smaller than 2^41, so all arithmetic is exact within the
53-bit integer range. The language-neutral rendering vectors protect this
optimization against a digest change.

The executable browser prototype produces the same digest through WebGPU,
WebGL2, computed CSS plus hit testing, and the CPU reference in Chromium with
forced SwiftShader, verified Mesa llvmpipe/ANGLE OpenGL, and a physical Intel
Iris Xe/Mesa Vulkan device. The llvmpipe calibration explicitly disables
WebGPU, preventing the software-WebGL result from being mixed with a physical
Vulkan adapter. A shared Playwright matrix also requires CPU/CSS identity,
adaptive fallback, strict CSP, widget contracts, and admin interactions in
Chromium, Firefox, and WebKit; any accelerated backend exposed by an engine
must match the same digest.
An opt-in physical Chromium project additionally destroys a live WebGPU device
and invokes `WEBGL_lose_context` during the next round, then requires CSS to
finish the unchanged plan while retaining every completed round digest.
It retains completed rounds while falling back from WebGL2 to CSS. The matrix
also pauses after one CSS round, navigates, resumes the same signed challenge
without a second issuance request, redeems it, and verifies completion cleanup;
separate cases reject expired/corrupt records, exercise explicit reset, and
protect successor state from stale execution owners. Freezing the geometry
still requires the full physical GPU, mobile, software-renderer, and
shipping-browser matrix.

## Privacy and transport

Privacy mode stores no raw IP, cookie, stable device/GPU identifier, or
third-party request. A tenant/site-scoped daily HMAC network pseudonym may
contribute at most four network tiers and cannot be correlated between site
keys through the token. Proxy forwarding headers are ignored unless the
immediate peer belongs to an explicitly configured proxy CIDR.

Browser-origin allowlists contain unique canonical URL origins. HTTPS is
required except for localhost and IP loopback development origins; wildcard,
credentials, path, query, fragment, whitespace, duplicate, empty, and
non-canonical default-port forms are invalid configuration. Both standalone
servers and the pure Fetch handler consume the behavior frozen in
[`allowed-origin-vectors.json`](../protocol/allowed-origin-vectors.json).

Operational overload is distinct from proof failure: use HTTP 429/503 with a
stable retryable error. No overload response may be recorded as bot suspicion.
The reference servers use HTTP 503 `capacity_unavailable` with
`next_action: "retry"`, a bounded `Retry-After`, and CORS on allowed browser
origins. Capacity admission is based only on an aggregate in-flight count; it
does not inspect or mutate pressure, identity, assurance, backend, or proof
state. Liveness, readiness, and metrics remain available while the
protocol/admin gate is saturated.

Request-body intake has a bounded transport deadline. An incomplete body
returns HTTP 408 `request_body_timeout`, `retryable: true`, and
`next_action: "retry"`, without entering pricing or consuming a nonce. This is
strictly an HTTP intake deadline: solving happens before the request, and once
a complete proof reaches verification no correctness timeout is imposed.

## Operational endpoints

`GET /healthz` is a no-store process-liveness probe and returns
`{"status":"ok"}` without consulting durable state. `GET /readyz` is a
no-store traffic-admission probe: it performs read-only checks against every
configuration, pressure, and nonce dependency required to issue and redeem
work, plus any configured signal or fallback provider health probe. An
unavailable dependency returns HTTP 503 with
`readiness_unavailable`, `retryable: true`, `next_action: "retry"`, and a
bounded retry hint. Audit state MUST NOT affect readiness because audit writes
are best-effort. `GET /metrics` exposes only unlabeled aggregate success
counters; it MUST NOT introduce tenant, request, network, browser, or device
labels.

Every dynamic response, including successful token-bearing responses and early
transport errors, carries `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff`. Errors on challenge and redemption routes
retain CORS for an allowed exact origin even when body collection fails before
protocol parsing. Static admin assets keep their explicit immutable/no-cache
policy instead of receiving the dynamic default. Both servers canonicalize the
configured asset root at startup and refuse to serve any final canonical path
outside it, including paths reached through in-tree symlinks.

Responses carry a fresh `X-Shar-Request-Id`. Optional structured completion
observations use `request-observation-v1` and contain exactly the request id,
normalized method, normalized route, HTTP status, and non-negative integer
duration in milliseconds. Implementations replace unknown paths with
`unmatched`, collapse dashboard paths to `/admin/*`, and never record query
strings, protocol bodies, origins, tenant/site/action bindings, client
addresses, headers, user agents, or device properties. Observation failure is
best-effort and MUST NOT alter traffic admission or proof validity.
