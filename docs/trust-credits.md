# Blinded trust credits

Shar's trust credit is an optional first-party optimization. It is never
required for a valid proof and it never changes whether an issued quote is
accepted. A deployment may omit the issuer entirely and the protocol remains
fully functional.

## Cryptographic profile

The current interoperable primitive is the verifiable VOPRF transcript from
[RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html), using the
`ristretto255-SHA512` ciphersuite. The issuance envelope is versioned as
`trust-voprf-v1`; the implementation deliberately keeps the primitive behind
the server's transport and storage interfaces so a separately reviewed
RFC 9578 deployment profile can be added without changing challenge or proof
semantics. The shared fixture in
[`protocol/trust-voprf-vectors.json`](../protocol/trust-voprf-vectors.json)
is checked by both Rust and pure TypeScript.

Issuer keys are derived from a 32-byte deployment seed and an opaque 1–32-byte
key id. The current public key and any overlapping previous keys are published
in `GET /.well-known/shar/v1` under `trust`. Private seeds stay in the key
file or environment and are never sent to a browser. Each root key derives a
cryptographically distinct VOPRF child key for the complete
tenant/site/action/origin scope. The challenge plan carries that child public
key while retaining the root key id for rotation. Redemption and spending
independently derive the same child key, so a blind evaluated after completing
work for one scope cannot be wrapped into a valid credit for another scope.

## Issuance and redemption

1. A challenge response includes a scoped `trust` plan when an issuer is
   configured. The plan contains the ciphersuite, scoped public key, root key
   id, bounded
   lifetime, and a digest of that public lifetime/scope metadata. It does not
   contain a token nonce or VOPRF input chosen by the issuer.
2. The browser creates a fresh secret 32-byte token nonce, combines it with the
   plan digest, key id, and full scope to form the domain-separated input, then
   sends only the blinded point with the normal work proof to
   `/v1/challenges/redeem`.
3. The server verifies the ordinary time-lock and rendering proof, evaluates
   the blinded point, and returns `trust-evaluation-v1` with the evaluated
   point and proof. It does not learn the unblinded credit value.
4. The browser verifies the VOPRF proof, unblinds the output, and creates a
   `shrtrust1_` canonical-CBOR token. The token binds tenant, site, action,
   origin, key id, client nonce, public metadata digest, issue time, expiry,
   and the 64-byte VOPRF output. The issuer saw neither the nonce nor input
   during issuance, so it cannot match the later token to a blinded transcript
   from protocol values alone.
5. The next challenge may present that token as `trust_token`. The server
   checks the scoped VOPRF output and atomically consumes a stable hash of the
   key id and finalized output in the `trust` nonce namespace. A replay, bad
   binding, unknown key, or
   expired token gets a retryable-new-challenge instruction; it does not ban
   the client.

The reference widget implements this complete lifecycle. It keeps at most one
credit for each exact normalized endpoint/tenant/site/action/origin scope in a
bounded same-tab `sessionStorage` wallet (16 scopes maximum). It never uses a
cookie, `localStorage`, cross-tab state, or device-derived input. In-memory
claims prevent concurrent executions in one page from offering the same local
credit. A successful challenge response removes the offered token; an
operational failure releases it for later use. If the server explicitly rejects
a stale, replayed, invalid, wrong-scope, or unknown-key credit, the widget
discards it and retries the challenge once without trust so the optional
optimization cannot prevent a finite quote.

The widget validates canonical encodings and reconstructs the public
scope/lifetime digest before blinding, verifies the returned DLEQ proof during
finalization, and validates the evaluation key, suite, and exact planned
lifetime before encoding a credit. Any
plan, randomness, finalization, quota, or storage failure is isolated from the
ordinary proof: correctly completed work still yields and returns its
verification token.

The default lifetime window is 24 hours (configurable from 60 seconds through
30 days). Public issue times are rounded down into a bucket no larger than one
hour and no larger than 1/24 of the configured lifetime. Credits issued for the
same key and scope in that window therefore share public metadata instead of
carrying a per-challenge timestamp tag, while a conforming client retains at
least 23/24 of the configured validity. The lifetime and scope digest are part
of the VOPRF input, so a holder cannot extend an unspent token by rewrapping its
clear CBOR fields. A token is single-use, and replay identity does not depend on
its serialization. Trust consumption can reduce future failure or
assurance debt, but it never reduces current action velocity, outstanding work,
or network pressure. Pressure bookkeeping is best effort after the durable
one-shot boundary, so a store hiccup cannot destroy a valid credit.

## Configuration

Key generation emits `SHAR_TRUST_SEED` and `SHAR_TRUST_KEY_ID`. During rotation,
the tools prepend the old pair to `SHAR_PREVIOUS_TRUST_KEYS`, an array of
`{ "seed": "base64url", "key_id": "base64url" }` objects. Set
`SHAR_TRUST_RETENTION_SECONDS` to select a value inside the documented bounds.
Leaving both current trust variables unset disables the optional feature; a
partial pair is rejected at startup.

Trust tokens are not cookies, browser identifiers, or a bot score. Operators
should describe the disclosed scope and retention in their privacy notice and
should not use a successfully redeemed credit as a reason to reject a proof.
