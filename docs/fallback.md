# Host fallback integration

Shar never presents image, audio, knowledge, or cognitive puzzles. A host can
instead offer passkey, email, authenticated-session, support, or another
first-party method. The host verifies that method; Shar only completes a
separate, bound fallback result. Fallback never fabricates proof-of-work or a
work receipt.

## Trust boundary

The browser receives only the advertised method names. It never receives the
`SHAR_FALLBACK_SECRET`, writes a successful assertion, or calls the privileged
completion endpoint. A host backend performs these steps:

1. Verify the selected method using its ordinary relying-party, email,
   authenticated-session, or support controls. Require CSRF protection and a
   recent reauthentication where appropriate.
2. Generate an unpredictable assertion id containing at least 128 bits of
   randomness.
3. Insert a `fallback-assertion-v1` record bound to the exact tenant, site key,
   action, canonical origin, optional region, method, assertion id, and optional
   session-binding hash. Set `verified_at` to the current Unix second and
   `expires_at` no later than five minutes afterward.
4. Submit those same bindings to Shar's `/v1/fallback/complete` endpoint using
   `Authorization: Bearer BASE64URL_SHAR_FALLBACK_SECRET` from the backend.
5. Accept only the direct response whose bindings equal the submitted values.
   Never convert it into a proof token or work receipt.

The assertion lookup must be idempotent and must not delete or mark the record
used. Shar performs atomic replay consumption after verification; if that write
fails, the same host lookup must be safe to retry. The host may delete expired
records asynchronously after Shar's five-minute replay window.

The language-neutral record schema is
[`fallback-assertion.schema.json`](../protocol/fallback-assertion.schema.json).
Both server cores consume the same boundary and lifetime vectors from
[`fallback-assertion-vectors.json`](../protocol/fallback-assertion-vectors.json).

## TypeScript

`StoredFallbackVerifier` uses only standard JavaScript and the injected store
and clock, so it works in Node, Bun, Deno, Workers, and other Fetch/WebCrypto
environments:

```ts
import {
  SharService,
  StoredFallbackVerifier,
  type FallbackAssertionStore,
} from "@shar/server";

const assertions: FallbackAssertionStore = {
  async health() {
    await database.assertReadable();
  },
  async find(assertionId) {
    // Project exactly one immutable fallback-assertion-v1 record. Do not
    // consume it in this query.
    return database.findFallbackAssertion(assertionId);
  },
};

const service = new SharService({
  ...options,
  fallback: { available: true, methods: ["authenticated-session"] },
  fallbackVerifier: new StoredFallbackVerifier(assertions, {
    now: () => Math.floor(Date.now() / 1000),
  }),
});
```

## Rust

Rust exposes the matching `StoredFallbackAssertion`,
`FallbackAssertionStore`, and `StoredFallbackVerifier` contracts:

```rust
use shar_core::{
    FallbackAssertionStore, StoredFallbackAssertion, StoredFallbackVerifier,
    StoreError,
};
use std::sync::Arc;

struct Assertions(Database);

impl FallbackAssertionStore for Assertions {
    fn health(&self) -> Result<(), StoreError> {
        self.0.assert_readable()
    }

    fn find(
        &self,
        assertion_id: &str,
    ) -> Result<Option<StoredFallbackAssertion>, StoreError> {
        self.0.find_fallback_assertion(assertion_id)
    }
}

let verifier = Arc::new(StoredFallbackVerifier::new(Arc::new(
    Assertions(database),
)));
let engine = engine.with_fallback_verifier(verifier);
```

Missing, expired, future-dated, over-five-minute, or binding-mismatched records
return `fallback_not_verified` without consuming the assertion id. Store,
clock, or malformed-record failures return retryable `fallback_unavailable`.
When fallback is not advertised, both cores reject direct completion with
`fallback_not_configured`, including integrations that bypass the standalone
HTTP handler.
