# Native core profiling

`issue-profile` isolates Rust challenge construction, canonical CBOR, COSE
signing, optional trust-plan construction, and time-lock input derivation from
HTTP and durable-store latency. It also reports response serialization
throughput and top-level field sizes. It accepts a protected key file but
never prints its contents. The time-lock section reports the active binary-GCD
derivation beside an in-process Euclidean reference over the same nonces and
modulus, avoiding cross-run CPU/load comparisons. It also isolates COSE
signing over a representative challenge-sized payload:

```sh
cargo run -p shar-core --release --example issue-profile -- /path/to/keys.json
```

Use a temporary generated key and remove it after the run. This diagnostic is
not a server-throughput or GA benchmark. It is intended to catch core-path
regressions such as accidentally restoring a full-width modular reduction or
redundant Euclidean step in time-lock input derivation. Compare measurements
only on the same isolated host and treat them as diagnostic rates, not release
claims.

`redis-profile` similarly isolates the synchronous Rust atomic-pricing adapter
from HTTP and cryptographic work:

```sh
cargo run -p shar-server --release --example redis-profile -- \
  redis://127.0.0.1:6379 /path/to/keys.json
```

Use only a dedicated profiling database because it creates expiring pressure
and outstanding-work keys. With a protected key file, the diagnostic also
measures complete issuance through Redis pressure state, SQLite configuration,
trust-plan construction, signing, and JSON serialization. The key contents are
never printed.
