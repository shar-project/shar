# Cap comparison harness

This harness pins Cap `standalone@3.1.8` and `widget@0.1.56` to exact Git
commits and npm integrity values. It never compares against `latest` and never
turns unlike work units into a fabricated cost ratio.

The comparand behavior is defined by Cap's
[`standalone@3.1.8` release](https://github.com/tiagozip/cap/releases/tag/standalone%403.1.8),
[`widget@0.1.56` release](https://github.com/tiagozip/cap/releases/tag/widget%400.1.56),
[challenge architecture](https://trycap.dev/guide/workings), and
[instrumentation documentation](https://trycap.dev/guide/instrumentation).

Prepare third-party inputs outside the tracked tree, then measure the current
Shar browser artifact graph:

```sh
npm run bench:cap:prepare
npm run bench:cap:bytes
npm run bench:cap:browser-bytes
```

`prepare` clones and extracts into ignored `.bench/cap`. It refuses a tag whose
commit differs from `manifest.json` or an npm tarball whose integrity differs
from the recorded registry value. Add `-- --install-core` when running the
machine-local CPU reference benchmark.

The artifact measurement counts Cap's published `cap.min.js` and the separate
WASM binary that version 0.1.56 eagerly fetches. Shar is bundled from its public
widget entry with production tree shaking. Raw, gzip, and Brotli sizes and
SHA-256 digests are retained. The 80% gate is reported as artifact evidence,
not promoted to the GA browser-network gate until a cold-cache network capture
confirms the same request graph.

`browser-bytes` performs that capture in a new Chromium context for each
product. A loopback server sends Brotli-compressed assets with `no-store`; the
harness waits for Resource Timing entries, counts encoded response bodies and
transfer sizes, verifies Cap actually fetched its WASM, and fails on unexpected
requests. This is Chromium evidence only, not a substitute for the remaining
browser/device matrix.

The live harness requires explicit endpoints and settings because Cap's
instrumentation, headless blocking, RSW, rate limit, Redis, and site-key policy
are server configuration—not properties that can be inferred from a response.
It records those settings alongside every result. Browser energy measurements
must come from the required reference devices; CPU time is not relabeled as
energy. Set `SHAR_BENCH_PID` and `CAP_BENCH_PID` to the corresponding server
process IDs to sample Linux `/proc` `VmRSS` during the issuance load; each
issuance result then includes baseline, peak, final, and sample-count fields.
Without those PIDs the throughput result remains valid but its memory gate is
marked partial. The RSS sample is reference-process evidence, not a stabilized
container limit or a substitute for the isolated multi-host benchmark. Each
issuance result also records decoded response-body byte distributions so
protocol-size differences remain visible when interpreting HTTP throughput.
The load generator uses the same explicit HTTP/1.1 keep-alive agent for both
products, with the socket limit fixed to the declared concurrency. This avoids
runtime-global connection-pool defaults becoming an unrecorded comparand. The
latency distribution is time from request start through response headers;
whole-operation throughput also includes reading and parsing each body.

## Local standalone comparison

`bench:cap:standalone-local.mjs` starts a fresh pinned Cap process and a fresh
Shar process for every run, alternates optimized Rust and production
JavaScript order, stabilizes process RSS, and retains every raw live result.
Cap requires an external Redis-compatible service. After preparing the pinned
source and installing its locked standalone dependencies, run:

```sh
CAP_BENCH_REDIS_URL=redis://127.0.0.1:6379 \
SHAR_BENCH_SHAR_STATE=sqlite \
npm run bench:cap:standalones
```

`SHAR_BENCH_SHAR_STATE=sqlite` measures Shar's default single-host SQLite WAL
profile while Cap continues to use its required Redis service. Set it to
`redis` to put Cap and Shar's atomic pressure/nonce state on the same external
service. The defaults are three repetitions, 1,000 issuance operations, total
concurrency 32 through one load-generator worker, and one action scope.
`SHAR_BENCH_CLIENT_WORKERS` can be set from 1 through 16 without changing total
concurrency; the worker count is always recorded so unlike client capacities
cannot be compared silently. Use multiple workers on a separate load-generator
host when one event loop cannot saturate the target servers; extra workers on
the server host can instead introduce CPU contention.
`SHAR_BENCH_ACTION_CARDINALITY=1000` selects the deliberately different
high-cardinality abuse profile; the chosen cardinality is always recorded.
`CAP_BENCH_PROTOCOL=rsw` switches the pinned Cap site from its default SHA-PoW
issuance path to its 2048-bit RSW path at the pinned release's default 75,000
iterations. The complete Cap settings object is recorded in every result;
RSW results default to `results/rsw/` while SHA results retain the historical
`results/` path, preventing one mode from overwriting the other. Publish and
evaluate the modes separately rather than comparing unlike workloads.

The summary in `results/local-standalone-comparison.json` reports min, median,
max, and relative standard deviation. Native throughput must be at least 2x
Cap and native idle RSS at most half Cap in **every** run; a favorable median
cannot hide a failing repetition. Relative standard deviation above 0.20 is
explicitly flagged as host noise and requires more repetitions or a more
isolated machine. These results remain `local_reference_only`: they exclude
Redis memory, container-runtime overhead, managed-store latency, browser solve
energy, and the required multi-host deployment matrix.

## Cap behavior matrix

The throughput profile defaults to the historical SHA setting and can run the
protocol-matched RSW issuance mode separately. This isolates server issuance;
it does not claim equal client work or attacker economics, which require the
separate calibrated device/economics harness. The behavior matrix exercises the
remaining pinned standalone semantics:

```sh
CAP_BENCH_REDIS_URL=redis://127.0.0.1:6379 \
npm run bench:cap:behavior
```

It creates isolated site keys and proves SHA and RSW redemption plus single-use
site verification, instrumentation rejection when its response is missing,
non-browser user-agent rejection, configured rate limiting, invalid-proof
failure, and subsequent replacement challenge issuance. The retained result is
`results/local-cap-behavior-matrix.json`. These are Cap comparison facts, not
features Shar should copy: Shar's assurance and automation signals only change
future finite prices and never reject a correct issued proof.

## Energy and attacker economics

`calibration.schema.json` defines the evidence accepted by the economic gate.
It requires at least 30 samples, named devices/hardware, a methodology URL,
measured p95 latency and joules, attacker cost per accepted request, and
sustained-abuse tier costs. Equal-benign-cost inputs must be within 5% of the
declared energy target. Evaluate a completed calibration with:

```sh
SHAR_BENCH_CALIBRATION=/absolute/path/to/calibration.json \
  npm run bench:cap:economics
```

There are deliberately no sample numbers or synthetic defaults. The evaluator
exits 2 when any of the 20%-latency, 20%-energy, 2x-attacker-cost, or negative
sustained-economics gates fails.
