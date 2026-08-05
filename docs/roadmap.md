# Release gates

The following are deliberately not represented as complete:

- freeze `render-v1` after byte-identical WebGPU, WebGL2, and real CSS-engine
  trials on the remaining physical GPU and mobile matrix; retained local
  and remote evidence now covers Intel Iris Xe, AMD Van Gogh, Arm Mali-G710,
  SwiftShader, Mesa llvmpipe, and a GPU-disabled browser without treating
  software fallback as hardware;
- independent review of production 2048-bit key generation and verification;
- replicated-service failover, TLS, and broader multi-host validation of the
  dual PostgreSQL and Redis-compatible atomic adapters; deterministic complete
  connection blackholes and recovery now run against both real standalones in
  CI, but do not substitute for the target managed services and proxies;
- an independently reviewed RFC 9578 deployment profile for the currently
  implemented RFC 9497/Ristretto255 blinded trust-credit primitive, plus the
  production assurance-retention review;
- professional translation review, broader locale coverage, production host
  implementations of advertised fallback methods, and broader Cap/browser
  compatibility coverage;
- execute and verify the protected-tag release workflow, which now automates
  multi-architecture Rust/JavaScript containers, npm provenance, SBOMs,
  signatures, and attestations; deploy the implemented namespace-scoped
  observation collector and Prometheus/Loki dashboard against target storage,
  verify retention and access controls, and independently audit the shipped
  policy editor and deployment examples;
- complete the pinned Cap `standalone@3.1.8` / `widget@0.1.56` benchmark matrix:
  the local standalone harness and raw native/JavaScript throughput/idle-memory
  evidence now exist. The protocol-matched local RSW runs pass the native 2x
  threshold, while the historical unlike SHA/RSW comparison does not; reproduce
  the matched result under isolated deployment conditions before accepting the
  gate.
  Reference-device latency/energy, GPU/CSS speedup, sustained-abuse economics,
  and the remaining device/browser matrix also remain. Artifact, Chromium
  cold-path byte, three-engine desktop keyboard/reflow/reduced-motion/
  forced-colors automation, and pinned
  SHA/RSW/instrumentation/UA/rate-limit/siteverify behavior evidence now exists;
- adversarial, privacy, WCAG 2.2 AA, EN 301 549, and cryptographic reviews.

GA requires every quantitative and audit threshold in the project plan to be
measured and published. Passing the conformance tests alone is not GA.
