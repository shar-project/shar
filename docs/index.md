# Shar documentation

Choose the path that matches what you are trying to do. You do not need to read
the protocol specification or release evidence to run a local evaluation.

## Start here

- [Quickstart](quickstart.md) — build from source, run either standalone, add a
  widget to a form, and verify the result from a backend.
- [Architecture](architecture.md) — the five-step request flow, trust boundaries,
  state ownership, and relationship between the Rust and TypeScript servers.
- [Project README](../README.md) — short product overview and current status.

## Integrate Shar

- [Widget guide](../packages/widget/README.md) — `<shar-challenge>`, `Shar.execute`,
  events, localization, accessibility, checkpoints, and optional WASM.
- [Pure-TypeScript server](../packages/server/README.md) — Fetch handler and host
  provider contracts for JavaScript runtimes.
- [Cap compatibility](../packages/cap-compat/README.md) — migrate a `<cap-widget>`
  integration while keeping familiar attributes and events.
- [Host fallback](fallback.md) — passkey, email, authenticated-session, and support
  flows without turning fallback into a proof bypass.
- [Blinded trust credits](trust-credits.md) — optional first-party unlinkable
  credits that can reduce future debt.

## Deploy and operate

- [Operations](operations.md) — key generation and rotation, all standalone
  settings, proxies, state adapters, observability, shutdown, backup, and failure
  testing.
- [Kubernetes scaffold](../deploy/kubernetes/README.md) — two replicas with
  external PostgreSQL/Redis state and distinct probes.
- [Observability](../deploy/observability/README.md) — Prometheus rules, Grafana,
  Loki, and the privacy-safe observation collector.
- [Security policy](../SECURITY.md) — supported versions and private reporting.

## Understand or review the protocol

- [Protocol v1](protocol.md) — normative invariants, pricing, envelopes,
  rendering, compatibility, privacy, and endpoint behavior.
- [Threat model](threat-model.md) — security goals, attacker capabilities, and
  explicit non-goals.
- [`protocol/`](../protocol/) — language-neutral schemas and deterministic vectors
  consumed by both implementations.

## Contribute and release

- [Contributor guide](contributing.md) — repository layout and the appropriate
  local test commands for each kind of change.
- [Release gates](roadmap.md) — concise, authoritative list of incomplete GA work.
- [Release evidence](release-status.md) — detailed completed-test ledger and
  caveats for maintainers and reviewers.
- [Release procedure](../RELEASING.md) — protected-tag publication workflow.

## Documentation conventions

User-facing guides describe only behavior implemented by both servers. Protocol
requirements use **must**; recommendations use **should**. Long test transcripts
and hardware evidence belong in the release ledger rather than the quickstart or
integration guides.
