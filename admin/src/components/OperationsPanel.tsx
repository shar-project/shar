import type { LiveStatus } from "../types";

const metrics = [
  ["Challenges issued", "shar_challenges_issued_total"],
  ["Proofs redeemed", "shar_challenges_redeemed_total"],
  ["Site verifications", "shar_site_verifications_total"],
  ["Fallback completions", "shar_fallback_completions_total"],
] as const;

const number = new Intl.NumberFormat();

export function OperationsPanel({
  status,
  busy,
  onRefresh,
}: {
  status: LiveStatus | null;
  busy: boolean;
  onRefresh: () => void;
}) {
  return (
    <>
      <header className="page-header">
        <h1>Operations</h1>
        <p>Privacy-safe runtime signals for this self-hosted instance.</p>
      </header>
      <section className="operations-toolbar" aria-label="Operations controls">
        <p>
          Counters contain no tenant, site, action, network, device, or user
          labels. Values reset when the process restarts.
        </p>
        <button
          className="button secondary"
          type="button"
          onClick={onRefresh}
          disabled={busy}
        >
          {busy ? "Refreshing…" : "Refresh status"}
        </button>
      </section>
      <section className="operations-grid" aria-label="Runtime counters">
        {metrics.map(([label, key]) => (
          <article className="operation-card" key={key}>
            <span>{label}</span>
            <strong>
              {status?.metrics[key] === undefined
                ? "—"
                : number.format(status.metrics[key])}
            </strong>
            <small>Since process start</small>
          </article>
        ))}
      </section>
      <section
        className="operations-status"
        aria-labelledby="runtime-status-title"
      >
        <h2 id="runtime-status-title">Runtime status</h2>
        <dl>
          <div>
            <dt>Health endpoint</dt>
            <dd className={status?.healthy ? "healthy" : "error-text"}>
              {status?.healthy ? "Healthy" : "Unavailable"}
            </dd>
          </div>
          <div>
            <dt>Signing keys</dt>
            <dd>{status?.keyCount ?? "Unavailable"}</dd>
          </div>
          <div>
            <dt>Time-lock keys</dt>
            <dd>{status?.modulusCount ?? "Unavailable"}</dd>
          </div>
        </dl>
      </section>
    </>
  );
}
