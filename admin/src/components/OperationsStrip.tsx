import type { LiveStatus } from "../types";

const metrics = [
  ["Challenges issued", "shar_challenges_issued_total"],
  ["Proofs redeemed", "shar_challenges_redeemed_total"],
  ["Site verifications", "shar_site_verifications_total"],
  ["Fallback completions", "shar_fallback_completions_total"],
] as const;
export function OperationsStrip({
  status,
  connected,
}: {
  status: LiveStatus | null;
  connected: boolean;
}) {
  return (
    <footer className="operations-strip">
      {metrics.map(([label, key]) => (
        <div className="metric" key={key}>
          <span>{label}</span>
          <strong>
            {status?.metrics[key] !== undefined
              ? new Intl.NumberFormat().format(status.metrics[key])
              : "—"}
          </strong>
          <small>
            {status?.metrics[key] !== undefined
              ? "Since process start"
              : "Awaiting live metrics"}
          </small>
        </div>
      ))}
      <div className="metric">
        <span>Storage status</span>
        <strong className={connected ? "healthy" : ""}>
          {connected ? "Connected" : "Not connected"}
        </strong>
        <small>Policy store</small>
      </div>
      <div className="metric">
        <span>Key rotation status</span>
        <strong className={status?.keyCount ? "healthy" : ""}>
          {status?.keyCount
            ? `${status.keyCount} signing key${status.keyCount === 1 ? "" : "s"}`
            : "Not connected"}
        </strong>
        <small>
          {status?.modulusCount
            ? `${status.modulusCount} time-lock key${status.modulusCount === 1 ? "" : "s"}`
            : "Discovery unavailable"}
        </small>
      </div>
    </footer>
  );
}
