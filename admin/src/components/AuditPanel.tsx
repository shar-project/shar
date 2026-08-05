import type { AuditEvent } from "../types";

function time(value: number): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(value * 1000));
}

export function AuditPanel({
  scope,
  events,
  busy,
  onRefresh,
  onScopeChange,
  onLoadScope,
}: {
  events: AuditEvent[];
  busy: boolean;
  onRefresh: () => void;
  scope: { tenant: string; site_key: string; action: string };
  onScopeChange: (key: "tenant" | "site_key" | "action", value: string) => void;
  onLoadScope: () => void;
}) {
  return (
    <>
      <header className="page-header">
        <h1>Audit events</h1>
        <p>
          Privacy-filtered activity for the selected tenant, site, and action.
        </p>
      </header>
      <section className="audit-toolbar" aria-label="Audit controls">
        <p>
          Events are retained for 24 hours and never include origins, session
          bindings, network pseudonyms, addresses, user agents, or device data.
        </p>
        <button
          className="button secondary"
          type="button"
          onClick={onRefresh}
          disabled={busy}
        >
          {busy ? "Refreshing…" : "Refresh events"}
        </button>
      </section>
      <section className="scope-row" aria-label="Audit scope">
        <label>
          Tenant
          <input
            value={scope.tenant}
            onChange={(event) => onScopeChange("tenant", event.target.value)}
          />
        </label>
        <label>
          Site
          <input
            value={scope.site_key}
            onChange={(event) => onScopeChange("site_key", event.target.value)}
          />
        </label>
        <label>
          Action
          <input
            value={scope.action}
            onChange={(event) => onScopeChange("action", event.target.value)}
          />
        </label>
        <button
          className="button secondary load-scope"
          type="button"
          onClick={onLoadScope}
          disabled={busy}
        >
          Load scope
        </button>
      </section>
      <div className="table-scroll audit-table">
        <table>
          <caption className="visually-hidden">
            Recent Shar audit events
          </caption>
          <thead>
            <tr>
              <th scope="col">Time (UTC)</th>
              <th scope="col">Event</th>
              <th scope="col">Tier</th>
              <th scope="col">Backend</th>
              <th scope="col">Code</th>
            </tr>
          </thead>
          <tbody>
            {events.length ? (
              events.map((event, index) => (
                <tr key={`${event.occurred_at}-${event.kind}-${index}`}>
                  <th scope="row">{time(event.occurred_at)}</th>
                  <td>{event.kind.replaceAll("_", " ")}</td>
                  <td>{event.tier === undefined ? "—" : event.tier}</td>
                  <td>{event.backend ?? "—"}</td>
                  <td>{event.code ?? "—"}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5}>
                  No events in this scope during the retention window.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
