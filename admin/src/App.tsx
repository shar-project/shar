import { useEffect, useMemo, useRef, useState } from "react";
import {
  AdminApiError,
  getAudit,
  getPolicy,
  liveStatus,
  putPolicy,
} from "./api";
import { AuditPanel } from "./components/AuditPanel";
import { Nav } from "./components/Nav";
import { OperationsPanel } from "./components/OperationsPanel";
import { OperationsStrip } from "./components/OperationsStrip";
import { FIELD_META, PolicyFields } from "./components/PolicyFields";
import { QuotePreview } from "./components/QuotePreview";
import { ShieldIcon, CloseIcon } from "./components/Icons";
import { UnlockDialog } from "./components/UnlockDialog";
import { trapModalFocus } from "./a11y";
import type {
  AuditEvent,
  LiveStatus,
  PolicyDocument,
  PolicyValues,
} from "./types";

const scopeDefault = {
  tenant: "default",
  site_key: "production",
  action: "signup",
};
const labels = Object.fromEntries(
  FIELD_META.map((field) => [field.key, field.label]),
) as Record<keyof PolicyValues, string>;
function readable(error: unknown) {
  if (error instanceof AdminApiError) {
    if (error.status === 401) return "That admin secret was not accepted.";
    if (error.status === 404)
      return "Administration is not enabled on this server.";
    return error.code.replaceAll("_", " ");
  }
  return "The server could not be reached.";
}
function validation(policy: PolicyValues) {
  const errors: Record<string, string> = {};
  if (!policy.version.trim() || policy.version.length > 128)
    errors.version = "Use 1–128 visible characters.";
  for (const key of ["base_iterations", "iteration_allowance"] as const) {
    if (!/^[1-9]\d*$/.test(policy[key]))
      errors[key] = "Enter a positive whole number.";
    else {
      try {
        if (BigInt(policy[key]) > (1n << 63n) - 1n)
          errors[key] = "This value cannot remain finite through Tier 32.";
      } catch {
        errors[key] = "Enter a positive whole number.";
      }
    }
  }
  for (const key of [
    "base_render_rounds",
    "quiet_window_seconds",
    "base_lifetime_seconds",
    "round_allowance_seconds",
    "max_lifetime_seconds",
  ] as const) {
    const value = policy[key];
    if (
      !Number.isSafeInteger(value) ||
      (key !== "round_allowance_seconds" && value <= 0) ||
      value < 0
    )
      errors[key] = "Enter a valid whole number.";
  }
  try {
    if (BigInt(policy.base_iterations) * 2n ** 32n > 2n ** 64n - 1n)
      errors.base_iterations = "Tier 32 would exceed the protocol limit.";
  } catch {}
  if (policy.base_render_rounds * 256 > 65_536)
    errors.base_render_rounds = "Tier 8 would exceed the 65,536-round limit.";
  return errors;
}

export default function App() {
  const [token, setToken] = useState("");
  const [document, setDocument] = useState<PolicyDocument | null>(null);
  const [loaded, setLoaded] = useState<PolicyDocument | null>(null);
  const [scope, setScope] = useState(scopeDefault);
  const [busy, setBusy] = useState(false);
  const [unlockError, setUnlockError] = useState("");
  const [notice, setNotice] = useState("");
  const [navOpen, setNavOpen] = useState(false);
  const [status, setStatus] = useState<LiveStatus | null>(null);
  const [statusBusy, setStatusBusy] = useState(false);
  const [jsonOpen, setJsonOpen] = useState(false);
  const [view, setView] = useState<"policies" | "audit" | "operations">(
    "policies",
  );
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditBusy, setAuditBusy] = useState(false);
  const noticeTimer = useRef<number | undefined>(undefined);
  const mainPanel = useRef<HTMLElement>(null);
  const jsonTrigger = useRef<HTMLButtonElement>(null);
  const jsonWasOpen = useRef(false);
  const errors = useMemo(
    () => (document ? validation(document.policy) : {}),
    [document],
  );
  const changed = useMemo(() => {
    if (!document || !loaded) return [];
    return (Object.keys(document.policy) as Array<keyof PolicyValues>).filter(
      (key) => String(document.policy[key]) !== String(loaded.policy[key]),
    );
  }, [document, loaded]);
  const flash = (message: string) => {
    setNotice(message);
    window.clearTimeout(noticeTimer.current);
    noticeTimer.current = window.setTimeout(() => setNotice(""), 3500);
  };
  const load = async (secret = token, nextScope = scope) => {
    setBusy(true);
    try {
      const value = await getPolicy(secret, nextScope);
      setToken(secret);
      setDocument(value);
      setLoaded(structuredClone(value));
      setScope({
        tenant: value.tenant,
        site_key: value.site_key,
        action: value.action,
      });
      setUnlockError("");
      void refreshStatus();
    } catch (error) {
      if (!token) setUnlockError(readable(error));
      else flash(readable(error));
      throw error;
    } finally {
      setBusy(false);
    }
  };
  const unlock = async (secret: string) => {
    try {
      await load(secret);
    } catch {}
  };
  const loadAudit = async (nextScope = scope) => {
    setAuditBusy(true);
    try {
      setAuditEvents((await getAudit(token, nextScope)).events);
    } catch (error) {
      flash(readable(error));
    } finally {
      setAuditBusy(false);
    }
  };
  const refreshStatus = async () => {
    setStatusBusy(true);
    try {
      setStatus(await liveStatus());
    } catch (error) {
      flash(readable(error));
    } finally {
      setStatusBusy(false);
    }
  };
  const selectView = (next: "policies" | "audit" | "operations") => {
    setView(next);
    setNavOpen(false);
    if (next === "audit") void loadAudit();
    if (next === "operations") void refreshStatus();
    queueMicrotask(() => mainPanel.current?.focus());
  };
  const closeJson = () => {
    setJsonOpen(false);
  };
  useEffect(() => {
    if (jsonWasOpen.current && !jsonOpen) jsonTrigger.current?.focus();
    jsonWasOpen.current = jsonOpen;
  }, [jsonOpen]);
  useEffect(() => () => window.clearTimeout(noticeTimer.current), []);
  if (!token || !document || !loaded)
    return <UnlockDialog busy={busy} error={unlockError} onUnlock={unlock} />;
  const changePolicy = (key: keyof PolicyValues, value: string) => {
    setDocument((current) => {
      if (!current) return current;
      const numeric = ![
        "version",
        "base_iterations",
        "iteration_allowance",
      ].includes(key);
      return {
        ...current,
        policy: {
          ...current.policy,
          [key]: numeric ? (value === "" ? Number.NaN : Number(value)) : value,
        },
      };
    });
  };
  const changeScope = (key: keyof typeof scope, value: string) =>
    setScope((current) => ({ ...current, [key]: value }));
  const save = async () => {
    if (Object.keys(errors).length) {
      flash("Resolve the highlighted policy fields first.");
      return;
    }
    setBusy(true);
    try {
      const saved = await putPolicy(token, {
        ...document,
        tenant: scope.tenant,
        site_key: scope.site_key,
        action: scope.action,
      });
      setDocument(saved);
      setLoaded(structuredClone(saved));
      flash("Policy saved. New quotes now use this configuration.");
    } catch (error) {
      flash(readable(error));
    } finally {
      setBusy(false);
    }
  };
  const switchScope = async () => {
    if (
      changed.length &&
      !confirm("Discard unsaved policy changes and load this scope?")
    )
      return;
    try {
      await load(token, scope);
      if (view === "audit") await loadAudit(scope);
    } catch {}
  };
  return (
    <div className="app-shell">
      <Nav
        open={navOpen}
        onToggle={() => setNavOpen((open) => !open)}
        active={view}
        onSelect={selectView}
        onUnavailable={(label) =>
          flash(`${label} has no separate view in this release.`)
        }
      />
      <main className="main-panel" ref={mainPanel} tabIndex={-1}>
        {view === "audit" ? (
          <AuditPanel
            scope={scope}
            events={auditEvents}
            busy={auditBusy}
            onRefresh={() => void loadAudit()}
            onScopeChange={changeScope}
            onLoadScope={() => void switchScope()}
          />
        ) : view === "operations" ? (
          <OperationsPanel
            status={status}
            busy={statusBusy}
            onRefresh={() => void refreshStatus()}
          />
        ) : (
          <>
            <header className="page-header">
              <h1>Work policies</h1>
              <p>Price abuse without rejecting valid work.</p>
            </header>
            <section className="scope-row" aria-label="Policy scope">
              <label>
                Tenant
                <input
                  value={scope.tenant}
                  onChange={(e) => changeScope("tenant", e.target.value)}
                />
              </label>
              <label>
                Site
                <input
                  value={scope.site_key}
                  onChange={(e) => changeScope("site_key", e.target.value)}
                />
              </label>
              <label>
                Action
                <input
                  value={scope.action}
                  onChange={(e) => changeScope("action", e.target.value)}
                />
              </label>
              <button
                className="button secondary load-scope"
                type="button"
                onClick={() => void switchScope()}
                disabled={busy}
              >
                Load scope
              </button>
            </section>
            <div className="editor-grid">
              <PolicyFields
                policy={document.policy}
                errors={errors}
                onChange={changePolicy}
              />
              <QuotePreview policy={document.policy} />
            </div>
            <section className="invariant">
              <ShieldIcon />
              <div>
                <strong>Correct work always succeeds</strong>
                <span>
                  Signals change future prices, never the validity of completed
                  work.
                </span>
              </div>
            </section>
            <div className="actions">
              <button
                className="button primary"
                type="button"
                onClick={() => void save()}
                disabled={busy || changed.length === 0}
              >
                {busy ? "Saving…" : "Save changes"}
              </button>
              <button
                className="button secondary"
                type="button"
                onClick={() => setDocument(structuredClone(loaded))}
                disabled={busy || changed.length === 0}
              >
                Discard
              </button>
            </div>
          </>
        )}
      </main>
      <aside className="summary-panel">
        <h2>
          {view === "audit"
            ? "Audit scope"
            : view === "operations"
              ? "Runtime status"
              : "Change summary"}
        </h2>
        <dl className="scope-summary">
          <div>
            <dt>Tenant</dt>
            <dd>{scope.tenant}</dd>
          </div>
          <div>
            <dt>Site</dt>
            <dd>{scope.site_key}</dd>
          </div>
          <div>
            <dt>Action</dt>
            <dd>{scope.action}</dd>
          </div>
        </dl>
        {view === "audit" ? (
          <>
            <hr />
            <p className="empty-changes">
              Showing the newest {auditEvents.length || "no"} event
              {auditEvents.length === 1 ? "" : "s"} from the 24-hour retention
              window.
            </p>
            <button
              className="button secondary json-button"
              type="button"
              onClick={() => void loadAudit()}
              disabled={auditBusy}
            >
              Refresh events
            </button>
          </>
        ) : view === "operations" ? (
          <>
            <hr />
            <p className="empty-changes">
              Runtime counters are intentionally aggregate and unlabeled. Use
              the audit view for privacy-filtered scoped events.
            </p>
            <button
              className="button secondary json-button"
              type="button"
              onClick={() => void refreshStatus()}
              disabled={statusBusy}
            >
              Refresh status
            </button>
          </>
        ) : (
          <>
            <hr />
            <h3>Modified fields</h3>
            {changed.length ? (
              <dl className="change-list">
                {changed.map((key) => (
                  <div key={key}>
                    <dt>{labels[key]}</dt>
                    <dd>{String(document.policy[key])}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="empty-changes">No unsaved changes.</p>
            )}
            <button
              ref={jsonTrigger}
              className="button secondary json-button"
              type="button"
              onClick={() => setJsonOpen(true)}
            >
              Policy JSON
            </button>
          </>
        )}
      </aside>
      {view !== "operations" && (
        <OperationsStrip status={status} connected={Boolean(document)} />
      )}
      {notice && (
        <div className="toast" role="status">
          {notice}
        </div>
      )}
      {jsonOpen && (
        <div className="modal-backdrop" role="presentation">
          <section
            className="json-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="json-title"
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                event.preventDefault();
                event.stopPropagation();
                closeJson();
              } else trapModalFocus(event);
            }}
          >
            <header>
              <h2 id="json-title">Policy JSON</h2>
              <button
                type="button"
                className="icon-button"
                aria-label="Close policy JSON"
                onClick={closeJson}
                autoFocus
              >
                <CloseIcon />
              </button>
            </header>
            <pre tabIndex={0} aria-label="Policy JSON document">
              {JSON.stringify(
                {
                  ...document,
                  tenant: scope.tenant,
                  site_key: scope.site_key,
                  action: scope.action,
                },
                null,
                2,
              )}
            </pre>
          </section>
        </div>
      )}
    </div>
  );
}
