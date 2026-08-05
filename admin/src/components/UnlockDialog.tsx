import { useState, type FormEvent } from "react";
import { ShieldIcon } from "./Icons";
import { trapModalFocus } from "../a11y";

interface Props {
  busy: boolean;
  error: string;
  onUnlock: (token: string) => Promise<void>;
}
export function UnlockDialog({ busy, error, onUnlock }: Props) {
  const [token, setToken] = useState("");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void onUnlock(token.trim());
  };
  return (
    <div className="unlock-backdrop" role="presentation">
      <section
        className="unlock-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="unlock-title"
        aria-describedby="unlock-description"
        tabIndex={-1}
        onKeyDown={trapModalFocus}
      >
        <ShieldIcon className="unlock-mark" />
        <h1 id="unlock-title">Open Shar administration</h1>
        <p id="unlock-description">
          Enter the separate admin bearer secret. It stays in this tab’s memory
          and is never saved.
        </p>
        <form onSubmit={submit}>
          <label htmlFor="admin-secret">Admin secret</label>
          <input
            id="admin-secret"
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={token}
            onChange={(event) => setToken(event.target.value)}
            required
            minLength={16}
            autoFocus
          />
          <button className="button primary" disabled={busy || !token.trim()}>
            {busy ? "Connecting…" : "Open dashboard"}
          </button>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
        </form>
      </section>
    </div>
  );
}
