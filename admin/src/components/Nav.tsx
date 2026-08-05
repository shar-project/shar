import { useRef } from "react";
import { DocumentIcon, GridIcon, KeyIcon, MenuIcon, PulseIcon } from "./Icons";

interface Props {
  open: boolean;
  onToggle: () => void;
  active: "policies" | "audit" | "operations";
  onSelect: (view: "policies" | "audit" | "operations") => void;
  onUnavailable: (label: string) => void;
}
export function Nav({
  open,
  onToggle,
  active,
  onSelect,
  onUnavailable,
}: Props) {
  const menuButton = useRef<HTMLButtonElement>(null);
  const items = [
    { label: "Overview", Icon: GridIcon, view: undefined },
    { label: "Work policies", Icon: DocumentIcon, view: "policies" as const },
    { label: "Audit events", Icon: PulseIcon, view: "audit" as const },
    { label: "Operations", Icon: PulseIcon, view: "operations" as const },
    { label: "Key rotation", Icon: KeyIcon },
  ];
  return (
    <>
      <button
        ref={menuButton}
        className="mobile-menu"
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls="primary-navigation"
      >
        <MenuIcon /> <span>Menu</span>
      </button>
      <aside
        className={`nav-rail ${open ? "nav-open" : ""}`}
        id="primary-navigation"
        onKeyDown={(event) => {
          if (open && event.key === "Escape") {
            event.preventDefault();
            onToggle();
            menuButton.current?.focus();
          }
        }}
      >
        <div className="brand">Shar</div>
        <nav aria-label="Administration">
          {items.map(({ label, Icon, view }) => {
            const isActive = view === active;
            return (
              <button
                key={label}
                type="button"
                className={`nav-item ${isActive ? "active" : ""}`}
                aria-current={isActive ? "page" : undefined}
                onClick={() => {
                  if (view) onSelect(view);
                  else onUnavailable(label);
                }}
              >
                <Icon />
                <span>{label}</span>
              </button>
            );
          })}
        </nav>
        <div className="self-hosted">
          <span className="status-dot" />
          Self-hosted<span>v0.1.0</span>
        </div>
      </aside>
    </>
  );
}
