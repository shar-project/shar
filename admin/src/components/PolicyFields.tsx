import type { PolicyValues } from "../types";

interface FieldMeta {
  key: keyof PolicyValues;
  label: string;
  help: string;
  kind: "text" | "bigint" | "number";
  unit?: string;
}
export const FIELD_META: readonly FieldMeta[] = [
  {
    key: "version",
    label: "Policy version",
    help: "Identifier committed into signed quotes.",
    kind: "text",
  },
  {
    key: "base_iterations",
    label: "Base iterations",
    help: "Time-lock iterations required at Tier 0.",
    kind: "bigint",
  },
  {
    key: "base_render_rounds",
    label: "Base rendering rounds",
    help: "Rendering rounds required at Tier 0.",
    kind: "number",
  },
  {
    key: "quiet_window_seconds",
    label: "Quiet window",
    help: "One pressure tier decays per quiet window.",
    kind: "number",
    unit: "seconds",
  },
  {
    key: "base_lifetime_seconds",
    label: "Base lifetime",
    help: "Initial lifetime of issued challenges.",
    kind: "number",
    unit: "seconds",
  },
  {
    key: "iteration_allowance",
    label: "Iteration allowance",
    help: "Iterations budgeted per lifetime second.",
    kind: "bigint",
  },
  {
    key: "round_allowance_seconds",
    label: "Round allowance",
    help: "Lifetime seconds budgeted per render round.",
    kind: "number",
    unit: "seconds",
  },
  {
    key: "max_lifetime_seconds",
    label: "Maximum lifetime",
    help: "Upper bound on challenge lifetime.",
    kind: "number",
    unit: "seconds",
  },
];

interface Props {
  policy: PolicyValues;
  errors: Record<string, string>;
  onChange: (key: keyof PolicyValues, value: string) => void;
}
export function PolicyFields({ policy, errors, onChange }: Props) {
  return (
    <div className="policy-fields">
      {FIELD_META.map((field) => {
        const value = String(policy[field.key]);
        const error = errors[field.key];
        return (
          <div className="policy-field" key={field.key}>
            <label htmlFor={field.key}>{field.label}</label>
            <div className={`input-shell ${error ? "invalid" : ""}`}>
              <input
                id={field.key}
                name={field.key}
                type={field.kind === "text" ? "text" : "text"}
                inputMode={field.kind === "text" ? undefined : "numeric"}
                value={value}
                onChange={(event) => onChange(field.key, event.target.value)}
                aria-describedby={`${field.key}-help${error ? ` ${field.key}-error` : ""}`}
                aria-invalid={Boolean(error)}
              />
              {field.unit && <span>{field.unit}</span>}
            </div>
            <p id={`${field.key}-help`}>{field.help}</p>
            {error && (
              <p className="field-error" id={`${field.key}-error`}>
                {error}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}
