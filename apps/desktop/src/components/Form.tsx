import type { ComponentType, ReactNode } from "react";
import type { LucideProps } from "lucide-react";

interface FieldProps {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
  wide?: boolean;
}

/** A labelled control. Wrapping in <label> ties the text to the input. */
export function Field({ label, hint, error, children, wide }: FieldProps) {
  return (
    <label className={wide ? "field field-wide" : "field"}>
      <span className="field-label">{label}</span>
      {children}
      {error ? <span className="field-error">{error}</span> : hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  );
}

interface ToggleProps {
  label: string;
  description?: ReactNode;
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}

export function Toggle({ label, description, checked, disabled, onChange }: ToggleProps) {
  return (
    <label className={disabled ? "toggle toggle-disabled" : "toggle"}>
      <input type="checkbox" role="switch" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span className="toggle-track" aria-hidden="true" />
      <span className="toggle-text">
        <span className="toggle-label">{label}</span>
        {description && <span className="toggle-description">{description}</span>}
      </span>
    </label>
  );
}

/** A compact on/off switch for list rows; the label is for screen readers and the tooltip. */
export function Switch({ checked, label, disabled, onChange }: { checked: boolean; label: string; disabled?: boolean; onChange: (on: boolean) => void }) {
  return (
    <label className={disabled ? "toggle toggle-compact toggle-disabled" : "toggle toggle-compact"} title={label}>
      <input type="checkbox" role="switch" aria-label={label} checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span className="toggle-track" aria-hidden="true" />
    </label>
  );
}

export function Card({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="card-header">
          {title && <h2>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function Pill({ tone, children }: { tone: "ok" | "warn" | "danger" | "muted" | "accent"; children: ReactNode }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

/** Sections of one page, one shown at a time. */
export function SubTabs<T extends string>({
  tabs,
  value,
  onChange,
  label,
}: {
  tabs: { id: T; label: string }[];
  value: T;
  onChange: (id: T) => void;
  label: string;
}) {
  return (
    <div className="subtabs" role="tablist" aria-label={label}>
      {tabs.map((t) => (
        <button key={t.id} role="tab" className="subtab" aria-selected={value === t.id} onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

/** A friendly blank page: what will appear here and how to get it. */
export function EmptyState({
  icon: Icon,
  title,
  action,
  children,
}: {
  icon: ComponentType<LucideProps>;
  title: string;
  action?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon" aria-hidden="true">
        <Icon size={24} />
      </span>
      <strong>{title}</strong>
      {children && <p className="muted">{children}</p>}
      {action}
    </div>
  );
}
