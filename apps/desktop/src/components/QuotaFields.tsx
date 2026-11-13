import { formatBytes, formatKbps } from "../format";
import type { Quota, QuotaPeriod, QuotaUse } from "../types";
import { Field } from "./Form";

/** Mirrors captun-core's MAX_QUOTA_MB. */
const MAX_QUOTA_MB = 1_000_000_000;

export const PERIOD_LABEL: Record<QuotaPeriod, string> = {
  day: "a day",
  week: "a week",
  month: "a month",
  total: "in total",
};

/** "2 GB a day, then 256 kbit/s" or "…, then no internet". */
export function describeQuota(q: Quota): string {
  const amount = formatBytes(q.mb * 1_048_576);
  const then = q.then_kbps != null ? `then ${formatKbps(q.then_kbps)}` : "then no internet";
  return `${amount} ${PERIOD_LABEL[q.every]}, ${then}`;
}

/** "1.2 GB of 2.0 GB used", with when it starts over. */
export function describeUse(use: QuotaUse): string {
  const left = use.over ? "used up" : `${formatBytes(use.used)} of ${formatBytes(use.allowed)} used`;
  if (use.resets_at_ms == null) return left;
  const when = new Date(use.resets_at_ms).toLocaleString(undefined, { weekday: "short", day: "numeric", month: "short", hour: "numeric", minute: "2-digit" });
  return `${left} · starts over ${when}`;
}

export interface QuotaForm {
  /** Empty: no allowance of its own. */
  amount: string;
  unit: "mb" | "gb";
  every: QuotaPeriod;
  then: "block" | "slow";
  slowKbps: string;
}

export function quotaToForm(q: Quota | null | undefined): QuotaForm {
  if (!q) return { amount: "", unit: "gb", every: "day", then: "block", slowKbps: "256" };
  const gb = q.mb % 1024 === 0;
  return {
    amount: String(gb ? q.mb / 1024 : q.mb),
    unit: gb ? "gb" : "mb",
    every: q.every,
    then: q.then_kbps != null ? "slow" : "block",
    slowKbps: q.then_kbps != null ? String(q.then_kbps) : "256",
  };
}

/** The allowance the form describes (none when the amount is empty), or why it cannot be one. */
export function formToQuota(form: QuotaForm): { quota?: Quota; error?: string } {
  const text = form.amount.trim();
  if (text === "") return {};
  const amount = Number(text);
  if (!(amount > 0) || !Number.isFinite(amount)) return { error: "The amount must be a number above 0." };
  const mb = Math.round(form.unit === "gb" ? amount * 1024 : amount);
  if (mb < 1 || mb > MAX_QUOTA_MB) return { error: "The amount must be between 1 MB and about a petabyte." };
  let then_kbps: number | undefined;
  if (form.then === "slow") {
    const kbps = Number(form.slowKbps.trim());
    if (!(kbps > 0) || !Number.isInteger(kbps)) return { error: "The slow speed must be a whole number above 0." };
    then_kbps = kbps;
  }
  return { quota: { mb, every: form.every, ...(then_kbps !== undefined ? { then_kbps } : {}) } };
}

/**
 * The fields of a data allowance: how much, how often it starts over, and
 * what happens once it is used up. `inherited` says what applies while the
 * amount is empty.
 */
export function QuotaFields({
  form,
  onChange,
  error,
  inherited,
}: {
  form: QuotaForm;
  onChange: (form: QuotaForm) => void;
  error?: string;
  inherited?: string;
}) {
  const set = (patch: Partial<QuotaForm>) => onChange({ ...form, ...patch });
  const off = form.amount.trim() === "";
  return (
    <>
      <Field label="Data allowance" error={error} hint={off ? (inherited ?? "Empty: unlimited.") : "Download and upload together."}>
        <div className="input-with-button">
          <input inputMode="decimal" value={form.amount} onChange={(e) => set({ amount: e.target.value })} placeholder="Unlimited" />
          <select aria-label="Unit" value={form.unit} onChange={(e) => set({ unit: e.target.value as QuotaForm["unit"] })} className="select-narrow">
            <option value="gb">GB</option>
            <option value="mb">MB</option>
          </select>
        </div>
      </Field>
      <Field label="Starts over">
        <select value={form.every} disabled={off} onChange={(e) => set({ every: e.target.value as QuotaPeriod })}>
          <option value="day">Every day at midnight</option>
          <option value="week">Every week</option>
          <option value="month">Every month, on the 1st</option>
          <option value="total">Never: only when started over by hand</option>
        </select>
      </Field>
      <Field label="When it is used up">
        <div className="input-with-button">
          <select value={form.then} disabled={off} onChange={(e) => set({ then: e.target.value as QuotaForm["then"] })}>
            <option value="block">No internet until it starts over</option>
            <option value="slow">Slow down to (kbit/s)</option>
          </select>
          {form.then === "slow" && (
            <input
              aria-label="Slow speed in kbit/s"
              inputMode="numeric"
              disabled={off}
              value={form.slowKbps}
              onChange={(e) => set({ slowKbps: e.target.value })}
              className="input-narrow"
            />
          )}
        </div>
      </Field>
    </>
  );
}
