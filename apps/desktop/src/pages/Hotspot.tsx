import { useState } from "react";
import { Eye, EyeOff, Info, Play, RefreshCw, Settings2, Wifi, WifiOff } from "lucide-react";
import { api, errorMessage } from "../api";
import { Field, Toggle } from "../components/Form";
import { Modal } from "../components/Modal";
import { CopyValue } from "../components/CopyValue";
import { useServiceCore, useServiceStatus } from "../service";
import { ADMIN_PROMPT, serviceRunning, startServiceAndWait } from "../system";
import type { Config, HotspotSupport, WifiBand } from "../types";
import { validateMaxClients, validatePassphrase, validateSsid } from "../validation";
import type { ShareMode } from "./share";

const PASS_ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/** 12 characters from an alphabet without look-alikes, without modulo bias. */
function generatePassphrase(length = 12): string {
  const limit = 256 - (256 % PASS_ALPHABET.length);
  const out: string[] = [];
  while (out.length < length) {
    for (const b of crypto.getRandomValues(new Uint8Array(32))) {
      if (b < limit && out.length < length) out.push(PASS_ALPHABET[b % PASS_ALPHABET.length] ?? "");
    }
  }
  return out.join("");
}

type Step = "save" | "service" | "start";

const STEP_TEXT: Record<Step, string> = {
  save: "Saving the settings…",
  service: `Starting Captun… ${ADMIN_PROMPT.during}`,
  start: "Turning the hotspot on…",
};

interface Form {
  ssid: string;
  passphrase: string;
  band: WifiBand;
  maxClients: string;
  autostart: boolean;
}

const DEFAULT_FORM: Form = { ssid: "Captun", passphrase: "", band: "auto", maxClients: "", autostart: true };

function fromConfig(config: Config | null): Form {
  if (!config) return DEFAULT_FORM;
  const h = config.hotspot;
  return {
    ssid: h.ssid,
    passphrase: h.passphrase ?? "",
    band: h.band,
    maxClients: h.max_clients != null ? String(h.max_clients) : "",
    autostart: h.autostart,
  };
}

function applyForm(draft: Config, form: Form) {
  draft.hotspot.ssid = form.ssid;
  draft.hotspot.passphrase = form.passphrase;
  draft.hotspot.band = form.band;
  draft.hotspot.autostart = form.autostart;
  const max = form.maxClients.trim();
  // An empty limit must be omitted, not sent as null, so serde's default applies.
  if (max === "") delete draft.hotspot.max_clients;
  else draft.hotspot.max_clients = Number(max);
}

/**
 * The Wi-Fi hotspot as Home's big button drives it: Start while off, the name
 * and password to join with while on. Its settings open in a dialog, on the
 * first Start and from "Wi-Fi settings".
 */
export function useHotspot(support: HotspotSupport | null): ShareMode {
  const { config, run, saveConfig, refreshConfig, refreshStatus } = useServiceCore();
  const status = useServiceStatus();
  const [editing, setEditing] = useState(false);
  const [step, setStep] = useState<Step | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stopping, setStopping] = useState(false);

  const state = status?.hotspot.state ?? "stopped";
  const on = state === "running";
  const switching = state === "starting" || state === "stopping";
  const busy = step !== null || stopping || switching;
  const saved = fromConfig(config);
  const configured = saved.passphrase !== "";
  const unavailable = support?.supported === false && !on && !switching;
  const osLimit = status?.hotspot.max_clients ?? null;
  const limits = [config?.hotspot.max_clients, osLimit].filter((n): n is number => n != null);
  const limit = limits.length > 0 ? Math.min(...limits) : null;
  const devices = status?.clients_online ?? 0;
  const failure = error ?? (state === "failed" ? status?.hotspot.error : null) ?? null;

  /** Saves `form` if given, starts the service if needed, then the hotspot. */
  const start = async (form?: Form) => {
    setError(null);
    let current: Step = "save";
    try {
      if (form) {
        setStep("save");
        // Offline this lands on this computer and reaches the service as it connects.
        const draft = structuredClone(await api.getConfig());
        applyForm(draft, form);
        await api.setConfig(draft);
      }
      if (!(await serviceRunning())) {
        current = "service";
        setStep("service");
        await startServiceAndWait();
      }
      current = "start";
      setStep("start");
      // A service that just started may be bringing the hotspot up by itself
      // (autostart); asking again would restart it.
      const now = await api.getStatus().catch(() => null);
      if (now?.hotspot.state === "running" || now?.hotspot.state === "starting") return;
      await api.startHotspot();
    } catch (e) {
      setError(`${current === "service" ? "Captun could not start: " : ""}${errorMessage(e)}`);
    } finally {
      setStep(null);
      await Promise.all([refreshConfig(), refreshStatus()]);
    }
  };

  const stop = async () => {
    setStopping(true);
    await run(api.stopHotspot, "Could not stop the hotspot");
    await refreshStatus();
    setStopping(false);
  };

  const overlay = editing ? (
    <HotspotSettings
      config={config}
      on={on}
      configured={configured}
      bandSupported={status?.capabilities.band_selection ?? true}
      osLimit={osLimit}
      notice={support?.notice ?? null}
      onClose={() => setEditing(false)}
      onSave={async (form) => {
        const radio = form.ssid !== saved.ssid || form.passphrase !== saved.passphrase || form.band !== saved.band;
        // The service restarts a running hotspot itself when its radio settings change.
        const ok = await saveConfig(
          (c) => applyForm(c, form),
          on && radio ? "Saved. The hotspot restarts with the new settings." : "Hotspot settings saved.",
        );
        if (ok) setEditing(false);
      }}
      onStart={(form) => {
        setEditing(false);
        void start(form);
      }}
    />
  ) : null;

  const settingsLink = configured ? (
    <button className="link-button" disabled={busy} onClick={() => setEditing(true)}>
      <Settings2 size={13} aria-hidden="true" /> Wi-Fi settings
    </button>
  ) : null;

  const base = { id: "wifi" as const, label: "Wi-Fi hotspot", icon: Wifi, active: on || busy, overlay };

  if (unavailable) {
    return { ...base, icon: WifiOff, phase: "unavailable", action: null, status: "Wi-Fi hotspot is not available", detail: support?.reason };
  }
  if (busy) {
    const text = step ? STEP_TEXT[step] : state === "stopping" || stopping ? "Turning off…" : "Turning on…";
    return { ...base, phase: "busy", action: null, status: text };
  }
  if (on) {
    return {
      ...base,
      phase: "on",
      action: { label: "Stop", run: () => void stop() },
      status: `Sharing over Wi-Fi · ${devices}${limit != null ? ` of ${limit}` : ""} device${devices === 1 && limit == null ? "" : "s"}`,
      detail: (
        <div className="join">
          <CopyValue label="Network" value={status?.hotspot.ssid ?? saved.ssid} />
          <CopyValue label="Password" value={saved.passphrase} secret />
        </div>
      ),
      // The devices are listed right below, with their own way to the Devices page.
      links: settingsLink,
    };
  }
  if (!configured) {
    return {
      ...base,
      phase: failure ? "error" : "off",
      action: { label: "Set up", run: () => setEditing(true) },
      status: "Share this computer's internet over Wi-Fi",
      detail: failure ?? "Pick a name and password; phones and laptops join it like any Wi-Fi.",
    };
  }
  return {
    ...base,
    phase: failure ? "error" : "off",
    action: { label: failure ? "Try again" : "Start", hint: ADMIN_PROMPT.before, run: () => void start() },
    status: failure ? "The hotspot is off" : `Ready to share as “${saved.ssid}”`,
    detail: failure ? (
      <span className="hero-problem">{failure}</span>
    ) : support?.notice ? (
      <span className="hero-note">
        <Info size={13} aria-hidden="true" /> {support.notice}
      </span>
    ) : limit != null ? (
      `Up to ${limit} devices`
    ) : undefined,
    links: settingsLink,
  };
}

interface SettingsProps {
  config: Config | null;
  on: boolean;
  configured: boolean;
  bandSupported: boolean;
  osLimit: number | null;
  notice: string | null;
  onClose: () => void;
  onSave: (form: Form) => Promise<void>;
  onStart: (form: Form) => void;
}

/** The hotspot's name, password and limits, in a dialog. */
function HotspotSettings({ config, on, configured, bandSupported, osLimit, notice, onClose, onSave, onStart }: SettingsProps) {
  const saved = fromConfig(config);
  // A first-time setup starts with a password ready to use.
  const [form, setForm] = useState<Form>(() => (configured ? saved : { ...saved, passphrase: saved.passphrase || generatePassphrase() }));
  const [reveal, setReveal] = useState(!configured);
  const [saving, setSaving] = useState(false);

  const update = (patch: Partial<Form>) => setForm((f) => ({ ...f, ...patch }));
  const ssidError = validateSsid(form.ssid);
  const passError = validatePassphrase(form.passphrase);
  const maxError = validateMaxClients(form.maxClients);
  const valid = !ssidError && !passError && !maxError && form.passphrase !== "";
  const dirty =
    form.ssid !== saved.ssid ||
    form.passphrase !== saved.passphrase ||
    form.band !== saved.band ||
    form.maxClients.trim() !== saved.maxClients ||
    form.autostart !== saved.autostart;

  const save = async () => {
    setSaving(true);
    await onSave(form);
    setSaving(false);
  };

  return (
    <Modal
      title={configured ? "Wi-Fi hotspot settings" : "Set up the Wi-Fi hotspot"}
      onClose={onClose}
      footer={
        <>
          <button className="button" onClick={onClose}>
            Cancel
          </button>
          {(on || configured) && (
            <button className={on ? "button button-primary" : "button"} disabled={!valid || !dirty || saving} onClick={() => void save()}>
              Save
            </button>
          )}
          {!on && (
            <button className="button button-primary" disabled={!valid || saving} onClick={() => onStart(form)}>
              <Play size={14} aria-hidden="true" /> {configured ? "Save and start" : "Start hotspot"}
            </button>
          )}
        </>
      }
    >
      <div className="form-grid">
        <Field label="Network name" error={ssidError}>
          <input value={form.ssid} onChange={(e) => update({ ssid: e.target.value })} spellCheck={false} data-autofocus />
        </Field>
        <Field label="Password" error={passError} hint="8 or more characters.">
          <div className="input-with-button">
            <input
              type={reveal ? "text" : "password"}
              value={form.passphrase}
              onChange={(e) => update({ passphrase: e.target.value })}
              autoComplete="new-password"
              spellCheck={false}
            />
            <button type="button" className="icon-button" aria-label={reveal ? "Hide password" : "Show password"} onClick={() => setReveal((r) => !r)}>
              {reveal ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
            <button
              type="button"
              className="icon-button"
              aria-label="Make up a password"
              title="Make up a password"
              onClick={() => {
                update({ passphrase: generatePassphrase() });
                setReveal(true);
              }}
            >
              <RefreshCw size={14} />
            </button>
          </div>
        </Field>
        <Field label="Wi-Fi band" hint={bandSupported ? undefined : "Picked by the system."}>
          <select value={form.band} onChange={(e) => update({ band: e.target.value as WifiBand })} disabled={!bandSupported}>
            <option value="auto">Automatic</option>
            <option value="2.4ghz">2.4 GHz (longer range)</option>
            <option value="5ghz">5 GHz (faster)</option>
            <option value="6ghz">6 GHz</option>
          </select>
        </Field>
        <Field label="Maximum devices" error={maxError} hint={osLimit != null ? `Empty: system limit (${osLimit}).` : "Empty: no limit."}>
          <input
            type="number"
            inputMode="numeric"
            min={1}
            max={255}
            placeholder="No limit"
            value={form.maxClients}
            onChange={(e) => update({ maxClients: e.target.value })}
          />
        </Field>
        <div className="field field-wide">
          <Toggle label="Turn on whenever Captun starts" checked={form.autostart} onChange={(autostart) => update({ autostart })} />
        </div>
      </div>
      {notice && (
        <p className="panel-note">
          <Info size={14} aria-hidden="true" /> {notice}
        </p>
      )}
    </Modal>
  );
}
