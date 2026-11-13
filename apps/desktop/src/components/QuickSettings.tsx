import { useState } from "react";
import { CircleAlert, CircleCheck, CircleX, Copy, Eye, EyeOff, Globe, Info, RefreshCw, Settings2, Wifi } from "lucide-react";
import { useNav } from "../nav";
import { egressLabel, egressName, usableEgresses } from "../configUtils";
import { generatePassphrase } from "../passphrase";
import { useServiceCore, useServiceStatus } from "../service";
import type { Config, RoutingStatus } from "../types";
import { validatePassphrase, validateSsid } from "../validation";
import { Card, Field, Toggle } from "./Form";
import { useToast } from "./Toast";

/**
 * The settings people change most, under Home's big button: the Wi-Fi's name
 * and password, and the way devices go out. The rest stays on its own page.
 */
export function QuickSettings({ wifi, onMoreWifi }: { wifi: boolean; onMoreWifi?: () => void }) {
  const { config } = useServiceCore();
  const on = useServiceStatus()?.hotspot.state === "running";
  if (!config) return null;
  const pass = config.hotspot.passphrase ?? "";
  return (
    <div className="quick">
      {/* Saved elsewhere (the dialog), the fields start over from what was saved. */}
      {wifi && <WifiQuick key={`${config.hotspot.ssid}\u0000${pass}`} config={config} on={on} onMore={onMoreWifi} />}
      <InternetQuick config={config} />
    </div>
  );
}

/** The hotspot's name and password, editable in place. */
function WifiQuick({ config, on, onMore }: { config: Config; on: boolean; onMore?: () => void }) {
  const { saveConfig } = useServiceCore();
  const toast = useToast();
  const savedPass = config.hotspot.passphrase ?? "";
  const [ssid, setSsid] = useState(config.hotspot.ssid);
  const [pass, setPass] = useState(savedPass);
  const [reveal, setReveal] = useState(false);
  const [saving, setSaving] = useState(false);

  const ssidError = validateSsid(ssid);
  const passError = validatePassphrase(pass);
  const dirty = ssid !== config.hotspot.ssid || pass !== savedPass;
  const valid = !ssidError && !passError && pass !== "";

  const save = async () => {
    setSaving(true);
    await saveConfig(
      (c) => {
        c.hotspot.ssid = ssid;
        c.hotspot.passphrase = pass;
      },
      on ? "Saved. The hotspot restarts with the new name and password." : "Wi-Fi name and password saved.",
    );
    setSaving(false);
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(pass);
      toast.success("Password copied");
    } catch {
      toast.error("Could not copy the password");
    }
  };

  return (
    <Card
      title={
        <span className="title-with-icon">
          <Wifi size={15} aria-hidden="true" /> Wi-Fi
        </span>
      }
      actions={
        // Save shows up once something is changed; More is always there, as on the card beside it.
        <>
          {dirty && (
            <button className="button button-primary button-small" disabled={!valid || saving} onClick={() => void save()}>
              Save
            </button>
          )}
          {onMore && <MoreLink onClick={onMore} label="More Wi-Fi settings" />}
        </>
      }
    >
      <div className="quick-fields">
        <Field label="Network name" error={ssidError}>
          <input value={ssid} onChange={(e) => setSsid(e.target.value)} spellCheck={false} />
        </Field>
        <Field label="Password" error={passError} hint={pass === "" ? "8 or more characters." : undefined}>
          <div className="input-with-button">
            <input
              type={reveal ? "text" : "password"}
              value={pass}
              onChange={(e) => setPass(e.target.value)}
              autoComplete="new-password"
              spellCheck={false}
            />
            <button type="button" className="icon-button" aria-label={reveal ? "Hide password" : "Show password"} onClick={() => setReveal((r) => !r)}>
              {reveal ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
            {pass !== "" && !dirty ? (
              <button type="button" className="icon-button" aria-label="Copy password" title="Copy" onClick={() => void copy()}>
                <Copy size={14} />
              </button>
            ) : (
              <button
                type="button"
                className="icon-button"
                aria-label="Make up a password"
                title="Make up a password"
                onClick={() => {
                  setPass(generatePassphrase());
                  setReveal(true);
                }}
              >
                <RefreshCw size={14} />
              </button>
            )}
          </div>
        </Field>
      </div>
    </Card>
  );
}

/** The way to a card's other settings, the same on every card. */
function MoreLink({ onClick, label }: { onClick: () => void; label: string }) {
  return (
    <button className="link-button" onClick={onClick} title={label}>
      <Settings2 size={13} aria-hidden="true" /> More
    </button>
  );
}

/** The routing state as the user sees it, before the service has said anything. */
function routingState(config: Config, routing: RoutingStatus | undefined): RoutingStatus["state"] {
  if (routing) return routing.state;
  return config.network.transparent_routing ? "waiting" : "off";
}

/**
 * The way devices go out, whether that choice applies right now (only while
 * Captun carries their traffic), and whether new devices wait for an OK.
 */
function InternetQuick({ config }: { config: Config }) {
  const { saveConfig } = useServiceCore();
  const nav = useNav();
  const routing = useServiceStatus()?.routing;
  const state = routingState(config, routing);
  const choices = usableEgresses(config);
  const current = config.network.default_egress;
  const currentOff = !choices.some((e) => e.id === current);

  const setDefault = (id: string) =>
    void saveConfig((c) => {
      c.network.default_egress = id;
    }, `Devices now go out through ${egressLabel(config, id)}`);
  const setRouting = (on: boolean) =>
    void saveConfig(
      (c) => {
        c.network.transparent_routing = on;
      },
      on ? "Outbounds turned on" : "Outbounds turned off: devices use this computer's internet",
    );
  const setAsk = (ask: boolean) =>
    void saveConfig(
      (c) => {
        c.network.quarantine_new_clients = ask;
      },
      ask ? "New devices now wait for your OK" : "New devices now get internet right away",
    );

  let line;
  switch (state) {
    case "off":
      line = (
        <p className="quick-state quick-state-off">
          <CircleAlert size={14} aria-hidden="true" />
          <span>
            Off: devices use this computer's own internet.{" "}
            <button className="link-button" onClick={() => setRouting(true)}>
              Turn on
            </button>
          </span>
        </p>
      );
      break;
    case "waiting":
      line = (
        <p className="quick-state">
          <Info size={14} aria-hidden="true" />
          <span>Applies once sharing starts.</span>
        </p>
      );
      break;
    case "active":
      line = (
        <p className="quick-state quick-state-ok">
          <CircleCheck size={14} aria-hidden="true" />
          <span>
            Applies now.{" "}
            <button className="link-button" onClick={() => setRouting(false)}>
              Turn off
            </button>
          </span>
        </p>
      );
      break;
    case "failed":
      line = (
        <p className="quick-state quick-state-failed" role="alert" title={routing?.error ?? undefined}>
          <CircleX size={14} aria-hidden="true" />
          <span>
            Could not apply: {routing?.error ?? "unknown error"}{" "}
            {/* Saving re-applies routing, which is how a failed start is retried. */}
            <button className="link-button" onClick={() => void saveConfig(() => undefined, "Trying again")}>
              Try again
            </button>
          </span>
        </p>
      );
      break;
  }

  return (
    <Card
      title={
        <span className="title-with-icon">
          <Globe size={15} aria-hidden="true" /> Internet for devices
        </span>
      }
      actions={<MoreLink onClick={() => nav("egresses")} label="All outbounds" />}
    >
      <Field label="Devices go out through">
        <select value={current} onChange={(e) => setDefault(e.target.value)}>
          {currentOff && <option value={current}>{egressLabel(config, current)} (off)</option>}
          {choices.map((e) => (
            <option key={e.id} value={e.id}>
              {egressName(e)}
            </option>
          ))}
        </select>
      </Field>
      {line}
      <Toggle
        label="Ask before new devices get internet"
        checked={config.network.quarantine_new_clients}
        onChange={setAsk}
      />
    </Card>
  );
}
