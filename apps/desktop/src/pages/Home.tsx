import { useState } from "react";
import { ChevronRight, Users } from "lucide-react";
import { PowerButton } from "../components/PowerButton";
import { QuickSettings } from "../components/QuickSettings";
import { useNav } from "../nav";
import { useClients } from "../service";
import { useHotspotSupport } from "../system";
import { useHotspot } from "./Hotspot";
import { useUsb } from "./Usb";

type ModeId = "wifi" | "usb";

// The mode last picked, kept while the app runs.
let lastMode: ModeId | null = null;

/**
 * The first screen, kept simple: the big wheel at the top that starts or
 * stops sharing, the way to share (Wi-Fi hotspot or USB to phone), one line
 * about the devices, and under it the settings people change most (the
 * Wi-Fi name and password, the way devices go out). Everything else about
 * the devices (each one's outbound, allowing or blocking) is on the Devices
 * and Outbound pages.
 */
export function Home() {
  const support = useHotspotSupport();
  const wifi = useHotspot(support);
  const usb = useUsb();
  const [chosen, setChosen] = useState<ModeId | null>(lastMode);

  const preferred: ModeId = wifi.active ? "wifi" : usb.active ? "usb" : wifi.phase === "unavailable" ? "usb" : "wifi";
  const mode = chosen ?? preferred;
  const current = mode === "wifi" ? wifi : usb;
  const choose = (id: ModeId) => {
    lastMode = id;
    setChosen(id);
  };

  return (
    <div className="home">
      <section className="hero" aria-label="Sharing">
        <PowerButton phase={current.phase} label={current.action?.label ?? "Wait"} title={current.action?.hint} onClick={current.action?.run} />
        <div className="hero-text">
          <h2 className="hero-status" aria-live="polite">
            {current.status}
          </h2>
          {current.detail && <div className="hero-detail">{current.detail}</div>}
          <div className="hero-actions">
            {current.links && <div className="hero-links">{current.links}</div>}
            <div className="mode-switch" role="radiogroup" aria-label="Share over">
              {[wifi, usb].map((m) => (
                <button key={m.id} role="radio" aria-checked={mode === m.id} className="mode" onClick={() => choose(m.id)}>
                  <m.icon size={14} aria-hidden="true" />
                  {m.label}
                  {m.active && <span className="mode-on" aria-label="on" />}
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>
      <DevicesLine sharing={wifi.phase === "on" || usb.phase === "on"} />
      <QuickSettings wifi={mode === "wifi" && wifi.phase !== "unavailable"} onMoreWifi={wifi.settings} />
      {wifi.overlay}
      {usb.overlay}
    </div>
  );
}

/** How many devices are on, and how many wait to be allowed, with the way to the Devices page. */
function DevicesLine({ sharing }: { sharing: boolean }) {
  const nav = useNav();
  const online = useClients().filter((c) => c.online);
  const waiting = online.filter((c) => c.state === "pending").length;
  if (!sharing && online.length === 0) return null;
  return (
    <div className="home-devices" aria-live="polite">
      <Users size={15} aria-hidden="true" />
      <span>
        {online.length === 0
          ? "No devices yet"
          : `${online.length} ${online.length === 1 ? "device" : "devices"} connected`}
        {waiting > 0 && <span className="home-waiting"> · {waiting} waiting to be allowed</span>}
      </span>
      {online.length > 0 && (
        <button className="link-button" onClick={() => nav("clients")}>
          See devices <ChevronRight size={13} aria-hidden="true" />
        </button>
      )}
    </div>
  );
}
