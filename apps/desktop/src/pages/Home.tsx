import { useState } from "react";
import { DeviceOutbounds } from "../components/DeviceOutbounds";
import { PowerButton } from "../components/PowerButton";
import { useHotspotSupport } from "../system";
import { useHotspot } from "./Hotspot";
import { useUsb } from "./Usb";

type ModeId = "wifi" | "usb";

// The mode last picked, kept while the app runs.
let lastMode: ModeId | null = null;

/**
 * The first screen: one big button that starts or stops sharing, the way to
 * share underneath it (Wi-Fi hotspot or USB to phone), and the devices using
 * the connection with the way each goes out.
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

  // While sharing, the button moves beside what to join, so the devices below
  // keep their room and the page never needs scrolling.
  return (
    <div className="home">
      <section className={current.phase === "on" ? "hero hero-on" : "hero"} aria-label="Sharing">
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
      <DeviceOutbounds />
      {wifi.overlay}
      {usb.overlay}
    </div>
  );
}
