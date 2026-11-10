import { memo, useCallback, useMemo, useRef, type ReactNode } from "react";
import { ChevronRight, CircleAlert, CircleCheck, CircleX, Info, Route } from "lucide-react";
import { deviceAddress, deviceName, egressLabel, egressName, profileFor, usableEgresses } from "../configUtils";
import { AddressChip } from "./AddressChip";
import { formatRate } from "../format";
import { useNav } from "../nav";
import { useClients, useDeviceTraffic, useServiceCore, useServiceStatus } from "../service";
import type { Config, EgressConfig, MacAddr, RoutingStatus, TrafficStats } from "../types";

/** The outbound a device uses when it has none of its own: its group's, else the default. */
function inheritedEgress(config: Config, group: string | null): string {
  const found = group ? config.group?.find((g) => g.id === group) : undefined;
  return found?.egress ?? config.network.default_egress;
}

interface DeviceRowProps {
  mac: string;
  name: string;
  address: string | undefined;
  /** Its speeds, shown only while outbounds apply (they are measured then). */
  showRate: boolean;
  /** Its traffic as the device list gave it, until the service sends its speeds. */
  listed: TrafficStats;
  /** Its own outbound; "" when it goes out like the rest. */
  own: string;
  group: string | null;
  config: Config;
  choices: EgressConfig[];
  onPick: (mac: string, egress: string) => void;
}

/** A row's speeds. It redraws by itself every second as they come; the row does not. */
function DeviceRowRate({ mac, listed }: { mac: MacAddr; listed: TrafficStats }) {
  const traffic = useDeviceTraffic(mac) ?? listed;
  return <span className="device-row-rate">{`↓ ${formatRate(traffic.rx_bps)} ↑ ${formatRate(traffic.tx_bps)}`}</span>;
}

/**
 * One device and the outbound it uses. The device list comes again whenever
 * a device comes, goes or changes; a row redraws only when something it
 * shows has changed, and its speeds redraw on their own.
 */
const DeviceRow = memo(function DeviceRow({ mac, name, address, showRate, listed, own, group, config, choices, onPick }: DeviceRowProps) {
  const ownOff = own !== "" && !choices.some((e) => e.id === own);
  return (
    <li className="device-row">
      <span className="device-row-name" title={mac}>
        {name}
      </span>
      {address && <AddressChip address={address} small />}
      {showRate && <DeviceRowRate mac={mac} listed={listed} />}
      <select aria-label={`Outbound for ${name}`} value={own} onChange={(e) => onPick(mac, e.target.value)}>
        <option value="">Like the rest ({egressLabel(config, inheritedEgress(config, group))})</option>
        {ownOff && <option value={own}>{egressLabel(config, own)} (off)</option>}
        {choices.map((e) => (
          <option key={e.id} value={e.id}>
            {egressName(e)}
          </option>
        ))}
      </select>
    </li>
  );
});

/** The routing state as the user sees it, before the service has said anything. */
function routingState(config: Config, routing: RoutingStatus | undefined): RoutingStatus["state"] {
  if (routing) return routing.state;
  return config.network.transparent_routing ? "waiting" : "off";
}

/**
 * The packets the capture had to drop since outbounds began to apply, a
 * running total like the packets taken beside it: short for the banner and
 * in full for its tooltip. Null when none were.
 */
function droppedInWords(dropped: number | null | undefined): { short: string; full: string } | null {
  if (!dropped || dropped <= 0) return null;
  const count = dropped.toLocaleString();
  const packets = dropped === 1 ? "1 packet was" : `${count} packets were`;
  return {
    short: `${count} dropped so far`,
    full: `${packets} dropped since outbounds began to apply, because Captun could not keep up. This happens when devices send more at once than this computer can handle.`,
  };
}

/**
 * Home's device list: one outbound for every device, any device on its own,
 * and, above all, whether those choices apply right now. They only do while
 * Captun carries the devices' traffic itself; until then devices use this
 * computer's internet directly, and the panel says so plainly.
 */
export function DeviceOutbounds() {
  const { config, saveConfig, saveClient } = useServiceCore();
  const clients = useClients();
  const status = useServiceStatus();
  const nav = useNav();
  // A pick finds its device in the latest list, so rows get the same handler
  // on every refresh and those that did not change keep still.
  const latest = useRef({ config, clients });
  latest.current = { config, clients };
  const setDevice = useCallback(
    (mac: string, id: string) => {
      const now = latest.current;
      const c = now.clients.find((x) => x.mac === mac);
      if (!now.config || !c) return;
      void saveClient(
        { ...profileFor(now.config, c), egress: id === "" ? undefined : id },
        id === "" ? `${deviceName(c)} goes out like the rest` : `${deviceName(c)} now goes out through ${egressLabel(now.config, id)}`,
      );
    },
    [saveClient],
  );
  const choices = useMemo(() => (config ? usableEgresses(config) : []), [config]);
  if (!config) return null;

  const devices = clients.filter((c) => c.online && c.state !== "blocked");
  const routing = status?.routing;
  const state = routingState(config, routing);
  // Said only when some were lost.
  const dropped = droppedInWords(routing?.dropped_packets);
  const applied = state === "active";
  const defaultId = config.network.default_egress;

  const setRouting = (on: boolean) =>
    void saveConfig(
      (c) => {
        c.network.transparent_routing = on;
      },
      on ? "Outbounds turned on" : "Outbounds turned off: devices use this computer's internet",
    );
  // Saving re-applies routing, which is how a failed start is retried.
  const retry = () => void saveConfig(() => undefined, "Trying again");

  const setDefault = (id: string) =>
    void saveConfig((c) => {
      c.network.default_egress = id;
    }, `Devices now go out through ${egressLabel(config, id)}`);

  let banner: ReactNode;
  switch (state) {
    case "off":
      banner = (
        <div className="routing routing-off" title="Turn on to send each device out the way chosen here, see its traffic, and cut it off when that way stops working (experimental).">
          <CircleAlert size={14} aria-hidden="true" />
          <span className="routing-text">
            <strong>Outbounds are off:</strong> devices use this computer's internet directly.
          </span>
          <button className="button button-primary button-small" onClick={() => setRouting(true)}>
            Turn on
          </button>
        </div>
      );
      break;
    case "waiting":
      banner = (
        <div className="routing routing-waiting">
          <Info size={14} aria-hidden="true" />
          <span className="routing-text">
            <strong>Outbounds are on:</strong> they apply once sharing starts.
          </span>
          <button className="link-button" onClick={() => setRouting(false)}>
            Turn off
          </button>
        </div>
      );
      break;
    case "active":
      banner = (
        <div
          className="routing routing-active"
          title={
            dropped
              ? dropped.full
              : routing?.captured_packets === 0
                ? "No packets yet: if this stays at 0 while a device browses, Captun is not seeing its traffic."
                : undefined
          }
        >
          <CircleCheck size={14} aria-hidden="true" />
          <span className="routing-text">
            <strong>Outbounds apply now</strong>
            {routing?.captured_packets != null && ` · ${routing.captured_packets.toLocaleString()} packets`}
            {dropped && <span className="routing-warn"> · {dropped.short}</span>}
          </span>
          <button className="link-button" onClick={() => setRouting(false)}>
            Turn off
          </button>
        </div>
      );
      break;
    case "failed":
      banner = (
        <div className="routing routing-failed" role="alert" title={routing?.error ?? undefined}>
          <CircleX size={14} aria-hidden="true" />
          <span className="routing-text">
            <strong>Outbounds failed:</strong> {routing?.error ?? "unknown error"}
          </span>
          <button className="button button-small" onClick={retry}>
            Try again
          </button>
          <button className="link-button" onClick={() => setRouting(false)}>
            Turn off
          </button>
        </div>
      );
      break;
    case "unsupported":
      banner = (
        <div className="routing routing-waiting">
          <Info size={14} aria-hidden="true" />
          <span className="routing-text">This system cannot send devices out one by one yet.</span>
        </div>
      );
      break;
  }

  return (
    <section className="devices-panel" aria-labelledby="devices-heading">
      <header className="devices-head">
        <h2 id="devices-heading">Devices</h2>
        <span className="devices-count">{devices.length}</span>
        <label className="out-via">
          <Route size={13} aria-hidden="true" />
          <span>Out via</span>
          <select aria-label="Outbound for all devices" value={defaultId} onChange={(e) => setDefault(e.target.value)}>
            {!choices.some((e) => e.id === defaultId) && <option value={defaultId}>{egressLabel(config, defaultId)}</option>}
            {choices.map((e) => (
              <option key={e.id} value={e.id}>
                {egressName(e)}
              </option>
            ))}
          </select>
        </label>
        <button className="link-button section-link" onClick={() => nav("clients")} aria-label="All devices" title="All devices">
          <ChevronRight size={15} aria-hidden="true" />
        </button>
      </header>

      {banner}

      {devices.length > 0 ? (
        <ul className="device-rows">
          {devices.map((c) => (
            <DeviceRow
              key={c.mac}
              mac={c.mac}
              name={deviceName(c)}
              address={deviceAddress(c)}
              showRate={applied}
              listed={c.traffic}
              own={c.egress ?? ""}
              group={c.group}
              config={config}
              choices={choices}
              onPick={setDevice}
            />
          ))}
        </ul>
      ) : (
        <p className="devices-empty">
          Devices appear here as they join; each can go out its own way.
          {choices.length <= 1 && (
            <>
              {" "}
              <button className="link-button" onClick={() => nav("egresses")}>
                Add a proxy or VPN link
              </button>
            </>
          )}
        </p>
      )}
    </section>
  );
}
