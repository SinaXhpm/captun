// This computer as the GUI sees it: starting the service, and what the
// hardware offers (Wi-Fi hotspot support, network adapters).

import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { useInterval } from "./hooks";
import type { HotspotSupport, InterfaceInfo } from "./types";

const CONNECT_TIMEOUT_MS = 30_000;
const CONNECT_POLL_MS = 500;
const SUPPORT_POLL_MS = 15_000;
const ADAPTER_POLL_MS = 5_000;

/** Waits until the GUI is connected. Settings saved on this computer reach the
 *  service before the connection is reported, so a refusal shows up here. */
async function waitForConnection(): Promise<void> {
  const deadline = Date.now() + CONNECT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const status = await api.connectionStatus();
    if (status.connected) {
      if (status.config_sync_error) throw new Error(status.config_sync_error);
      return;
    }
    await new Promise((resolve) => window.setTimeout(resolve, CONNECT_POLL_MS));
  }
  throw new Error("The Captun service did not come up in time. Try again, or check that it was allowed to start.");
}

export async function serviceRunning(): Promise<boolean> {
  return (await api.connectionStatus().catch(() => null))?.connected ?? false;
}

export const PLATFORM: "windows" | "mac" | "linux" = /Windows/.test(navigator.userAgent)
  ? "windows"
  : /Mac/.test(navigator.userAgent)
    ? "mac"
    : "linux";

/** What the system asks before Captun may change network settings. */
export const ADMIN_PROMPT = {
  windows: { during: "approve the Windows prompt", before: "Windows may ask for permission." },
  mac: { during: "enter your Mac password when asked", before: "macOS asks for your password." },
  linux: { during: "enter your password when asked", before: "The system may ask for your password." },
}[PLATFORM];

/** Starts the service (the system asks for permission) and waits for it. */
export async function startServiceAndWait(): Promise<void> {
  await api.startService();
  await waitForConnection();
}

const STOP_TIMEOUT_MS = 15_000;

/**
 * Stops the running service and starts it again (the system asks for
 * permission), for example so a newer copy of Captun takes over.
 */
export async function restartServiceAndWait(): Promise<void> {
  try {
    await api.stopService();
  } catch {
    throw new Error(
      "This copy of the Captun service is too old to restart from here. End captun-daemon.exe in Task Manager, then press Start on Home.",
    );
  }
  const deadline = Date.now() + STOP_TIMEOUT_MS;
  while (await serviceRunning()) {
    if (Date.now() > deadline) throw new Error("The Captun service did not stop in time.");
    await new Promise((resolve) => window.setTimeout(resolve, CONNECT_POLL_MS));
  }
  await startServiceAndWait();
}

/**
 * Whether this computer can host a Wi-Fi hotspot, re-checked now and then so
 * turning Wi-Fi on is noticed. `null` until the first answer.
 */
export function useHotspotSupport(): HotspotSupport | null {
  const [support, setSupport] = useState<HotspotSupport | null>(null);
  const check = () => void api.hotspotSupport().then(setSupport, () => undefined);
  useEffect(check, []);
  useInterval(check, SUPPORT_POLL_MS, true);
  return support;
}

/**
 * This computer's network adapters, refreshed every few seconds so a phone
 * plugged in for USB tethering shows up. Listed by the service when it runs
 * (it knows which one carries the hotspot), otherwise locally. `null` until
 * the first answer.
 */
export function useAdapters(): { adapters: InterfaceInfo[] | null; refresh: () => void } {
  const [adapters, setAdapters] = useState<InterfaceInfo[] | null>(null);
  const refresh = useCallback(() => void api.listInterfaces().then(setAdapters, () => undefined), []);
  useEffect(refresh, [refresh]);
  useInterval(refresh, ADAPTER_POLL_MS, true);
  return { adapters, refresh };
}
