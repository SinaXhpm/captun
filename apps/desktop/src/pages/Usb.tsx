import { useCallback, useEffect, useState } from "react";
import { CircleHelp, Info, Usb } from "lucide-react";
import { api, errorMessage } from "../api";
import { Modal } from "../components/Modal";
import { useToast } from "../components/Toast";
import { useInterval } from "../hooks";
import { useServiceCore, useServiceStatus } from "../service";
import { ADMIN_PROMPT, PLATFORM, serviceRunning, startServiceAndWait } from "../system";
import type { AdbDeviceInfo } from "../types";
import type { ShareMode } from "./share";

const SCAN_POLL_MS = 3000;

type Phase = "service" | "phone" | "start" | "stop";

const PHASE_TEXT: Record<Phase, string> = {
  service: `Starting Captun… ${ADMIN_PROMPT.during}`,
  phone: "Looking for the phone…",
  start: "Setting up the USB tunnel… tap Allow on the phone if it asks",
  stop: "Stopping…",
};

/** One line on how a phone is doing, saying what to do when it is stuck. */
function phoneLine(d: AdbDeviceInfo): string {
  switch (d.state) {
    case "device":
      return `${d.label} is ready`;
    case "unauthorized":
      return `${d.label}: unlock it and tap Allow on the phone`;
    case "offline":
      return `${d.label}: plug the cable in again`;
    case "no_permissions":
      return PLATFORM === "windows"
        ? `${d.label}: install the phone's USB driver ("Android ADB Interface")`
        : `${d.label}: this computer does not allow access to the phone yet (on Linux, add a udev rule for it)`;
    default:
      return `${d.label}: ${d.state}`;
  }
}

/** Why Start found no phone to use, in words that say what to do next. */
function noPhoneReason(list: AdbDeviceInfo[], ready: AdbDeviceInfo[]): string {
  if (ready.length > 1) return "More than one phone is connected. Pick one, then press Start.";
  const stuck = list[0];
  if (stuck) return `${phoneLine(stuck)}, then press Start again.`;
  return "No phone found. Check the cable and that USB debugging is on, then press Start again.";
}

/**
 * Reverse USB tethering as Home's big button drives it: the phone gets this
 * computer's internet over a USB cable, through Captun's own tunnel (the
 * built-in adb points the phone's proxy at Captun on the USB link). Nothing
 * is installed on the phone. Captun only gives internet: the computer never
 * uses the phone's.
 */
export function useUsb(): ShareMode {
  const { connected, refreshStatus } = useServiceCore();
  const status = useServiceStatus();
  const toast = useToast();
  const [devices, setDevices] = useState<AdbDeviceInfo[] | null>(null);
  const [picked, setPicked] = useState("");
  const [phase, setPhase] = useState<Phase | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [caution, setCaution] = useState<string | null>(null);
  const [help, setHelp] = useState(false);
  const session = status?.tether.reverse ?? null;

  const scan = useCallback(async () => {
    const list = await api.listAdbDevices();
    setDevices(list);
    return list;
  }, []);

  // Keep the list fresh while waiting for a phone to be plugged in.
  useEffect(() => {
    if (connected) void scan().catch(() => undefined);
  }, [connected, scan]);
  useInterval(() => void scan().catch(() => undefined), SCAN_POLL_MS, connected && !session && phase === null);

  const ready = (devices ?? []).filter((d) => d.ready);
  const choose = (list: AdbDeviceInfo[]) => list.find((d) => d.serial === picked) ?? (list.length === 1 ? list[0] : undefined);
  const phone = session ? devices?.find((d) => d.serial === session.serial) : (choose(ready) ?? devices?.[0]);

  const start = async () => {
    setError(null);
    try {
      if (!(await serviceRunning())) {
        setPhase("service");
        await startServiceAndWait();
      }
      setPhase("phone");
      const list = await scan();
      const readyNow = list.filter((d) => d.ready);
      const target = choose(readyNow);
      if (!target) throw new Error(noPhoneReason(list, readyNow));
      setPhase("start");
      const out = await api.setReverseTether(target.serial, true, "system_proxy");
      toast.success("The phone is online", out.message);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setPhase(null);
      await refreshStatus();
    }
  };

  const stop = async () => {
    if (!session) return;
    setPhase("stop");
    setError(null);
    try {
      const out = await api.setReverseTether(session.serial, false, "system_proxy");
      setCaution(out.caution ?? null);
      toast.success(out.message);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setPhase(null);
      await refreshStatus();
    }
  };

  const overlay = (
    <>
      {caution && (
        <Modal
          title="Before you unplug"
          onClose={() => setCaution(null)}
          footer={
            <button className="button button-primary" onClick={() => setCaution(null)}>
              Got it
            </button>
          }
        >
          <p className="caution-text">{caution}</p>
        </Modal>
      )}
      {help && (
        <Modal
          title="Share with a phone over USB"
          onClose={() => setHelp(false)}
          footer={
            <button className="button button-primary" onClick={() => setHelp(false)}>
              OK
            </button>
          }
        >
          <ol className="steps">
            <li>
              On the phone, turn on <strong>USB debugging</strong> (Settings → Developer options).
            </li>
            <li>Connect it to this computer with a USB cable.</li>
            <li>
              Press <strong>Start</strong>. The first time, tap <strong>Allow</strong> on the phone.
            </li>
          </ol>
          <p className="muted small">
            This computer's internet goes to the phone; the computer never uses the phone's. Nothing is installed on the phone. Web and apps work; games
            and calls (UDP) don't yet.
          </p>
        </Modal>
      )}
    </>
  );

  const base = { id: "usb" as const, label: "USB to phone", icon: Usb, overlay };
  if (phase) {
    return { ...base, phase: "busy", active: true, action: null, status: PHASE_TEXT[phase] };
  }
  if (session) {
    return {
      ...base,
      phase: "on",
      active: true,
      action: { label: "Stop", run: () => void stop() },
      status: `Sharing with ${phone?.label ?? session.serial} over USB`,
      detail: (
        <span className="hero-note">
          <Info size={13} aria-hidden="true" /> Web and apps work; games and calls (UDP) don't in this mode.
        </span>
      ),
    };
  }
  const statusLine = !connected
    ? "Connect a phone by USB, then press Start"
    : phone
      ? phoneLine(phone)
      : devices === null
        ? "Looking for phones…"
        : "No phone connected yet";
  return {
    ...base,
    phase: error ? "error" : "off",
    active: false,
    action: { label: error ? "Try again" : "Start", hint: ADMIN_PROMPT.before, run: () => void start() },
    status: error ? "The phone did not get online" : statusLine,
    detail: error ? (
      <span className="hero-problem">{error}</span>
    ) : (devices?.length ?? 0) > 1 ? (
      <select aria-label="Phone" value={phone?.serial ?? ""} onChange={(e) => setPicked(e.target.value)}>
        {devices?.map((d) => (
          <option key={d.serial} value={d.serial}>
            {phoneLine(d)}
          </option>
        ))}
      </select>
    ) : undefined,
    links: (
      <button className="link-button" onClick={() => setHelp(true)}>
        <CircleHelp size={13} aria-hidden="true" /> How to connect
      </button>
    ),
  };
}
