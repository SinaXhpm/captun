import { useEffect, useRef } from "react";
import type { UnlistenFn } from "@tauri-apps/api/event";
import { onConnection, onIpcEvent } from "./api";
import type { ConnectionStatus, IpcEvent } from "./types";

/**
 * Subscribes to a Tauri event for the component's lifetime. The latest
 * handler is kept in a ref so callers can pass inline closures without
 * resubscribing on every render.
 */
function useTauriEvent<T>(subscribe: (handler: (payload: T) => void) => Promise<UnlistenFn>, handler: (payload: T) => void) {
  const latest = useRef(handler);
  latest.current = handler;

  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    let cancelled = false;
    void subscribe((payload) => latest.current(payload)).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [subscribe]);
}

/** Every event the service pushes (clients, hotspot, DNS queries …). */
export function useIpcEvent(handler: (event: IpcEvent) => void) {
  useTauriEvent(onIpcEvent, handler);
}

/** Connection state changes of the GUI ↔ service link. */
export function useConnectionEvent(handler: (status: ConnectionStatus) => void) {
  useTauriEvent(onConnection, handler);
}

/** Runs `tick` every `ms` while `active` is true. */
export function useInterval(tick: () => void, ms: number, active = true) {
  const latest = useRef(tick);
  latest.current = tick;
  useEffect(() => {
    if (!active) return;
    const id = window.setInterval(() => latest.current(), ms);
    return () => window.clearInterval(id);
  }, [ms, active]);
}
