import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, errorMessage } from "./api";
import { useToast } from "./components/Toast";
import { useConnectionEvent, useInterval, useIpcEvent } from "./hooks";
import type {
  ClientProfile,
  ClientView,
  Config,
  ConnectionStatus,
  DeviceTraffic,
  DnsQueryBatch,
  DnsQueryLog,
  ListStatus,
  ListsProgress,
  MacAddr,
  ServiceStatus,
} from "./types";

const DNS_LOG_LIMIT = 500;
const STATUS_POLL_MS = 5000;
/** How often the lists are asked about while an update runs, in case an event went missing. */
const LISTS_POLL_MS = 5000;

/**
 * The connection, the config and the actions: the parts that change only now
 * and then. The status (polled every few seconds), the device list (sent when
 * a device comes, goes or changes) and the devices' speeds (sent every second)
 * have contexts of their own, so a page that does not show them does not
 * redraw for them.
 */
interface ServiceCore {
  connection: ConnectionStatus | null;
  connected: boolean;
  config: Config | null;
  refreshStatus: () => Promise<void>;
  refreshConfig: () => Promise<void>;
  /**
   * Re-reads the config, applies `mutate` to a copy and sends it back, so a
   * section editor never overwrites changes made elsewhere in the meantime.
   */
  saveConfig: (mutate: (draft: Config) => void, success?: string) => Promise<boolean>;
  saveClient: (profile: ClientProfile, success?: string) => Promise<boolean>;
  /** Runs an action and reports failure (and optionally success) as a toast. */
  run: (action: () => Promise<unknown>, failure: string, success?: string) => Promise<boolean>;
}

interface ServiceContextValue extends ServiceCore {
  status: ServiceStatus | null;
  clients: ClientView[];
}

const CoreContext = createContext<ServiceCore | null>(null);
// `undefined` means no provider: `null` is a real value (no status yet).
const StatusContext = createContext<ServiceStatus | null | undefined>(undefined);
const ClientsContext = createContext<ClientView[] | null>(null);

export function ServiceProvider({ children }: { children: ReactNode }) {
  const toast = useToast();
  const [connection, setConnection] = useState<ConnectionStatus | null>(null);
  const [status, setStatus] = useState<ServiceStatus | null>(null);
  const [clients, setClients] = useState<ClientView[]>([]);
  const [config, setConfig] = useState<Config | null>(null);
  const connected = connection?.connected ?? false;

  useEffect(() => {
    api.connectionStatus().then(setConnection, () => undefined);
  }, []);
  useConnectionEvent(setConnection);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api.getStatus());
    } catch {
      // The connection banner already explains outages; polling stays quiet.
    }
  }, []);

  const refreshConfig = useCallback(async () => {
    try {
      setConfig(await api.getConfig());
    } catch (e) {
      toast.error("Could not load the configuration", errorMessage(e));
    }
  }, [toast]);

  // The config is always available: from the service, or from the copy saved
  // on this computer while the service is not running.
  useEffect(() => {
    void refreshConfig();
    if (!connected) {
      setStatus(null);
      setClients([]);
      return;
    }
    void refreshStatus();
    void api.listClients().then(setClients, () => undefined);
  }, [connected, refreshStatus, refreshConfig]);

  useInterval(() => void refreshStatus(), STATUS_POLL_MS, connected);

  useIpcEvent((event) => {
    switch (event.kind) {
      case "clients":
        setClients(event.data);
        break;
      case "traffic":
        // The speeds have a context of their own (TrafficProvider).
        break;
      case "hotspot":
        setStatus((s) => (s ? { ...s, hotspot: event.data } : s));
        break;
      case "xray":
        setStatus((s) => (s ? { ...s, xray: event.data } : s));
        break;
      case "config_changed":
        void refreshConfig();
        break;
      case "dns_queries":
        // The lookup log listens for these itself (DnsLogProvider).
        break;
      case "lists":
        // So do the online lists (ListsProvider).
        break;
    }
  });

  const run = useCallback(
    async (action: () => Promise<unknown>, failure: string, success?: string) => {
      try {
        await action();
        if (success) toast.success(success);
        return true;
      } catch (e) {
        toast.error(failure, errorMessage(e));
        return false;
      }
    },
    [toast],
  );

  // Saves run one after another: each reads the settings the one before left,
  // so two quick changes never undo each other.
  const saves = useRef<Promise<unknown>>(Promise.resolve());
  const saveConfig = useCallback(
    (mutate: (draft: Config) => void, success = "Settings saved") => {
      const save = saves.current.then(() =>
        run(
          async () => {
            const draft = structuredClone(await api.getConfig());
            mutate(draft);
            await api.setConfig(draft);
            setConfig(draft);
          },
          "Could not save settings",
          connected ? success : "Saved. It takes effect when sharing starts.",
        ),
      );
      saves.current = save;
      return save;
    },
    [run, connected],
  );

  const saveClient = useCallback(
    async (profile: ClientProfile, success?: string) => {
      const ok = await run(() => api.setClientProfile(profile), "Could not update the device", success);
      if (ok) void refreshConfig();
      return ok;
    },
    [run, refreshConfig],
  );

  const core = useMemo<ServiceCore>(
    () => ({ connection, connected, config, refreshStatus, refreshConfig, saveConfig, saveClient, run }),
    [connection, connected, config, refreshStatus, refreshConfig, saveConfig, saveClient, run],
  );

  return (
    <CoreContext.Provider value={core}>
      <StatusContext.Provider value={status}>
        <ClientsContext.Provider value={clients}>
          <TrafficProvider connected={connected}>
            <DnsLogProvider>
              <ListsProvider>{children}</ListsProvider>
            </DnsLogProvider>
          </TrafficProvider>
        </ClientsContext.Provider>
      </StatusContext.Provider>
    </CoreContext.Provider>
  );
}

/** The connection, the config and the actions; does not redraw for status polls or device-list updates. */
export function useServiceCore(): ServiceCore {
  const ctx = useContext(CoreContext);
  if (!ctx) throw new Error("useServiceCore must be used inside <ServiceProvider>");
  return ctx;
}

/** The service's status; `null` while it is not running or has not answered yet. */
export function useServiceStatus(): ServiceStatus | null {
  const ctx = useContext(StatusContext);
  if (ctx === undefined) throw new Error("useServiceStatus must be used inside <ServiceProvider>");
  return ctx;
}

/**
 * Every device the service knows, sent again whenever one comes, goes or
 * changes. Its speeds there are those of when it was sent: `useDeviceTraffic`
 * has them current.
 */
export function useClients(): ClientView[] {
  const ctx = useContext(ClientsContext);
  if (!ctx) throw new Error("useClients must be used inside <ServiceProvider>");
  return ctx;
}

/**
 * Everything at once. A component using it redraws for every status poll and
 * device-list update; one that needs less should use the hooks above.
 */
export function useService(): ServiceContextValue {
  const core = useServiceCore();
  const status = useServiceStatus();
  const clients = useClients();
  return useMemo(() => ({ ...core, status, clients }), [core, status, clients]);
}

// ---- Device speeds ----------------------------------------------------------

const NO_TRAFFIC: ReadonlyMap<MacAddr, DeviceTraffic> = new Map();
const TrafficContext = createContext<ReadonlyMap<MacAddr, DeviceTraffic> | null>(null);

/**
 * Each device's traffic by its MAC, kept apart from the device list: the
 * service sends it every second while it changes, and only the cells that
 * show it redraw for it.
 */
function TrafficProvider({ connected, children }: { connected: boolean; children: ReactNode }) {
  const [traffic, setTraffic] = useState<ReadonlyMap<MacAddr, DeviceTraffic>>(NO_TRAFFIC);

  useEffect(() => {
    if (!connected) setTraffic(NO_TRAFFIC);
  }, [connected]);

  useIpcEvent((event) => {
    if (event.kind !== "traffic") return;
    // Each report holds every online device that has had traffic.
    setTraffic(new Map(event.data.map((device) => [device.mac, device])));
  });

  return <TrafficContext.Provider value={traffic}>{children}</TrafficContext.Provider>;
}

/**
 * A device's traffic as the service last sent it; `undefined` until it sends
 * some for that device. A component using it redraws every second, so keep
 * it to the cells that show speeds.
 */
export function useDeviceTraffic(mac: MacAddr): DeviceTraffic | undefined {
  const ctx = useContext(TrafficContext);
  if (!ctx) throw new Error("useDeviceTraffic must be used inside <ServiceProvider>");
  return ctx.get(mac);
}

// ---- Lookup log -------------------------------------------------------------

interface DnsLogValue {
  /** Newest first, at most DNS_LOG_LIMIT. */
  entries: DnsQueryLog[];
  /** Lookups that never reached the log because too many came at once, since it was last cleared. */
  dropped: number;
  clear: () => void;
}

const DnsLogContext = createContext<DnsLogValue | null>(null);

/**
 * The log with a batch (oldest first) put on top, newest first, keeping the
 * newest DNS_LOG_LIMIT. Only what can be shown is copied, however big the batch.
 */
function addToDnsLog(log: DnsQueryLog[], batch: DnsQueryBatch): DnsQueryLog[] {
  if (batch.entries.length === 0) return log;
  return [...batch.entries.slice(-DNS_LOG_LIMIT).reverse(), ...log].slice(0, DNS_LOG_LIMIT);
}

/** Lookups of a batch that never reach the log: left out on the way, or more than it holds. */
function unseenLookups(batch: DnsQueryBatch): number {
  return batch.dropped + Math.max(0, batch.entries.length - DNS_LOG_LIMIT);
}

/**
 * The live lookup log, kept apart from the rest of the service's state:
 * batches of lookups arrive a few times a second, and only the log needs to
 * redraw for them.
 */
function DnsLogProvider({ children }: { children: ReactNode }) {
  const [entries, setEntries] = useState<DnsQueryLog[]>([]);
  const [dropped, setDropped] = useState(0);

  useIpcEvent((event) => {
    if (event.kind !== "dns_queries") return;
    const batch = event.data;
    if (batch.entries.length > 0) setEntries((log) => addToDnsLog(log, batch));
    const unseen = unseenLookups(batch);
    if (unseen > 0) setDropped((n) => n + unseen);
  });

  const clear = useCallback(() => {
    setEntries([]);
    setDropped(0);
  }, []);
  const value = useMemo<DnsLogValue>(() => ({ entries, dropped, clear }), [entries, dropped, clear]);

  return <DnsLogContext.Provider value={value}>{children}</DnsLogContext.Provider>;
}

/** The lookup log; only the DNS page's log reads it, so nothing else redraws for lookups. */
export function useDnsLog(): DnsLogValue {
  const ctx = useContext(DnsLogContext);
  if (!ctx) throw new Error("useDnsLog must be used inside <ServiceProvider>");
  return ctx;
}

// ---- Online lists -----------------------------------------------------------

const NO_LISTS: ListsProgress = { updating: false, done: 0, total: 0, lists: [] };

interface ListsValue {
  /** How each online list the rules use stands, and how far an update is. */
  progress: ListsProgress;
  /**
   * Starts downloading every list again, through `through`. Done once the
   * service has answered, which it does at once; how the update ends is told
   * in a toast, wherever the user is by then.
   */
  update: (through: string) => Promise<void>;
}

const ListsContext = createContext<ListsValue | null>(null);

/** Tells what an update the user started came to, by how the lists stand after it. */
function reportLists(toast: ReturnType<typeof useToast>, lists: ListStatus[]) {
  const failed = lists.filter((l) => l.error);
  if (failed.length === 0) toast.success("Lists updated");
  else
    toast.error(
      failed.length === lists.length ? "No list could be downloaded" : `${failed.length} of ${lists.length} lists could not be downloaded`,
      failed[0]?.error ?? "",
    );
}

/**
 * The online lists, kept above the pages: the service downloads them in the
 * background, one after another, which can take minutes, and the Rules page
 * may be left and opened again meanwhile. Lists are downloaded only when
 * `update` is called; asking how they stand downloads nothing.
 */
function ListsProvider({ children }: { children: ReactNode }) {
  const { connected, config } = useServiceCore();
  const toast = useToast();
  const [progress, setProgress] = useState<ListsProgress>(NO_LISTS);
  // Answers and events come by different ways, so an answer can arrive after
  // newer news: it is used only if nothing came in since it was asked for.
  const received = useRef(0);
  // An update the user started: asked for, then seen under way, then seen
  // over, when what it came to is told once.
  const started = useRef<"no" | "asked" | "running">("no");

  const receive = useCallback(
    (next: ListsProgress) => {
      received.current += 1;
      setProgress(next);
      if (next.updating) {
        if (started.current === "asked") started.current = "running";
      } else if (started.current === "running") {
        started.current = "no";
        reportLists(toast, next.lists);
      }
    },
    [toast],
  );

  const ask = useCallback(
    async (question: () => Promise<ListsProgress>) => {
      const asked = received.current;
      const next = await question();
      if (received.current === asked) receive(next);
    },
    [receive],
  );

  useIpcEvent((event) => {
    if (event.kind === "lists") receive(event.data);
  });

  // Again whenever the rules name other lists, or the service comes or goes.
  const links = (config?.rule ?? []).flatMap((r) => r.lists ?? []).join("\n");
  useEffect(() => {
    if (!connected) {
      // Whatever is still on its way is about the service that went.
      received.current += 1;
      started.current = "no";
      setProgress(NO_LISTS);
      return;
    }
    ask(api.getLists).catch(() => undefined);
  }, [connected, links, ask]);

  // A busy connection may drop an event: while an update runs, asking now
  // and then makes sure its end is seen.
  useInterval(() => void ask(api.getLists).catch(() => undefined), LISTS_POLL_MS, connected && progress.updating);

  const update = useCallback(
    async (through: string) => {
      started.current = "asked";
      try {
        await ask(() => api.updateLists(through));
      } catch (e) {
        started.current = "no";
        toast.error("Lists not updated", errorMessage(e));
      }
    },
    [ask, toast],
  );

  const value = useMemo<ListsValue>(() => ({ progress, update }), [progress, update]);
  return <ListsContext.Provider value={value}>{children}</ListsContext.Provider>;
}

/** The online lists and the way to update them; only the Rules page reads them. */
export function useLists(): ListsValue {
  const ctx = useContext(ListsContext);
  if (!ctx) throw new Error("useLists must be used inside <ServiceProvider>");
  return ctx;
}
