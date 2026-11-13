import { useEffect, useMemo, useRef, useState, type ComponentType, type KeyboardEvent } from "react";
import {
  BarChart3,
  ChevronDown,
  Globe,
  House,
  ListOrdered,
  Route,
  Settings as SettingsIcon,
  Users,
  type LucideProps,
} from "lucide-react";
import { AboutDialog } from "./components/AboutDialog";
import { ConnectionBanner } from "./components/ConnectionBanner";
import { WindowControls } from "./components/WindowControls";
import { NavContext, type PageId } from "./nav";
import { useClients, useServiceStatus } from "./service";
import { PLATFORM } from "./system";
import { Clients } from "./pages/Clients";
import { Dns } from "./pages/Dns";
import { Egresses } from "./pages/Egresses";
import { Home } from "./pages/Home";
import { Rules } from "./pages/Rules";
import { Usage } from "./pages/Usage";
import { Settings } from "./pages/Settings";

interface Page {
  id: PageId;
  label: string;
  icon: ComponentType<LucideProps>;
  view: ComponentType;
}

/** Always in the top bar. */
const MAIN: Page[] = [
  { id: "home", label: "Home", icon: House, view: Home },
  { id: "clients", label: "Devices", icon: Users, view: Clients },
  { id: "usage", label: "Usage", icon: BarChart3, view: Usage },
  { id: "egresses", label: "Outbound", icon: Route, view: Egresses },
];

/** Under "More": set up once, visited rarely. */
const MORE: Page[] = [
  { id: "rules", label: "Rules", icon: ListOrdered, view: Rules },
  { id: "dns", label: "DNS", icon: Globe, view: Dns },
  { id: "settings", label: "Settings", icon: SettingsIcon, view: Settings },
];

/** What the top bar says about sharing, in a few words. */
function sharingLine(on: boolean, devices: number): string {
  return on ? `Sharing · ${devices} device${devices === 1 ? "" : "s"}` : "Not sharing";
}

/** The "More" menu: a button that opens a short list of the rarer pages. */
function MoreMenu({ page, onPick }: { page: PageId; onPick: (page: PageId) => void }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const current = MORE.find((p) => p.id === page);

  useEffect(() => {
    if (!open) return;
    const outside = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", outside);
    root.current?.querySelector<HTMLButtonElement>('[role="menuitem"]')?.focus();
    return () => document.removeEventListener("mousedown", outside);
  }, [open]);

  const onKey = (e: KeyboardEvent) => {
    const items = [...(root.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? [])];
    const at = items.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "Escape") {
      setOpen(false);
      button.current?.focus();
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const next = (at + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length;
      items[next]?.focus();
    }
  };

  return (
    <div className="more" ref={root} onKeyDown={onKey}>
      <button
        ref={button}
        className="topnav-item"
        title={current ? `${current.label} · more pages` : "More pages"}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-current={current ? "page" : undefined}
        onClick={() => setOpen((o) => !o)}
      >
        {current ? <current.icon size={15} aria-hidden="true" /> : <SettingsIcon size={15} aria-hidden="true" />}
        <span className="topnav-label">{current?.label ?? "More"}</span>
        <ChevronDown size={13} aria-hidden="true" />
      </button>
      {open && (
        <div className="more-menu" role="menu" aria-label="More pages">
          {MORE.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              role="menuitem"
              className="more-item"
              aria-current={page === id ? "page" : undefined}
              onClick={() => {
                setOpen(false);
                onPick(id);
              }}
            >
              <Icon size={15} aria-hidden="true" />
              {label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function App() {
  const [page, setPage] = useState<PageId>("home");
  const [about, setAbout] = useState(false);
  const clients = useClients();
  const status = useServiceStatus();
  const pending = clients.filter((c) => c.online && c.state === "pending").length;
  const current = [...MAIN, ...MORE].find((p) => p.id === page) ?? MAIN[0];
  const View = current?.view ?? Home;
  // The same element on every redraw of the top bar, whose badge and status
  // line change often: the page then redraws only for what it reads itself
  // (a page that never shows the status skips its polls, see service.tsx).
  const view = useMemo(() => <View />, [View]);
  const sharing = status?.hotspot.state === "running" || !!status?.tether.reverse || (status?.access_network.running ?? false);
  const online = clients.filter((c) => c.online).length;

  return (
    <NavContext.Provider value={setPage}>
      <div className="app">
        {/* The app draws its own title bar: drag it by any empty part. On macOS
            the system traffic lights sit at its left edge. */}
        <header className={PLATFORM === "mac" ? "topbar topbar-mac" : "topbar"} data-tauri-drag-region>
          <button className="brand" onClick={() => setAbout(true)} aria-label="About Captun" title="About Captun">
            {/* The helm drawn for this small size, so its spokes and handles stay crisp. */}
            <img className="brand-mark" src="/logo-24.png" srcSet="/logo-24.png 1x, /logo-32.png 1.33x, /logo-48.png 2x" alt="" />
            <span className="brand-text">Captun</span>
          </button>
          <nav className="topnav" aria-label="Main">
            {/* In a narrow window only the open page shows its name: the
                others keep theirs for screen readers, and the title gives a
                hover hint. */}
            {MAIN.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                className="topnav-item"
                title={id === "clients" && pending > 0 ? `${label} · ${pending} waiting for approval` : label}
                aria-current={page === id ? "page" : undefined}
                onClick={() => setPage(id)}
              >
                <Icon size={15} aria-hidden="true" />
                <span className="topnav-label">{label}</span>
                {id === "clients" && pending > 0 && (
                  <span className="nav-badge" aria-label={`${pending} waiting for approval`}>
                    {pending}
                  </span>
                )}
              </button>
            ))}
            <MoreMenu page={page} onPick={setPage} />
          </nav>
          <div className="topbar-fill" data-tauri-drag-region />
          <span className={sharing ? "topbar-status topbar-status-on" : "topbar-status"} title={sharingLine(sharing, online)} data-tauri-drag-region>
            <span className={sharing ? "dot dot-ok" : "dot dot-off"} aria-hidden="true" />
            {/* The dot is filled while sharing and hollow when not, so the state never rests on colour alone. */}
            <span className="topbar-status-text topbar-status-long">{sharingLine(sharing, online)}</span>
            <span className="topbar-status-text topbar-status-short" aria-hidden="true">{sharing ? "Sharing" : "Off"}</span>
          </span>
          {PLATFORM !== "mac" && <WindowControls />}
        </header>
        <main className="main">
          <ConnectionBanner />
          {/* The top bar shows where you are; the heading is for screen readers. */}
          <h1 className="visually-hidden">{current?.label}</h1>
          {view}
        </main>
        {about && <AboutDialog onClose={() => setAbout(false)} />}
      </div>
    </NavContext.Provider>
  );
}
