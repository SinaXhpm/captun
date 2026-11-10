import { useEffect, useState } from "react";
import { CircleCheck, Download, ExternalLink, Globe, Loader, RefreshCw } from "lucide-react";
import { api, errorMessage } from "../api";
import { useServiceStatus } from "../service";
import type { AppInfo, UpdateInfo } from "../types";
import { Modal } from "./Modal";

/** GitHub's mark (Octicons, MIT), as Lucide no longer ships brand icons. */
function GitHubMark({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}

type Check = { state: "idle" } | { state: "checking" } | { state: "done"; info: UpdateInfo } | { state: "failed"; error: string };

/** The address without its scheme, for showing. */
const bare = (url: string) => url.replace(/^https?:\/\//, "");

/**
 * Opened from the logo: what this copy of Captun is, where the project lives,
 * and whether a newer release is out.
 */
export function AboutDialog({ onClose }: { onClose: () => void }) {
  const status = useServiceStatus();
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [check, setCheck] = useState<Check>({ state: "idle" });

  useEffect(() => {
    void api.appInfo().then(setInfo, () => undefined);
  }, []);

  const open = (url: string) => void api.openLink(url).catch(() => undefined);
  const runCheck = async () => {
    setCheck({ state: "checking" });
    try {
      setCheck({ state: "done", info: await api.checkUpdate() });
    } catch (e) {
      setCheck({ state: "failed", error: errorMessage(e) });
    }
  };

  const service = status?.service_version;
  let result = null;
  if (check.state === "done") {
    const u = check.info;
    result = u.newer ? (
      <div className="update update-new">
        <Download size={15} aria-hidden="true" />
        <div className="update-text">
          <strong>Version {u.latest} is out.</strong>
          {u.notes && <p className="update-notes">{u.notes}</p>}
        </div>
        {u.url && (
          <button className="button button-primary button-small" onClick={() => open(u.url ?? "")}>
            Download
          </button>
        )}
      </div>
    ) : (
      <div className="update update-ok">
        <CircleCheck size={15} aria-hidden="true" />
        <span className="update-text">
          {u.latest ? `You have the latest version (${u.current}).` : "No release has been published on GitHub yet."}
        </span>
      </div>
    );
  } else if (check.state === "failed") {
    result = (
      <div className="update update-failed" role="alert">
        <span className="update-text">Could not check: {check.error}</span>
      </div>
    );
  }

  return (
    <Modal title="About Captun" onClose={onClose}>
      <div className="about">
        {/* The helm on the app icon's navy tile; its glow is a still gradient, not a filter. */}
        <span className="about-tile" aria-hidden="true">
          <img className="about-logo" src="/logo.png" alt="" />
        </span>
        <div className="about-name">Captun</div>
        <p className="about-tagline">Share this computer's internet over Wi-Fi or USB, with a different way out for each device.</p>
        <dl className="about-versions">
          <dt>Version</dt>
          <dd>{info?.version ?? "…"}</dd>
          {service && service !== info?.version && (
            <>
              <dt>Service</dt>
              <dd>{service}</dd>
            </>
          )}
        </dl>

        {info && (
          <div className="about-links">
            <button className="about-link" onClick={() => open(info.website)}>
              <Globe size={14} aria-hidden="true" />
              {bare(info.website)}
              <ExternalLink size={12} aria-hidden="true" />
            </button>
            <button className="about-link" onClick={() => open(info.repository)}>
              <GitHubMark />
              {bare(info.repository).replace(/^github\.com\//, "GitHub · ")}
              <ExternalLink size={12} aria-hidden="true" />
            </button>
          </div>
        )}

        <button className="button" disabled={check.state === "checking"} onClick={() => void runCheck()}>
          {check.state === "checking" ? <Loader size={14} className="spin" aria-hidden="true" /> : <RefreshCw size={14} aria-hidden="true" />}
          {check.state === "checking" ? "Checking…" : "Check for updates"}
        </button>
        {result}
      </div>
    </Modal>
  );
}
