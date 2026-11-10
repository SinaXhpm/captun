import { useEffect, useState } from "react";
import { Copy, Minus, Square, X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";

/**
 * Minimize, maximize and close for the app's own title bar (Windows and
 * Linux draw none of their own; macOS keeps its traffic lights).
 */
export function WindowControls() {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    const win = getCurrentWindow();
    let stop: (() => void) | undefined;
    let live = true;
    const sync = () => void win.isMaximized().then((m) => live && setMaximized(m), () => undefined);
    sync();
    void win.onResized(sync).then((unlisten) => {
      if (live) stop = unlisten;
      else unlisten();
    });
    return () => {
      live = false;
      stop?.();
    };
  }, []);

  const win = getCurrentWindow();
  return (
    <div className="window-controls">
      <button className="window-control" aria-label="Minimize" title="Minimize" onClick={() => void win.minimize()}>
        <Minus size={15} strokeWidth={1.5} />
      </button>
      <button
        className="window-control"
        aria-label={maximized ? "Restore" : "Maximize"}
        title={maximized ? "Restore" : "Maximize"}
        onClick={() => void win.toggleMaximize()}
      >
        {maximized ? <Copy size={13} strokeWidth={1.5} /> : <Square size={12} strokeWidth={1.5} />}
      </button>
      <button className="window-control window-close" aria-label="Close" title="Close" onClick={() => void win.close()}>
        <X size={16} strokeWidth={1.5} />
      </button>
    </div>
  );
}
