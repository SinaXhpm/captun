import { getCurrentWindow } from "@tauri-apps/api/window";

/**
 * Stops every animation while nobody can see the window: `window-hidden` on
 * <html> pauses them all (styles.css). The page counts as hidden when the
 * webview says so, or when the window is minimized. WebView2 is not told
 * about minimizing, so every resize (minimizing and restoring each send one)
 * asks the window itself: the size alone cannot tell, because this window
 * draws its own title bar and keeps a small, non-zero size while minimized.
 */
export function pauseAnimationsWhileHidden(): void {
  const root = document.documentElement;
  let minimized = false;
  const sync = () => root.classList.toggle("window-hidden", minimized || document.visibilityState === "hidden");
  document.addEventListener("visibilitychange", sync);
  sync();
  try {
    const win = getCurrentWindow();
    // Only the answer to the latest resize counts, should replies cross.
    let asked = 0;
    void win
      .onResized(({ payload }) => {
        // A first guess (a window with a system title bar shrinks to 0 × 0),
        // then the window's own answer.
        minimized = payload.width === 0 || payload.height === 0;
        sync();
        const ask = ++asked;
        win.isMinimized().then(
          (m) => {
            if (ask !== asked) return;
            minimized = m;
            sync();
          },
          () => undefined,
        );
      })
      .catch(() => undefined);
  } catch {
    // Not inside the app's window (a plain browser): visibility alone decides.
  }
}
