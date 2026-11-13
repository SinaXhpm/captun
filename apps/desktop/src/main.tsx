import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { ToastProvider } from "./components/Toast";
import { pauseAnimationsWhileHidden } from "./motion";
import { ServiceProvider } from "./service";
// Inter, with its optical sizes: one smooth face for all text, shipped with
// the app (no download) so it looks the same on every computer.
import "@fontsource-variable/inter/opsz.css";
import "./styles.css";

pauseAnimationsWhileHidden();

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <ToastProvider>
        <ServiceProvider>
          <App />
        </ServiceProvider>
      </ToastProvider>
    </StrictMode>,
  );
}
