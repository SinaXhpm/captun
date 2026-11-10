import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { ToastProvider } from "./components/Toast";
import { pauseAnimationsWhileHidden } from "./motion";
import { ServiceProvider } from "./service";
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
