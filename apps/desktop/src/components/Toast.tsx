import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { CircleAlert, CircleCheck, X } from "lucide-react";

type ToastKind = "success" | "error";

interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  message?: string;
}

interface ToastApi {
  success(title: string, message?: string): void;
  error(title: string, message?: string): void;
}

const ToastContext = createContext<ToastApi | null>(null);

// Errors stay long enough to read multi-line validation output.
const DURATION: Record<ToastKind, number> = { success: 3500, error: 15000 };

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((list) => list.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (kind: ToastKind, title: string, message?: string) => {
      const id = nextId.current++;
      setToasts((list) => [...list.slice(-4), { id, kind, title, message }]);
      window.setTimeout(() => dismiss(id), DURATION[kind]);
    },
    [dismiss],
  );

  const api = useMemo<ToastApi>(
    () => ({
      success: (title, message) => push("success", title, message),
      error: (title, message) => push("error", title, message),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toasts">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.kind}`} role={t.kind === "error" ? "alert" : "status"}>
            {t.kind === "error" ? <CircleAlert size={16} /> : <CircleCheck size={16} />}
            <div className="toast-body">
              <strong>{t.title}</strong>
              {t.message && <pre className="toast-message">{t.message}</pre>}
            </div>
            <button className="icon-button" aria-label="Dismiss notification" onClick={() => dismiss(t.id)}>
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside <ToastProvider>");
  return ctx;
}
