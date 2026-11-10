import { useState } from "react";
import { Copy, Eye, EyeOff } from "lucide-react";
import { useToast } from "./Toast";

/** A value people copy to another device, such as the network name. */
export function CopyValue({ label, value, secret = false }: { label: string; value: string; secret?: boolean }) {
  const toast = useToast();
  const [shown, setShown] = useState(!secret);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label} copied`);
    } catch {
      toast.error(`Could not copy the ${label.toLowerCase()}`);
    }
  };
  return (
    <div className="copy-value">
      <span className="copy-label">{label}</span>
      <span className="copy-text mono">{shown ? value : "•".repeat(Math.min(Math.max(value.length, 8), 14))}</span>
      {secret && (
        <button className="icon-button" aria-label={shown ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`} onClick={() => setShown((s) => !s)}>
          {shown ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      )}
      <button className="icon-button" aria-label={`Copy ${label.toLowerCase()}`} title="Copy" onClick={() => void copy()}>
        <Copy size={14} />
      </button>
    </div>
  );
}
