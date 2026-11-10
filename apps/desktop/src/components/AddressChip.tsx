import { Copy } from "lucide-react";
import { useToast } from "./Toast";

/** A device's or this computer's address on the shared network; a click copies it. */
export function AddressChip({ address, small = false }: { address: string; small?: boolean }) {
  const toast = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(address);
      toast.success(`${address} copied`);
    } catch {
      toast.error("Could not copy the address");
    }
  };
  return (
    <button
      type="button"
      className={small ? "address-chip address-chip-small mono" : "address-chip mono"}
      title="Copy this address"
      aria-label={`Copy address ${address}`}
      onClick={(e) => {
        // Rows that open on click keep still.
        e.stopPropagation();
        void copy();
      }}
    >
      {address}
      {!small && <Copy size={11} aria-hidden="true" />}
    </button>
  );
}
