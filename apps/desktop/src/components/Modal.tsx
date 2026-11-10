import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { X } from "lucide-react";

interface ModalProps {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}

/**
 * Native <dialog> shown modally while mounted: the browser handles focus
 * trapping and Escape. Parents mount it to open and unmount it to close, which
 * also resets any form state inside.
 */
export function Modal({ title, onClose, children, footer, wide }: ModalProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (dialog && !dialog.open) {
      dialog.showModal();
      // showModal focuses the first control (the close button); start on the
      // field the dialog marks instead.
      dialog.querySelector<HTMLElement>("[data-autofocus]")?.focus();
    }
    return () => dialog?.close();
  }, []);

  return (
    <dialog
      ref={ref}
      className={wide ? "modal modal-wide" : "modal"}
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <header className="modal-header">
        <h2 id={titleId}>{title}</h2>
        <button className="icon-button" aria-label="Close" onClick={onClose}>
          <X size={16} />
        </button>
      </header>
      <div className="modal-body">{children}</div>
      {footer && <footer className="modal-footer">{footer}</footer>}
    </dialog>
  );
}

interface ConfirmProps {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  /** When set, the user must tick this checkbox before confirming. */
  acknowledge?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({ title, children, confirmLabel, danger, acknowledge, onConfirm, onCancel }: ConfirmProps) {
  const [acked, setAcked] = useState(!acknowledge);
  return (
    <Modal
      title={title}
      onClose={onCancel}
      footer={
        <>
          <button className="button" onClick={onCancel}>
            Cancel
          </button>
          <button className={danger ? "button button-danger" : "button button-primary"} disabled={!acked} onClick={onConfirm}>
            {confirmLabel}
          </button>
        </>
      }
    >
      <div className="confirm-text">{children}</div>
      {acknowledge && (
        <label className="check">
          <input type="checkbox" checked={acked} onChange={(e) => setAcked(e.target.checked)} />
          <span>{acknowledge}</span>
        </label>
      )}
    </Modal>
  );
}
