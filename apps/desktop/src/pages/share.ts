import type { ComponentType, ReactNode } from "react";
import type { LucideProps } from "lucide-react";
import type { PowerPhase } from "../components/PowerButton";

/**
 * One way of sharing this computer's internet, as Home shows it: the big
 * button's state and action, a status line, and whatever else it needs.
 */
export interface ShareMode {
  id: "wifi" | "usb";
  label: string;
  icon: ComponentType<LucideProps>;
  phase: PowerPhase;
  /** On, or getting there: marked in the mode switch. */
  active: boolean;
  /** What the big button does now; none while it cannot do anything. */
  action: { label: string; hint?: string; run: () => void } | null;
  /** One line under the button. */
  status: string;
  /** More about it: join details, the phone, a problem. */
  detail?: ReactNode;
  /** Small links under the detail, such as settings. */
  links?: ReactNode;
  /** Opens its settings, where it has any to open now. */
  settings?: () => void;
  /** Dialogs it may open. */
  overlay?: ReactNode;
}
