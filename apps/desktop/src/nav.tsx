import { createContext, useContext } from "react";

export type PageId = "home" | "clients" | "egresses" | "rules" | "dns" | "settings";

/** Opens another page, e.g. the device list from the dashboard. */
export const NavContext = createContext<(page: PageId) => void>(() => undefined);

export function useNav(): (page: PageId) => void {
  return useContext(NavContext);
}
