import { createContext, useCallback, useContext, useEffect, useState, type MouseEvent, type ReactNode } from "react";

type Nav = {
  path: string;
  navigate: (to: string) => void;
};

const NavContext = createContext<Nav | null>(null);

/** The address bar is the source of truth. A client router retried a stuck scan navigation and froze the tab. */
export function Navigation({ children }: { children: ReactNode }) {
  const [path, setPath] = useState(() => window.location.pathname);
  const navigate = useCallback((to: string) => {
    const next = to.startsWith("/") ? to : `/${to}`;
    if (next !== window.location.pathname) window.history.pushState(null, "", next);
    setPath(next);
  }, []);

  useEffect(() => {
    const sync = () => setPath(window.location.pathname);
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, []);

  return <NavContext.Provider value={{ path, navigate }}>{children}</NavContext.Provider>;
}

export function useNavigation(): Nav {
  const value = useContext(NavContext);
  if (!value) throw new Error("Navigation is missing");
  return value;
}

export function scanIdFromPath(path: string): string {
  const prefix = "/scans/";
  if (!path.startsWith(prefix)) return "";
  const id = path.slice(prefix.length).split("/")[0] ?? "";
  try {
    return decodeURIComponent(id);
  } catch {
    return id;
  }
}

export function onSameTabClick(event: MouseEvent<HTMLAnchorElement>, navigate: (to: string) => void, to: string) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  navigate(to);
}
