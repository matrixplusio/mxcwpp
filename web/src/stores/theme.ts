import { create } from "zustand";

type Mode = "light" | "dark";

const STORAGE_KEY = "mxcwpp-theme";

function readStored(): Mode {
  if (typeof window === "undefined") return "light";
  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (stored === "light" || stored === "dark") return stored;
  return "light"; // 默认浅色(不跟随系统),用户切换后记住
}

/** 在 <html> 上应用/移除 .dark 类 */
export function applyTheme(mode: Mode) {
  if (typeof document === "undefined") return;
  document.documentElement.classList.toggle("dark", mode === "dark");
}

function persist(mode: Mode) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(STORAGE_KEY, mode);
}

interface ThemeState {
  mode: Mode;
  toggle: () => void;
  setMode: (m: Mode) => void;
  init: () => void;
}

export const useThemeStore = create<ThemeState>((set, get) => ({
  mode: "light",
  toggle: () => get().setMode(get().mode === "light" ? "dark" : "light"),
  setMode: (m) => {
    persist(m);
    applyTheme(m);
    set({ mode: m });
  },
  init: () => {
    const mode = readStored();
    applyTheme(mode);
    set({ mode });
  },
}));
