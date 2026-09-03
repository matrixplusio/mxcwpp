import { create } from "zustand";
import { TOKEN_KEY, USER_KEY } from "@/lib/api/codes";
import type { LoginUser } from "@/lib/api/types";

interface AuthState {
  token: string | null;
  user: LoginUser | null;
  setSession: (token: string, user: LoginUser) => void;
  clear: () => void;
  isAuthenticated: () => boolean;
  hydrate: () => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: null,
  user: null,
  setSession: (token, user) => {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
    set({ token, user });
  },
  clear: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    set({ token: null, user: null });
  },
  isAuthenticated: () => !!get().token,
  hydrate: () => {
    const token = localStorage.getItem(TOKEN_KEY);
    const userRaw = localStorage.getItem(USER_KEY);
    set({ token, user: userRaw ? JSON.parse(userRaw) : null });
  },
}));
