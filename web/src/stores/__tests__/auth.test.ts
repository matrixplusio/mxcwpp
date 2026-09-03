import { describe, it, expect, beforeEach } from "vitest";
import { useAuthStore } from "@/stores/auth";
import { TOKEN_KEY, USER_KEY } from "@/lib/api/codes";

describe("auth store", () => {
  beforeEach(() => { localStorage.clear(); useAuthStore.setState({ token: null, user: null }); });

  it("setSession persists token+user", () => {
    useAuthStore.getState().setSession("tk", { username: "admin", role: "admin" });
    expect(useAuthStore.getState().token).toBe("tk");
    expect(localStorage.getItem(TOKEN_KEY)).toBe("tk");
    expect(JSON.parse(localStorage.getItem(USER_KEY)!).username).toBe("admin");
  });

  it("isAuthenticated true after setSession", () => {
    useAuthStore.getState().setSession("tk", { username: "a", role: "r" });
    expect(useAuthStore.getState().isAuthenticated()).toBe(true);
  });

  it("clear removes token+user", () => {
    useAuthStore.getState().setSession("tk", { username: "a", role: "r" });
    useAuthStore.getState().clear();
    expect(useAuthStore.getState().token).toBeNull();
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
    expect(useAuthStore.getState().isAuthenticated()).toBe(false);
  });
});
