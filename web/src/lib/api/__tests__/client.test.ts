import { describe, it, expect, beforeEach } from "vitest";
import { unwrap, resolveBaseURL, attachToken } from "@/lib/api/client";
import { TOKEN_KEY } from "@/lib/api/codes";

describe("api client helpers", () => {
  beforeEach(() => localStorage.clear());

  it("unwrap returns data when code===0", () => {
    expect(unwrap({ code: 0, data: { a: 1 } })).toEqual({ a: 1 });
  });

  it("unwrap throws business error when code!==0", () => {
    expect(() => unwrap({ code: 1001, message: "boom" })).toThrowError("boom");
  });

  it("resolveBaseURL switches /v2 routes to /api", () => {
    expect(resolveBaseURL("/dashboard/stats")).toBe("/api/v1");
    expect(resolveBaseURL("/v2/kube/clusters")).toBe("/api");
  });

  it("resolveBaseURL returns empty for already /api-prefixed urls", () => {
    expect(resolveBaseURL("/api/v2/kube/clusters")).toBe("");
    expect(resolveBaseURL("/api/v1/auth/me")).toBe("");
  });

  it("attachToken injects Authorization header", () => {
    localStorage.setItem(TOKEN_KEY, "abc");
    const headers: Record<string, string> = {};
    attachToken(headers);
    expect(headers.Authorization).toBe("Bearer abc");
  });

  it("attachToken no-op without token", () => {
    const headers: Record<string, string> = {};
    attachToken(headers);
    expect(headers.Authorization).toBeUndefined();
  });
});
