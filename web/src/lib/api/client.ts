import axios, { AxiosHeaders } from "axios";
import { CODE, TOKEN_KEY, USER_KEY } from "./codes";

export interface ApiResp<T = unknown> { code: number; message?: string; data?: T; }

export function resolveBaseURL(url: string): string {
  if (url.startsWith("/api/")) return "";
  return url.startsWith("/v2/") ? "/api" : "/api/v1";
}

export function attachToken(headers: Record<string, string>): void {
  const token = typeof window !== "undefined" ? localStorage.getItem(TOKEN_KEY) : null;
  if (token) headers.Authorization = `Bearer ${token}`;
}

export function unwrap<T>(body: ApiResp<T>): T {
  if (body.code === CODE.SUCCESS) return body.data as T;
  throw new Error(body.message || `请求失败(code=${body.code})`);
}

export const http = axios.create({ timeout: 30000, headers: { "Content-Type": "application/json" } });

http.interceptors.request.use((config) => {
  config.baseURL = resolveBaseURL(config.url || "");
  const h = (config.headers ??= new AxiosHeaders()) as AxiosHeaders;
  const token = typeof window !== "undefined" ? localStorage.getItem(TOKEN_KEY) : null;
  if (token) h.set("Authorization", `Bearer ${token}`);
  return config;
});

http.interceptors.response.use((resp) => {
  if (resp.config.responseType === "blob") return resp;
  const body = resp.data as ApiResp;
  if (body.code === CODE.TOKEN_EXPIRED) {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new Error("登录已过期");
  }
  return resp;
});

export async function get<T>(url: string, params?: object): Promise<T> {
  const resp = await http.get<ApiResp<T>>(url, { params });
  return unwrap(resp.data);
}
export async function post<T>(url: string, data?: object): Promise<T> {
  const resp = await http.post<ApiResp<T>>(url, data);
  return unwrap(resp.data);
}
export async function put<T>(url: string, data?: object): Promise<T> {
  const resp = await http.put<ApiResp<T>>(url, data);
  return unwrap(resp.data);
}
export async function del<T>(url: string, params?: object): Promise<T> {
  const resp = await http.delete<ApiResp<T>>(url, { params });
  return unwrap(resp.data);
}
export async function upload<T>(url: string, file: File, field = "file"): Promise<T> {
  const fd = new FormData();
  fd.append(field, file);
  const resp = await http.post<ApiResp<T>>(url, fd, { headers: { "Content-Type": "multipart/form-data" } });
  return unwrap(resp.data);
}
export async function getBlob(url: string, params?: object): Promise<Blob> {
  const resp = await http.get<Blob>(url, { params, responseType: "blob" });
  return resp.data;
}
