import { get, post, put, del, upload } from "./client";
import type { Paged, User, PermModule, Role, Notification, SiteConfig, RetentionPolicy, FeatureFlag } from "./types";

export const systemApi = {
  // users
  listUsers: (params: { page: number; page_size: number; username?: string; role?: string; status?: string }) =>
    get<Paged<User>>("/users", params),
  getUser: (id: number) => get<User>(`/users/${id}`),
  createUser: (body: Partial<User> & { password?: string }) => post<User>("/users", body),
  updateUser: (id: number, body: Partial<User> & { password?: string }) => put<User>(`/users/${id}`, body),
  deleteUser: (id: number) => del<void>(`/users/${id}`),
  // rbac
  listPermissions: () => get<PermModule[]>("/rbac/permissions"),
  listRoles: () => get<Role[]>("/rbac/roles"),
  getRolePermissions: (role: string) => get<{ permissions: string[]; role: string }>(`/rbac/roles/${role}/permissions`),
  updateRolePermissions: (role: string, permissions: string[]) => put<void>(`/rbac/roles/${role}/permissions`, { permissions }),
  createRole: (body: { code: string; name: string; permissions: string[] }) => post<{ code: string; name: string }>("/rbac/roles", body),
  deleteRole: (role: string) => del<void>(`/rbac/roles/${role}`),
  // notifications
  listNotifications: (params: { page: number; page_size: number; enabled?: boolean; keyword?: string }) =>
    get<Paged<Notification>>("/notifications", params),
  createNotification: (body: Partial<Notification>) => post<Notification>("/notifications", body),
  updateNotification: (id: number, body: Partial<Notification>) => put<Notification>(`/notifications/${id}`, body),
  deleteNotification: (id: number) => del<void>(`/notifications/${id}`),
  testNotification: (body: Partial<Notification>) => post<void>("/notifications/test", body),
  // settings
  getSiteConfig: () => get<SiteConfig>("/system-config/site"),
  updateSiteConfig: (body: Partial<SiteConfig>) => put<SiteConfig>("/system-config/site", body),
  uploadLogo: (file: File) => upload<{ logo_url: string }>("/system-config/upload-logo", file, "logo"),
  // retention
  listRetention: () => get<Paged<RetentionPolicy>>("/retention-policies"),
  updateRetention: (chTable: string, retention_days: number) => put<RetentionPolicy>(`/retention-policies/${chTable}`, { retention_days }),
  // feature flags
  listFeatureFlags: () => get<Paged<FeatureFlag>>("/feature-flags"),
  updateFeatureFlag: (key: string, value: string) => put<FeatureFlag>(`/feature-flags/${key}`, { value }),
  // 系统版本(用于「关于系统」)
  version: () => get<{ component: string; version: string; timestamp: string }>("/system/version"),
};
