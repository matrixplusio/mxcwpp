import { get, post } from "./client";
import type { LoginRequest, LoginResponse, LoginUser } from "./types";

export const authApi = {
  precheck: (username: string) => post<{ need_captcha: boolean }>("/auth/login-precheck", { username }),
  login: (data: LoginRequest) => post<LoginResponse>("/auth/login", data),
  logout: () => post<void>("/auth/logout"),
  me: () => get<LoginUser>("/auth/me"),
  changePassword: (old_password: string, new_password: string) =>
    post<void>("/auth/change-password", { old_password, new_password }),
  captchaUrl: () => "/api/v1/auth/captcha",
};
