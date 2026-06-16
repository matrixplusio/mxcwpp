import apiClient from './client'

export interface LoginRequest {
  username: string
  password: string
  captcha_id?: string
  captcha_code?: string
  device_id?: string
}

export interface CaptchaResponse {
  captcha_id: string
  captcha_image: string
}

export interface LoginResponse {
  token: string
  user: {
    username: string
    role: string
  }
  need_change_password?: boolean
}

export interface ChangePasswordRequest {
  old_password: string
  new_password: string
}

export const authApi = {
  getCaptcha: async (): Promise<CaptchaResponse> => {
    return apiClient.get('/auth/captcha')
  },

  login: async (data: LoginRequest): Promise<LoginResponse> => {
    return apiClient.post('/auth/login', data)
  },

  loginPrecheck: async (data: { username: string; device_id?: string }): Promise<{ need_captcha: boolean }> => {
    return apiClient.post('/auth/login-precheck', data)
  },

  logout: async (): Promise<void> => {
    return apiClient.post('/auth/logout')
  },

  getCurrentUser: async (): Promise<{ username: string; role: string }> => {
    return apiClient.get('/auth/me')
  },

  changePassword: async (data: ChangePasswordRequest): Promise<void> => {
    return apiClient.post('/auth/change-password', data)
  },
}

export const rbacApi = {
  listPermissions: async () => {
    return apiClient.get('/rbac/permissions')
  },

  listRoles: async () => {
    return apiClient.get('/rbac/roles')
  },

  getRolePermissions: async (role: string): Promise<{ role: string; permissions: string[] }> => {
    return apiClient.get(`/rbac/roles/${role}/permissions`)
  },

  updateRolePermissions: async (role: string, permissions: string[]): Promise<void> => {
    return apiClient.put(`/rbac/roles/${role}/permissions`, { permissions })
  },
}
