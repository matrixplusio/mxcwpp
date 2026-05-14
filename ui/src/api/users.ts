import apiClient from './client'

export interface User {
  id: number
  username: string
  email: string
  role: 'admin' | 'user'
  status: 'active' | 'inactive'
  last_login?: string
  created_at: string
  updated_at: string
}

export interface ListUsersParams {
  page?: number
  page_size?: number
  username?: string
  role?: string
  status?: string
}

export interface ListUsersResponse {
  total: number
  items: User[]
}

export interface CreateUserRequest {
  username: string
  password: string
  email?: string
  role: 'admin' | 'user'
  status?: 'active' | 'inactive'
}

export interface UpdateUserRequest {
  password?: string
  email?: string
  role?: 'admin' | 'user'
  status?: 'active' | 'inactive'
}

export const usersApi = {
  list: async (params?: ListUsersParams): Promise<ListUsersResponse> => {
    return apiClient.get('/users', { params })
  },

  get: async (id: number): Promise<User> => {
    return apiClient.get(`/users/${id}`)
  },

  create: async (data: CreateUserRequest): Promise<User> => {
    return apiClient.post('/users', data)
  },

  update: async (id: number, data: UpdateUserRequest): Promise<User> => {
    return apiClient.put(`/users/${id}`, data)
  },

  delete: async (id: number): Promise<void> => {
    return apiClient.delete(`/users/${id}`)
  },
}
