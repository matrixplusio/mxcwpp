import { defineStore } from 'pinia'
import { ref } from 'vue'
import { authApi } from '@/api/auth'
import type { LoginRequest } from '@/api/auth'

const TOKEN_KEY = 'mxcsec_token'
const USER_KEY = 'mxcsec_user'

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string | null>(localStorage.getItem(TOKEN_KEY))
  const user = ref<{ username: string; role: string } | null>(
    (() => {
      const stored = localStorage.getItem(USER_KEY)
      return stored ? JSON.parse(stored) : null
    })()
  )

  const isAuthenticated = () => {
    return !!token.value
  }

  const needChangePassword = ref(false)

  const login = async (data: LoginRequest) => {
    const response = await authApi.login(data)
    token.value = response.token
    user.value = response.user
    needChangePassword.value = response.need_change_password || false
    localStorage.setItem(TOKEN_KEY, response.token)
    localStorage.setItem(USER_KEY, JSON.stringify(response.user))
    return response
  }

  const logout = async () => {
    try {
      await authApi.logout()
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      token.value = null
      user.value = null
      localStorage.removeItem(TOKEN_KEY)
      localStorage.removeItem(USER_KEY)
    }
  }

  const initAuth = async () => {
    if (token.value) {
      try {
        const currentUser = await authApi.getCurrentUser()
        user.value = currentUser
        localStorage.setItem(USER_KEY, JSON.stringify(currentUser))
      } catch (error) {
        // Token 可能已过期，清除认证信息
        token.value = null
        user.value = null
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(USER_KEY)
      }
    }
  }

  return {
    token,
    user,
    needChangePassword,
    isAuthenticated,
    login,
    logout,
    initAuth,
  }
})
