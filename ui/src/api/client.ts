/**
 * API 客户端模块
 *
 * 提供统一的 HTTP 请求客户端，包含：
 * - 请求拦截器：自动添加认证 Token
 * - 响应拦截器：统一处理错误和业务响应
 * - 全局错误提示：使用 Ant Design Vue message 显示错误信息
 */

import axios, { AxiosRequestConfig } from 'axios'
import { message } from 'ant-design-vue'
import type { ApiResponse } from './types'
import { RespCode } from './codes'

const CODE_TOKEN_EXPIRED = RespCode.TOKEN_EXPIRED

/**
 * 创建 axios 实例
 *
 * 配置：
 * - baseURL: API 基础路径
 * - timeout: 请求超时时间（30秒）
 * - headers: 默认请求头
 */
const axiosInstance = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

/**
 * 请求拦截器
 *
 * 功能：
 * - 自动从 localStorage 获取认证 Token
 * - 将 Token 添加到请求头的 Authorization 字段
 */
axiosInstance.interceptors.request.use(
  (config) => {
    // 添加 token 认证信息
    const token = localStorage.getItem('mxcsec_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    // 路径前缀分流: 默认 baseURL=/api/v1.
    // 调用方传 /v2/... 或 /api/v2/... 时改 baseURL 为 /api, 避免 /api/v1 + /v2/... 错拼.
    if (config.url) {
      if (config.url.startsWith('/api/v2/')) {
        config.baseURL = ''
      } else if (config.url.startsWith('/v2/')) {
        config.baseURL = '/api'
      }
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

/**
 * 响应拦截器
 *
 * 功能：
 * - 统一处理业务响应格式（code, message, data）
 * - 自动显示错误提示（使用 Ant Design Vue message）
 * - 处理认证失败（401）自动跳转登录
 * - 处理网络错误和 HTTP 错误
 */
axiosInstance.interceptors.response.use(
  (response) => {
    // 文件下载请求（responseType=blob）直接返回 Blob，跳过业务响应解析
    if (response.config.responseType === 'blob') {
      return response.data
    }
    // 统一约定：业务接口一律 HTTP 200，用 body 的 code 表达结果（0=成功，非0=业务错误）。
    const res = response.data as ApiResponse
    if (res.code === 0) {
      // 后端 SuccessMessage 仅返回 {code, message} 无 data；返回 {message} 兜底，避免调用方 NPE
      return res.data ?? { message: res.message }
    }

    const errorMessage = res.message || '请求失败'
    console.error('API Error:', res.code, errorMessage)

    // 40101 = 登录已过期 / Token 无效：清理并跳转登录页（打印路由与登录页本身除外）
    if (res.code === CODE_TOKEN_EXPIRED) {
      const path = window.location.pathname
      if (!path.startsWith('/print/') && path !== '/login') {
        localStorage.removeItem('mxcsec_token')
        localStorage.removeItem('mxcsec_user')
        message.warning(errorMessage)
        window.location.href = '/login'
      }
      return Promise.reject(new Error(errorMessage))
    }

    // 其余业务错误：统一弹窗提示后端 message（绝不暴露裸 code / "status code 4xx"）
    message.error(errorMessage)
    return Promise.reject(new Error(errorMessage))
  },
  (error) => {
    // 走到这里的只剩真正的传输层错误：网络断开、gin panic(500)、探针 503 等（业务错误已在上面以 200+code 处理）
    const backendMsg: string = error.response?.data?.message || ''
    if (!error.response) {
      const msg = '网络错误，请检查网络连接'
      message.error(msg)
      console.error('Network Error:', error)
      return Promise.reject(new Error(msg))
    }
    const status = error.response.status
    let msg = backendMsg
    if (!msg) {
      if (status >= 500) msg = '服务器错误，请稍后重试'
      else if (status === 404) msg = '请求的资源不存在'
      else msg = '请求失败'
    }
    message.error(msg)
    console.error('HTTP Error:', error)
    return Promise.reject(new Error(msg))
  }
)

/**
 * 类型化的 API 客户端
 *
 * 由于响应拦截器返回的是解包后的数据（res.data），而不是 AxiosResponse，
 * 所以需要重新定义方法的返回类型为 Promise<T> 而不是 Promise<AxiosResponse<T>>
 */
const apiClient = {
  get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return axiosInstance.get(url, config) as Promise<T>
  },

  post<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return axiosInstance.post(url, data, config) as Promise<T>
  },

  put<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return axiosInstance.put(url, data, config) as Promise<T>
  },

  delete<T = void>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return axiosInstance.delete(url, config) as Promise<T>
  },

  patch<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    return axiosInstance.patch(url, data, config) as Promise<T>
  },

  download(url: string, params?: Record<string, unknown>): Promise<Blob> {
    return axiosInstance.get(url, { params, responseType: 'blob' }) as Promise<Blob>
  },
}

export default apiClient
