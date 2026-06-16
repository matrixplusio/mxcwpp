import { ref, type Ref } from 'vue'
import { message } from 'ant-design-vue'

export interface UseRequestOptions<T> {
  /** 请求函数 */
  fn: (...args: any[]) => Promise<T>
  /** 失败时的提示前缀 */
  errorMessage?: string
  /** 是否在请求失败时自动弹出错误提示。默认 false：错误已由全局 axios 拦截器统一弹窗，避免重复提示 */
  showError?: boolean
}

export interface UseRequestReturn<T> {
  loading: Ref<boolean>
  data: Ref<T | null>
  run: (...args: any[]) => Promise<T | null>
}

/**
 * 异步请求 composable，封装 loading 状态 + 错误处理
 *
 * @example
 * const { loading, data, run } = useRequest({
 *   fn: (params) => hostsApi.list(params),
 *   errorMessage: '加载主机列表失败',
 * })
 * await run({ page: 1, page_size: 20 })
 */
export function useRequest<T>(options: UseRequestOptions<T>): UseRequestReturn<T> {
  const loading = ref(false) as Ref<boolean>
  const data = ref<T | null>(null) as Ref<T | null>

  async function run(...args: any[]): Promise<T | null> {
    loading.value = true
    try {
      const result = await options.fn(...args)
      data.value = result
      return result
    } catch (error: any) {
      // 默认不再重复弹窗（全局拦截器已统一提示）；仅在显式 showError=true 时弹出
      if (options.showError === true) {
        const prefix = options.errorMessage ?? '请求失败'
        message.error(`${prefix}: ${error.message || '未知错误'}`)
      }
      return null
    } finally {
      loading.value = false
    }
  }

  return { loading, data, run }
}
