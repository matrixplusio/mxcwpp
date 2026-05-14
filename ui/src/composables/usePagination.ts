import { reactive } from 'vue'

export interface PaginationState {
  current: number
  pageSize: number
  total: number
  showTotal: (total: number) => string
}

export interface UsePaginationOptions {
  defaultPageSize?: number
  showTotal?: (total: number) => string
}

/**
 * 分页状态管理 composable
 *
 * @example
 * const { pagination, setTotal, resetPage } = usePagination()
 * // 在 API 调用中：
 * const res = await api.list({ page: pagination.current, page_size: pagination.pageSize })
 * setTotal(res.total)
 * // 在表格 @change 中：
 * const handleTableChange = (pag: any) => { pagination.current = pag.current; load() }
 */
export function usePagination(options?: UsePaginationOptions) {
  const pagination = reactive<PaginationState>({
    current: 1,
    pageSize: options?.defaultPageSize ?? 20,
    total: 0,
    showTotal: options?.showTotal ?? ((total: number) => `共 ${total} 条`),
  })

  function setTotal(total: number) {
    pagination.total = total
  }

  function resetPage() {
    pagination.current = 1
  }

  function getParams() {
    return {
      page: pagination.current,
      page_size: pagination.pageSize,
    }
  }

  return {
    pagination,
    setTotal,
    resetPage,
    getParams,
  }
}
