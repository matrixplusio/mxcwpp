import { describe, it, expect } from 'vitest'
import { usePagination } from '../usePagination'

describe('usePagination', () => {
  it('使用默认值初始化', () => {
    const { pagination } = usePagination()
    expect(pagination.current).toBe(1)
    expect(pagination.pageSize).toBe(20)
    expect(pagination.total).toBe(0)
  })

  it('接受自定义 pageSize', () => {
    const { pagination } = usePagination({ defaultPageSize: 50 })
    expect(pagination.pageSize).toBe(50)
  })

  it('setTotal 更新总数', () => {
    const { pagination, setTotal } = usePagination()
    setTotal(100)
    expect(pagination.total).toBe(100)
  })

  it('resetPage 重置到第 1 页', () => {
    const { pagination, resetPage } = usePagination()
    pagination.current = 5
    resetPage()
    expect(pagination.current).toBe(1)
  })

  it('getParams 返回分页参数', () => {
    const { pagination, getParams } = usePagination()
    pagination.current = 3
    pagination.pageSize = 10

    const params = getParams()
    expect(params).toEqual({ page: 3, page_size: 10 })
  })

  it('showTotal 默认格式', () => {
    const { pagination } = usePagination()
    expect(pagination.showTotal(42)).toBe('共 42 条')
  })

  it('showTotal 支持自定义', () => {
    const { pagination } = usePagination({
      showTotal: (total) => `Total: ${total}`,
    })
    expect(pagination.showTotal(99)).toBe('Total: 99')
  })
})
