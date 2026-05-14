import { describe, it, expect, vi } from 'vitest'
import { useRequest } from '../useRequest'

// mock ant-design-vue message
vi.mock('ant-design-vue', () => ({
  message: {
    error: vi.fn(),
    warning: vi.fn(),
    success: vi.fn(),
    info: vi.fn(),
  },
}))

describe('useRequest', () => {
  it('初始状态 loading 为 false，data 为 null', () => {
    const { loading, data } = useRequest({
      fn: async () => 'result',
    })
    expect(loading.value).toBe(false)
    expect(data.value).toBeNull()
  })

  it('成功请求后 data 有值，loading 恢复 false', async () => {
    const { loading, data, run } = useRequest({
      fn: async () => ({ items: [1, 2, 3] }),
    })

    const result = await run()
    expect(result).toEqual({ items: [1, 2, 3] })
    expect(data.value).toEqual({ items: [1, 2, 3] })
    expect(loading.value).toBe(false)
  })

  it('失败请求后返回 null，loading 恢复 false', async () => {
    const { loading, data, run } = useRequest({
      fn: async () => {
        throw new Error('network error')
      },
      showError: false,
    })

    const result = await run()
    expect(result).toBeNull()
    expect(data.value).toBeNull()
    expect(loading.value).toBe(false)
  })

  it('支持传参给 fn', async () => {
    const mockFn = vi.fn(async (id: number) => ({ id }))
    const { run } = useRequest({ fn: mockFn })

    await run(42)
    expect(mockFn).toHaveBeenCalledWith(42)
  })

  it('失败时显示错误提示（默认 showError=true）', async () => {
    const { message } = await import('ant-design-vue')
    const { run } = useRequest({
      fn: async () => {
        throw new Error('请求超时')
      },
      errorMessage: '加载失败',
    })

    await run()
    expect(message.error).toHaveBeenCalledWith('加载失败: 请求超时')
  })

  it('showError=false 时不显示错误提示', async () => {
    const { message } = await import('ant-design-vue')
    vi.mocked(message.error).mockClear()

    const { run } = useRequest({
      fn: async () => {
        throw new Error('fail')
      },
      showError: false,
    })

    await run()
    expect(message.error).not.toHaveBeenCalled()
  })

  it('多次调用 run，data 保持最后一次结果', async () => {
    let counter = 0
    const { data, run } = useRequest({
      fn: async () => ++counter,
    })

    await run()
    expect(data.value).toBe(1)

    await run()
    expect(data.value).toBe(2)
  })
})
