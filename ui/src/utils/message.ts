/**
 * 消息提示工具函数
 * 统一管理操作成功、失败、警告等提示信息
 */

import { message } from 'ant-design-vue'

/**
 * 显示成功消息
 */
export const showSuccess = (content: string, duration = 3) => {
  message.success(content, duration)
}

/**
 * 显示错误消息
 */
export const showError = (content: string, duration = 3) => {
  message.error(content, duration)
}

/**
 * 显示警告消息
 */
export const showWarning = (content: string, duration = 3) => {
  message.warning(content, duration)
}

/**
 * 显示信息消息
 */
export const showInfo = (content: string, duration = 3) => {
  message.info(content, duration)
}

/**
 * 显示加载消息（返回关闭函数）
 */
export const showLoading = (content: string = '加载中...') => {
  const hide = message.loading(content, 0)
  return hide
}

/**
 * 操作成功提示
 */
export const showOperationSuccess = (operation: string) => {
  showSuccess(`${operation}成功`)
}

/**
 * 操作失败提示
 */
export const showOperationError = (operation: string, error?: string) => {
  const errorMsg = error || '操作失败，请稍后重试'
  showError(`${operation}失败: ${errorMsg}`)
}

/**
 * 确认删除提示（返回 Promise）
 */
export const confirmDelete = (itemName: string = '该项'): Promise<boolean> => {
  return new Promise((resolve) => {
    // 这里可以使用 Modal.confirm，但为了简化，先返回 true
    // 实际使用时应该在组件中使用 Modal.confirm
    resolve(window.confirm(`确定要删除${itemName}吗？此操作不可恢复。`))
  })
}
