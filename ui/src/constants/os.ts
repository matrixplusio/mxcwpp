/**
 * 操作系统相关常量配置
 */

export interface OSOption {
  label: string
  value: string
}

/**
 * 支持的操作系统列表
 * 用于前端各页面的 OS 选择器
 */
export const OS_OPTIONS: OSOption[] = [
  { label: 'Rocky Linux', value: 'rocky' },
  { label: 'CentOS', value: 'centos' },
  { label: 'Oracle Linux', value: 'oracle' },
  { label: 'Debian', value: 'debian' },
  { label: 'Ubuntu', value: 'ubuntu' },
  { label: 'openEuler', value: 'openeuler' },
  { label: 'Alibaba Cloud Linux', value: 'alibaba' },
]

/**
 * OS Family 标签映射
 */
export const OS_FAMILY_LABELS: Record<string, string> = {
  rocky: 'Rocky Linux',
  centos: 'CentOS',
  oracle: 'Oracle Linux',
  debian: 'Debian',
  ubuntu: 'Ubuntu',
  openeuler: 'openEuler',
  alibaba: 'Alibaba Cloud Linux',
  rhel: 'Red Hat Enterprise Linux',
}

/**
 * 获取 OS Family 的显示标签
 */
export function getOSFamilyLabel(family: string): string {
  return OS_FAMILY_LABELS[family] || family
}
