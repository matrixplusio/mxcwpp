import apiClient from './client'

export interface PreCheckPackage {
  name: string
  installed_version?: string
  available_version?: string
  repo?: string
  action: 'upgrade' | 'already_latest' | 'not_available' | 'upgrade_but_below_fixed'
}

// P5.2 affected process（lsof 找到的依赖该 lib 的运行进程，shared_lib 类才会有）
// 字符串格式："nginx (PID 1234)"

export const hostVulnPreCheckApi = {
  /** 单条 host_vulnerability pre-check（异步，agent 回报后写 DB） */
  triggerOne: (hostVulnId: number) => {
    return apiClient.post<{ hostVulnId: number; hostId: string }>(
      `/host-vulnerabilities/${hostVulnId}/precheck`,
    )
  },

  /** 该 host 全部 unpatched + 未 precheck / failed / >24h 过期 漏洞批量 pre-check */
  triggerAllForHost: (hostId: string) => {
    return apiClient.post<{ hostId: string; scheduled: number; failed: number; total: number }>(
      `/hosts/${encodeURIComponent(hostId)}/precheck-all`,
    )
  },

  /**
   * 全集群所有 online 主机的 unpatched 漏洞批量 pre-check（admin 权限）
   * 单 host 单次 dispatch 上限 200，超出部分留给 6h 周期 cron。
   */
  triggerAllOnline: () => {
    return apiClient.post<{
      hosts_total: number
      hosts_dispatched: number
      scheduled: number
      failed: number
    }>(`/host-vulnerabilities/precheck-all-online`)
  },
}
