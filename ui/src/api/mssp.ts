/**
 * MSSP 多租户托管 API (P4-11)
 *
 * MSSP (Managed Security Service Provider) 模式给安全服务商管理多个客户租户:
 *   - 父租户 (provider): 服务商自己, 全权限
 *   - 子租户 (customer): 客户, 各自隔离, 父租户可读 + 限制可写
 *
 * UI 控制台用:
 *   - 子租户列表 + 健康度
 *   - 横跨子租户的统一告警视图
 *   - 子租户配额 (主机/告警/策略数上限)
 *   - 配额变更审批
 */
import apiClient from './client'
import type { ApiResponse } from './types'

const { get, post, put, delete: del } = apiClient

export interface ChildTenant {
  id: string
  parent_id: string
  name: string
  status: 'active' | 'suspended' | 'pending'
  contact_email: string
  contact_phone: string
  host_count: number
  host_quota: number
  alert_count_7d: number
  critical_alert_count_7d: number
  mode: 'observe' | 'protect'
  created_at: string
  expires_at: string | null
}

export interface TenantQuota {
  tenant_id: string
  host_quota: number
  alert_quota_per_day: number
  policy_quota: number
  current_hosts: number
  current_policies: number
  current_alerts_today: number
}

export interface CrossTenantAlert {
  id: string
  tenant_id: string
  tenant_name: string
  host_id: string
  host_name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  rule_id: string
  status: 'open' | 'ack' | 'closed'
  created_at: string
}

export interface MSSPDashboardSummary {
  total_child_tenants: number
  active_child_tenants: number
  total_hosts_managed: number
  critical_alerts_7d: number
  pending_quota_requests: number
}

export const MSSPApi = {
  /** 控制台首页汇总. */
  dashboard(): Promise<ApiResponse<MSSPDashboardSummary>> {
    return get('/mssp/dashboard')
  },

  /** 子租户列表. */
  listChildTenants(params?: {
    status?: string
    search?: string
    page?: number
    page_size?: number
  }): Promise<ApiResponse<{ items: ChildTenant[]; total: number }>> {
    return get('/mssp/child-tenants', { params })
  },

  /** 子租户详情. */
  getChildTenant(id: string): Promise<ApiResponse<ChildTenant>> {
    return get(`/mssp/child-tenants/${id}`)
  },

  /** 新增子租户. */
  createChildTenant(payload: Omit<ChildTenant, 'id' | 'host_count' | 'alert_count_7d' | 'critical_alert_count_7d' | 'created_at'>): Promise<ApiResponse<ChildTenant>> {
    return post('/mssp/child-tenants', payload)
  },

  /** 编辑子租户. */
  updateChildTenant(id: string, payload: Partial<ChildTenant>): Promise<ApiResponse<ChildTenant>> {
    return put(`/mssp/child-tenants/${id}`, payload)
  },

  /** 删除子租户 (软删除, 数据保留). */
  deleteChildTenant(id: string): Promise<ApiResponse<void>> {
    return del(`/mssp/child-tenants/${id}`)
  },

  /** 暂停子租户 (停 Agent 投递). */
  suspendChildTenant(id: string, reason: string): Promise<ApiResponse<void>> {
    return post(`/mssp/child-tenants/${id}/suspend`, { reason })
  },

  /** 恢复. */
  resumeChildTenant(id: string): Promise<ApiResponse<void>> {
    return post(`/mssp/child-tenants/${id}/resume`)
  },

  /** 查租户配额. */
  getQuota(tenantId: string): Promise<ApiResponse<TenantQuota>> {
    return get(`/mssp/child-tenants/${tenantId}/quota`)
  },

  /** 改配额 (高敏感, 走 ConfigChange 审批). */
  updateQuota(tenantId: string, payload: Partial<TenantQuota>, reason: string): Promise<ApiResponse<TenantQuota>> {
    return put(`/mssp/child-tenants/${tenantId}/quota`, { ...payload, reason })
  },

  /** 横跨子租户的告警视图 (服务商 NOC 用). */
  crossTenantAlerts(params?: {
    severity?: string
    status?: string
    tenant_id?: string
    page?: number
    page_size?: number
  }): Promise<ApiResponse<{ items: CrossTenantAlert[]; total: number }>> {
    return get('/mssp/alerts', { params })
  },

  /** 一键代客户响应 (代客户 ack/close alert). */
  ackAlertAsTenant(tenantId: string, alertId: string, note: string): Promise<ApiResponse<void>> {
    return post(`/mssp/child-tenants/${tenantId}/alerts/${alertId}/ack`, { note })
  },
}
