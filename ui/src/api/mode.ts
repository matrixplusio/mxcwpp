/**
 * 运行模式管理 API (Sprint 4 PR69)
 *
 * v2.0 引入两阶段哲学:
 *   - observe (默认): 仅观察 + 告警, 不阻断业务
 *   - protect:        observe + 自动阻断, 需 6 闸门 (G1-G6) admission 才能切换
 *
 * 4 级覆盖优先级 (高→低):
 *   rule > host_label > tenant > global
 */
import apiClient from './client'
import type { ApiResponse } from './types'

const { get, post } = apiClient

export type RunningMode = 'observe' | 'protect'

export interface GlobalMode {
  mode: RunningMode
  updated_by: string
  updated_at: string
}

export interface TenantMode {
  tenant_id: string
  mode: RunningMode
  updated_by: string
  updated_at: string
}

export interface HostLabelOverride {
  id: number
  tenant_id: string
  label_selector: string
  mode: RunningMode
  reason: string
  expires_at: string | null
}

export interface RuleOverride {
  id: number
  tenant_id: string
  rule_id: string
  mode: RunningMode
  reason: string
}

/** 6 闸门状态 (G1-G6 admission). */
export interface AdmissionGate {
  id: string                // G1..G6
  name: string
  description: string
  status: 'pass' | 'fail' | 'pending'
  detail: string
  evidence: string | null
  last_checked_at: string
}

export interface AdmissionSummary {
  tenant_id: string
  target_mode: RunningMode
  ready: boolean            // 全部 G1-G6 pass 才 ready
  gates: AdmissionGate[]
  blocking_reasons: string[]
}

export const ModeAPI = {
  /** 取当前用户租户模式 (后端 GET /api/v2/system/mode). */
  getGlobal(): Promise<ApiResponse<GlobalMode>> {
    return get('/v2/system/mode')
  },

  /**
   * 全局模式切换 - 通过给当前 tenant 设置 mode 实现 (POST /api/v2/admin/tenants/t-default/mode).
   * tenant_id 走默认; 多租户走 setTenant.
   */
  setGlobal(mode: RunningMode, reason: string): Promise<ApiResponse<GlobalMode>> {
    return post('/v2/admin/tenants/t-default/mode', { mode, reason })
  },

  /** 列出所有租户模式 (admin). */
  getTenant(tenantId: string): Promise<ApiResponse<TenantMode>> {
    return get(`/v2/admin/tenants/${tenantId}/mode`)
  },

  /** 租户模式切换 (POST /api/v2/admin/tenants/:id/mode). */
  setTenant(tenantId: string, mode: RunningMode, reason: string): Promise<ApiResponse<TenantMode>> {
    return post(`/v2/admin/tenants/${tenantId}/mode`, { mode, reason })
  },

  /** 列所有租户模式. */
  listTenantModes(): Promise<ApiResponse<TenantMode[]>> {
    return get('/v2/admin/tenants/modes')
  },

  /** 占位: 后续 PR 实现 host_label 覆盖 (后端尚未提供, 返回空). */
  listHostLabelOverrides(): Promise<ApiResponse<HostLabelOverride[]>> {
    return Promise.resolve({ code: 0, message: 'not implemented', data: [] } as ApiResponse<HostLabelOverride[]>)
  },

  /** 占位: 后续 PR 实现 rule 覆盖. */
  listRuleOverrides(): Promise<ApiResponse<RuleOverride[]>> {
    return Promise.resolve({ code: 0, message: 'not implemented', data: [] } as ApiResponse<RuleOverride[]>)
  },

  /** 6 闸门检查 (后端 endpoint 待实现, 占位返 ready=false). */
  checkAdmission(targetMode: RunningMode): Promise<ApiResponse<AdmissionSummary>> {
    return Promise.resolve({
      code: 0,
      message: 'not implemented',
      data: {
        tenant_id: 't-default',
        target_mode: targetMode,
        ready: false,
        gates: [],
        blocking_reasons: ['admission endpoint not yet exposed'],
      },
    } as ApiResponse<AdmissionSummary>)
  },
}
