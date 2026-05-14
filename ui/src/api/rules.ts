import apiClient from './client'
import type { Rule, CheckConfig, FixConfig, RuntimeType } from './types'

export interface RuleCreateData {
  rule_id: string
  category?: string
  title: string
  description?: string
  severity?: 'critical' | 'high' | 'medium' | 'low'
  runtime_types?: RuntimeType[]
  check_config: CheckConfig
  fix_config?: FixConfig
}

export interface RuleUpdateData {
  category?: string
  title?: string
  description?: string
  severity?: 'critical' | 'high' | 'medium' | 'low'
  enabled?: boolean
  runtime_types?: RuntimeType[]
  check_config?: CheckConfig
  fix_config?: FixConfig
}

export const rulesApi = {
  // 获取策略的规则列表
  list: (policyId: string) => {
    return apiClient.get<{ items: Rule[]; total: number }>(`/policies/${policyId}/rules`)
  },

  // 获取规则详情
  get: (ruleId: string) => {
    return apiClient.get<Rule>(`/rules/${ruleId}`)
  },

  // 创建规则
  create: (policyId: string, data: RuleCreateData) => {
    return apiClient.post<Rule>(`/policies/${policyId}/rules`, data)
  },

  // 更新规则
  update: (ruleId: string, data: RuleUpdateData) => {
    return apiClient.put<Rule>(`/rules/${ruleId}`, data)
  },

  // 删除规则
  delete: (ruleId: string) => {
    return apiClient.delete(`/rules/${ruleId}`)
  },
}
