import apiClient from './client'

export interface KubeCheckConfig {
  resourceType: string
  apiGroup: string
  namespace: string
  expression: string
  matchPolicy: 'any_match_fail' | 'no_match_fail'
}

export interface KubeBaselineRule {
  id: number
  checkId: string
  checkName: string
  category: string
  severity: string
  description: string
  remediation: string
  benchmark: string
  checkConfig?: KubeCheckConfig | null
  enabled: boolean
  builtin: boolean
  hasCheckFunc?: boolean
  hasCheckConfig?: boolean
  createdAt: string
  updatedAt: string
}

export interface KubeBaselineRuleStats {
  totalRules: number
  enabled: number
  disabled: number
  builtin: number
}

export interface ListRulesResponse {
  total: number
  items: KubeBaselineRule[]
  stats: KubeBaselineRuleStats
}

export interface ImportResult {
  total: number
  created: number
  updated: number
  skipped: number
}

export interface CreateRuleParams {
  checkId: string
  checkName: string
  category: string
  severity: string
  description?: string
  remediation?: string
  benchmark?: string
  checkConfig?: KubeCheckConfig | null
}

export interface UpdateRuleParams {
  checkName?: string
  category?: string
  severity?: string
  description?: string
  remediation?: string
  benchmark?: string
  enabled?: boolean
  checkConfig?: KubeCheckConfig | null
}

export interface ExpressionTemplate {
  id: number
  name: string
  description: string
  resourceType: string
  apiGroup: string
  namespace: string
  expression: string
  matchPolicy: string
  builtin: boolean
  createdAt: string
  updatedAt: string
}

export interface ValidateResult {
  valid: boolean
  error?: string
}

export function listRules(params: Record<string, unknown>) {
  return apiClient.get<ListRulesResponse>('/kube/baseline-rules', { params })
}

export function getRule(id: number) {
  return apiClient.get<KubeBaselineRule>(`/kube/baseline-rules/${id}`)
}

export function createRule(data: CreateRuleParams) {
  return apiClient.post<KubeBaselineRule>('/kube/baseline-rules', data)
}

export function updateRule(id: number, data: UpdateRuleParams) {
  return apiClient.put<KubeBaselineRule>(`/kube/baseline-rules/${id}`, data)
}

export function deleteRule(id: number) {
  return apiClient.delete(`/kube/baseline-rules/${id}`)
}

export function toggleRule(id: number) {
  return apiClient.put(`/kube/baseline-rules/${id}/toggle`)
}

export function exportRules() {
  return apiClient.download('/kube/baseline-rules/export')
}

export function importRules(data: unknown[], mode: 'skip' | 'update' = 'skip') {
  return apiClient.post<ImportResult>(`/kube/baseline-rules/import?mode=${mode}`, data)
}

export function validateExpression(expression: string) {
  return apiClient.post<ValidateResult>('/kube/baseline-rules/validate-expression', { expression })
}

export function getExpressionTemplates() {
  return apiClient.get<ExpressionTemplate[]>('/kube/baseline-rules/expression-templates')
}

export interface CreateExpressionTemplateParams {
  name: string
  description?: string
  resourceType: string
  apiGroup?: string
  namespace?: string
  expression: string
  matchPolicy?: string
}

export interface UpdateExpressionTemplateParams {
  name?: string
  description?: string
  resourceType?: string
  apiGroup?: string
  namespace?: string
  expression?: string
  matchPolicy?: string
}

export function createExpressionTemplate(data: CreateExpressionTemplateParams) {
  return apiClient.post<ExpressionTemplate>('/kube/baseline-rules/expression-templates', data)
}

export function updateExpressionTemplate(id: number, data: UpdateExpressionTemplateParams) {
  return apiClient.put<ExpressionTemplate>(`/kube/baseline-rules/expression-templates/${id}`, data)
}

export function deleteExpressionTemplate(id: number) {
  return apiClient.delete(`/kube/baseline-rules/expression-templates/${id}`)
}
