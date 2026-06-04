import apiClient from './client'

export interface FeatureFlag {
  id: number
  key: string
  value: string
  default_value: string
  description: string
  updated_by: string
  updated_at: string
  created_at: string
}

export interface RetentionPolicy {
  id: number
  ch_table: string
  display_name: string
  description: string
  retention_days: number
  updated_by: string
  updated_at: string
  created_at: string
}

export const adminDataConfigApi = {
  // Feature Flags
  listFlags: () => {
    return apiClient.get<{ items: FeatureFlag[]; total: number }>('/feature-flags')
  },
  updateFlag: (key: string, value: string) => {
    return apiClient.put<FeatureFlag>(`/feature-flags/${encodeURIComponent(key)}`, { value })
  },

  // Retention Policies
  listPolicies: () => {
    return apiClient.get<{ items: RetentionPolicy[]; total: number }>('/retention-policies')
  },
  updatePolicy: (chTable: string, retentionDays: number) => {
    return apiClient.put<RetentionPolicy>(`/retention-policies/${encodeURIComponent(chTable)}`, {
      retention_days: retentionDays,
    })
  },
}
