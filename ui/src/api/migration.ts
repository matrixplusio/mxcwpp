import apiClient from './client'
import type { PaginatedResponse } from './types'

// 连接测试结果
export interface TestConnectionResult {
  version: string
  tables: Record<string, number>
}

// 表报告
export interface TableReport {
  table: string
  total: number
  created: number
  skipped: number
  failed: number
  skip_reasons?: string[]
  fail_errors?: string[]
}

// 迁移任务
export interface MigrationJob {
  id: number
  source_url: string
  source_user: string
  scope: string[]
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  current_table: string
  total_records: number
  created_count: number
  skipped_count: number
  failed_count: number
  report_data?: TableReport[]
  error: string
  operator_id: number
  started_at: string | null
  finished_at: string | null
  created_at: string
  updated_at: string
}

export const migrationApi = {
  // 测试连接
  testConnection: (data: { url: string; username: string; password: string }) => {
    return apiClient.post<TestConnectionResult>('/system/migration/test-connection', data)
  },

  // 启动迁移
  startJob: (data: { url: string; username: string; password: string; scope: string[] }) => {
    return apiClient.post<MigrationJob>('/system/migration/jobs', data)
  },

  // 获取迁移任务列表
  listJobs: (params?: { page?: number; page_size?: number }) => {
    return apiClient.get<PaginatedResponse<MigrationJob>>('/system/migration/jobs', { params })
  },

  // 获取迁移任务详情
  getJob: (id: number) => {
    return apiClient.get<MigrationJob>(`/system/migration/jobs/${id}`)
  },

  // 取消迁移任务
  cancelJob: (id: number) => {
    return apiClient.post(`/system/migration/jobs/${id}/cancel`)
  },
}
