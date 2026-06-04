import apiClient from './client'
import type { PaginatedResponse } from './types'

export interface Storyline {
  id: number
  story_id: string
  host_id: string
  hostname: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'active' | 'resolved' | 'investigating'
  phase: string
  summary: string
  rule_names: string
  event_count: number
  alert_count: number
  risk_score: number
  first_seen_at: string
  last_seen_at: string
  resolved_at?: string
  resolved_by?: string
  created_at: string
  updated_at: string
}

export interface StorylineEvent {
  id: number
  story_id: string
  host_id: string
  data_type: number
  event_type: string
  pid: string
  exe: string
  detail: string
  rule_name: string
  severity: string
  timestamp: string
  created_at: string
}

export interface StorylineDetail {
  storyline: Storyline
  events: StorylineEvent[]
  events_total: number
  events_page: number
  events_page_size: number
}

export interface GetStorylineParams {
  page?: number
  page_size?: number
}

export interface StorylineStats {
  total: number
  active: number
  critical_active: number
}

export interface ListStorylineParams {
  page?: number
  page_size?: number
  host_id?: string
  severity?: string
  status?: string
}

export const storylineApi = {
  list: (params?: ListStorylineParams) => {
    return apiClient.get<PaginatedResponse<Storyline>>('/storylines', { params })
  },

  get: (storyId: string, params?: GetStorylineParams) => {
    return apiClient.get<StorylineDetail>(`/storylines/${storyId}`, { params })
  },

  resolve: (storyId: string) => {
    return apiClient.post(`/storylines/${storyId}/resolve`)
  },

  stats: () => {
    return apiClient.get<StorylineStats>('/storylines/stats')
  },
}
