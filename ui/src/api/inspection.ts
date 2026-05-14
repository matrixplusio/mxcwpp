import apiClient from './client'

export interface PluginStatus {
  name: string
  version: string
  status: string
  latest_version: string
  need_update: boolean
}

export interface InspectionHostItem {
  host_id: string
  hostname: string
  ipv4: string[]
  status: string
  agent_version: string
  agent_start_time: string | null
  system_boot_time: string | null
  last_heartbeat: string | null
  os_family: string
  os_version: string
  arch: string
  runtime_type: string
  business_line: string
  plugins: PluginStatus[]
}

export interface InspectionSummary {
  total_hosts: number
  online_hosts: number
  offline_hosts: number
  agent_outdated_count: number
  plugin_error_count: number
  plugin_outdated_count: number
}

export interface InspectionOverview {
  summary: InspectionSummary
  latest_agent_version: string
  latest_plugin_versions: Record<string, string>
  hosts: InspectionHostItem[]
}

export const inspectionApi = {
  getOverview: () => {
    return apiClient.get<InspectionOverview>('/inspection/overview')
  },
}
