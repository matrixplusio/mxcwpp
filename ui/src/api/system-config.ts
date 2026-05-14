import apiClient from './client'

export interface KubernetesImageConfig {
  repository: string
  versions: string[]
  default_version: string
}

export interface SiteConfig {
  site_name: string
  site_logo: string
  site_domain: string
  backend_url: string
}

export interface AlertConfig {
  repeat_alert_interval: number // 重复告警通知间隔（分钟）
  enable_periodic_summary: boolean // 是否启用定期汇总
}

export const systemConfigApi = {
  // 获取 Kubernetes 镜像配置
  getKubernetesImageConfig: async (): Promise<KubernetesImageConfig> => {
    return apiClient.get<KubernetesImageConfig>('/system-config/kubernetes-image')
  },

  // 更新 Kubernetes 镜像配置
  updateKubernetesImageConfig: async (data: {
    repository: string
    versions: string[]
    default_version: string
  }): Promise<KubernetesImageConfig> => {
    return apiClient.put<KubernetesImageConfig>('/system-config/kubernetes-image', data)
  },

  // 获取站点配置
  getSiteConfig: async (): Promise<SiteConfig> => {
    return apiClient.get<SiteConfig>('/system-config/site')
  },

  // 更新站点配置
  updateSiteConfig: async (data: {
    site_name: string
    site_logo?: string
    site_domain: string
    backend_url: string
  }): Promise<SiteConfig> => {
    return apiClient.put<SiteConfig>('/system-config/site', data)
  },

  // 上传 Logo
  uploadLogo: async (file: File): Promise<{ logo_url: string }> => {
    const formData = new FormData()
    formData.append('logo', file)
    return apiClient.post<{ logo_url: string }>('/system-config/upload-logo', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
  },

  // 获取告警配置
  getAlertConfig: async (): Promise<AlertConfig> => {
    return apiClient.get<AlertConfig>('/system-config/alert')
  },

  // 更新告警配置
  updateAlertConfig: async (data: AlertConfig): Promise<AlertConfig> => {
    return apiClient.put<AlertConfig>('/system-config/alert', data)
  },
}
