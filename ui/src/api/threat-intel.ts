import apiClient from './client'
import type { SecurityDBSyncRecord } from './antivirus'

export const threatIntelApi = {
  getStats: () => {
    return apiClient.get<{ ip: number; hash: number; domain: number; url: number; total: number }>('/threat-intel/stats')
  },

  listIOCs: (params?: { type?: string; page?: number; page_size?: number }) => {
    return apiClient.get<{ items: string[]; total: number; type: string }>('/threat-intel/iocs', { params })
  },

  checkIOC: (type: string, value: string) => {
    return apiClient.post<{ hit: boolean; type: string; value: string }>('/threat-intel/check', { type, value })
  },

  triggerSync: () => {
    return apiClient.post<{ message: string }>('/threat-intel/sync')
  },

  getSyncStatus: () => {
    return apiClient.get<SecurityDBSyncRecord | { status: string; message: string }>('/threat-intel/sync-status')
  },

  getSyncHistory: (params?: { page?: number; page_size?: number }) => {
    return apiClient.get<{ total: number; items: SecurityDBSyncRecord[] }>('/threat-intel/sync-history', { params })
  },
}
