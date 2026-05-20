<template>
  <div class="vulndb-manage-page">
    <div class="page-header">
      <h2>漏洞库管理</h2>
      <span class="page-header-hint">管理本地漏洞数据库缓存，支持离线导入与过期清理</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value primary">{{ stats.mode || '-' }}</div>
          <div class="stat-label">运行模式</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value">{{ stats.totalCount ?? 0 }}</div>
          <div class="stat-label">漏洞总量</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value warning">{{ stats.unpatchedCount ?? 0 }}</div>
          <div class="stat-label">未修复</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value success">{{ stats.patchedCount ?? 0 }}</div>
          <div class="stat-label">已修复</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value time-value">{{ formatDate(stats.lastUpdated) }}</div>
          <div class="stat-label">最后更新</div>
        </div>
      </a-col>
    </a-row>

    <!-- 操作区域 -->
    <div class="dashboard-card" style="margin-bottom: 16px;">
      <div class="card-body">
        <div class="section-title">离线导入</div>
        <div class="upload-area">
          <a-upload
            :file-list="fileList"
            :before-upload="beforeUpload"
            :max-count="1"
            accept=".json,.gz,.zip"
            @remove="handleRemoveFile"
          >
            <a-button>
              <template #icon><UploadOutlined /></template>
              选择文件
            </a-button>
          </a-upload>
          <a-button
            type="primary"
            :disabled="fileList.length === 0"
            :loading="uploading"
            style="margin-left: 12px"
            @click="handleUpload"
          >
            开始导入
          </a-button>
          <a-popconfirm
            title="确定要清理所有已过期的缓存数据吗？"
            @confirm="handlePurge"
          >
            <a-button
              danger
              :loading="purging"
              style="margin-left: 12px"
            >
              清理过期缓存
            </a-button>
          </a-popconfirm>
        </div>
        <div class="upload-hint">
          支持 JSON / GZ / ZIP 格式的漏洞库离线包
        </div>
      </div>
    </div>

    <!-- 导入历史 -->
    <div class="dashboard-card">
      <div class="card-body">
        <div class="section-title">导入历史</div>
        <a-table
          :columns="importColumns"
          :data-source="importRecords"
          :loading="loadingImports"
          size="middle"
          row-key="id"
          :pagination="false"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'status'">
              <a-tag :color="importStatusColor(record.status)" :bordered="false">
                {{ importStatusText(record.status) }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'createdAt'">
              {{ formatDate(record.createdAt) }}
            </template>
          </template>
        </a-table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, reactive } from 'vue'
import { message } from 'ant-design-vue'
import { UploadOutlined } from '@ant-design/icons-vue'
import type { UploadFile } from 'ant-design-vue'
import apiClient from '@/api/client'

interface CacheStats {
  mode?: string
  totalCount?: number
  unpatchedCount?: number
  patchedCount?: number
  lastUpdated?: string
}

interface ImportRecord {
  id: number
  fileName: string
  fileSize: number
  status: string
  importedCount: number
  errorMsg?: string
  createdBy: string
  createdAt: string
}

const stats = reactive<CacheStats>({})
const fileList = ref<UploadFile[]>([])
const uploading = ref(false)
const purging = ref(false)
const loadingImports = ref(false)
const importRecords = ref<ImportRecord[]>([])

const importColumns = [
  { title: 'ID', dataIndex: 'id', width: 60 },
  { title: '文件名', dataIndex: 'fileName', width: 200 },
  { title: '文件大小', dataIndex: 'fileSize', width: 100, customRender: ({ text }: { text: number }) => formatFileSize(text) },
  { title: '导入数量', dataIndex: 'importedCount', width: 100 },
  { title: '状态', key: 'status', width: 100 },
  { title: '操作人', dataIndex: 'createdBy', width: 100 },
  { title: '导入时间', key: 'createdAt', width: 170 },
]

const importStatusColor = (status: string) => {
  const map: Record<string, string> = {
    success: 'success',
    failed: 'error',
    processing: 'processing',
    pending: 'default',
  }
  return map[status] || 'default'
}

const importStatusText = (status: string) => {
  const map: Record<string, string> = {
    success: '成功',
    failed: '失败',
    processing: '导入中',
    pending: '待处理',
  }
  return map[status] || status
}

const formatDate = (dateStr?: string): string => {
  if (!dateStr) return '-'
  return dateStr.replace('T', ' ').substring(0, 19)
}

const formatFileSize = (bytes: number): string => {
  if (!bytes || bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let size = bytes
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024
    i++
  }
  return `${size.toFixed(1)} ${units[i]}`
}

const loadStats = async () => {
  try {
    const data = await apiClient.get<CacheStats>('/vulnerabilities/cache/stats')
    Object.assign(stats, data)
  } catch {
    // ignore
  }
}

const loadImports = async () => {
  loadingImports.value = true
  try {
    const data = await apiClient.get<{ items: ImportRecord[]; total: number }>('/vulnerabilities/cache/imports')
    importRecords.value = data?.items ?? []
  } catch {
    importRecords.value = []
  } finally {
    loadingImports.value = false
  }
}

const beforeUpload = (file: UploadFile) => {
  fileList.value = [file]
  return false
}

const handleRemoveFile = () => {
  fileList.value = []
}

const handleUpload = async () => {
  if (fileList.value.length === 0) return
  const file = fileList.value[0]
  const formData = new FormData()
  formData.append('file', file as any)

  uploading.value = true
  try {
    await apiClient.post('/vulnerabilities/cache/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    message.success('导入成功')
    fileList.value = []
    loadStats()
    loadImports()
  } catch {
    message.error('导入失败')
  } finally {
    uploading.value = false
  }
}

const handlePurge = async () => {
  purging.value = true
  try {
    await apiClient.post('/vulnerabilities/cache/purge')
    message.success('过期缓存已清理')
    loadStats()
  } catch {
    message.error('清理失败')
  } finally {
    purging.value = false
  }
}

onMounted(() => {
  loadStats()
  loadImports()
})
</script>

<style scoped>
.vulndb-manage-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.page-header {
  display: flex;
  align-items: baseline;
  gap: 12px;
  margin-bottom: 24px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.page-header-hint {
  font-size: 13px;
  color: #86909C;
}

.stat-card {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  padding: 16px;
  text-align: center;
  min-height: 80px;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.stat-value { font-size: 24px; font-weight: 700; color: #1D2129; line-height: 1.2; }
.stat-value.primary { color: #165DFF; font-size: 16px; }
.stat-value.time-value { font-size: 14px; font-weight: 600; color: #1D2129; }
.stat-value.success { color: #52C41A; }
.stat-value.warning { color: #FF7D00; }

.stat-label { margin-top: 4px; font-size: 12px; color: #86909C; }

.dashboard-card { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; }
.card-body { padding: 20px; }

.section-title {
  font-size: 14px;
  font-weight: 600;
  color: #262626;
  margin-bottom: 12px;
}

.upload-area {
  display: flex;
  align-items: center;
}

.upload-hint {
  margin-top: 8px;
  font-size: 12px;
  color: #86909C;
}
</style>
