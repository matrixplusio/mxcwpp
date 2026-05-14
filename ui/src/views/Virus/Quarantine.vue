<template>
  <div class="quarantine-page">
    <div class="page-header">
      <h2>文件隔离箱</h2>
      <span class="page-header-hint">管理被隔离的威胁文件，支持恢复或永久删除</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value">{{ statistics.quarantined }}</div>
          <div class="stat-label">隔离中</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value critical">{{ statistics.severity.critical + statistics.severity.high }}</div>
          <div class="stat-label">高危文件</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value primary">{{ statistics.affectedHosts }}</div>
          <div class="stat-label">涉及主机</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value">{{ formatFileSize(statistics.totalSize) }}</div>
          <div class="stat-label">占用空间</div>
        </div>
      </a-col>
    </a-row>

    <!-- 主内容 -->
    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search
            v-model:value="searchText"
            placeholder="搜索威胁名称、文件路径、主机名或 IP"
            style="width: 320px"
            allow-clear
            @search="handleFilterChange"
          />
          <a-select
            v-model:value="filterStatus"
            style="width: 140px"
            placeholder="状态"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="quarantined">隔离中</a-select-option>
            <a-select-option value="restored">已恢复</a-select-option>
            <a-select-option value="deleted">已删除</a-select-option>
          </a-select>
          <a-select
            v-model:value="filterSeverity"
            style="width: 140px"
            placeholder="严重级别"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="critical">紧急</a-select-option>
            <a-select-option value="high">高危</a-select-option>
            <a-select-option value="medium">中危</a-select-option>
            <a-select-option value="low">低危</a-select-option>
          </a-select>
          <a-select
            v-model:value="filterThreatType"
            style="width: 140px"
            placeholder="威胁类型"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="virus">病毒</a-select-option>
            <a-select-option value="trojan">木马</a-select-option>
            <a-select-option value="worm">蠕虫</a-select-option>
            <a-select-option value="ransomware">勒索</a-select-option>
            <a-select-option value="rootkit">Rootkit</a-select-option>
            <a-select-option value="miner">挖矿</a-select-option>
            <a-select-option value="backdoor">后门</a-select-option>
            <a-select-option value="other">其他</a-select-option>
          </a-select>

          <div class="filter-actions">
            <a-button @click="handleReset">重置</a-button>
            <a-button
              v-if="selectedRowKeys.length > 0"
              danger
              @click="handleBatchDelete"
            >
              批量删除 ({{ selectedRowKeys.length }})
            </a-button>
          </div>
        </div>

        <a-table
          :columns="columns"
          :data-source="files"
          :loading="loading"
          :pagination="pagination"
          :row-selection="{ selectedRowKeys, onChange: onSelectChange, getCheckboxProps: getCheckboxProps }"
          size="middle"
          row-key="id"
          @change="handleTableChange"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'threatName'">
              <a @click="showDetail(record)">{{ record.threatName }}</a>
            </template>
            <template v-else-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity]" :bordered="false">
                {{ severityTextMap[record.severity] || record.severity }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'threatType'">
              <a-tag :bordered="false">{{ threatTypeTextMap[record.threatType] || record.threatType }}</a-tag>
            </template>
            <template v-else-if="column.key === 'host'">
              <RouterLink :to="`/hosts/${record.hostId}`">{{ record.hostname || record.hostId }}</RouterLink>
              <div style="color: #86909C; font-size: 12px">{{ record.ip }}</div>
            </template>
            <template v-else-if="column.key === 'originalPath'">
              <span style="font-family: monospace; font-size: 12px; word-break: break-all">{{ record.originalPath }}</span>
            </template>
            <template v-else-if="column.key === 'fileSize'">
              {{ formatFileSize(record.fileSize) }}
            </template>
            <template v-else-if="column.key === 'status'">
              <a-tag :color="statusColorMap[record.status]" :bordered="false">
                {{ statusTextMap[record.status] || record.status }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a @click="showDetail(record)">详情</a>
                <template v-if="record.status === 'quarantined'">
                  <a-popconfirm title="确认恢复该文件到原始路径？" @confirm="handleRestore(record.id)">
                    <a style="color: #00B42A">恢复</a>
                  </a-popconfirm>
                  <a-popconfirm title="确认永久删除该文件？此操作不可逆。" @confirm="handleDelete(record.id)">
                    <a style="color: #F53F3F">删除</a>
                  </a-popconfirm>
                </template>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 详情抽屉 -->
    <a-drawer
      v-model:open="detailVisible"
      :title="detailRecord?.threatName || '隔离文件详情'"
      width="640"
      placement="right"
    >
      <template v-if="detailRecord">
        <a-descriptions :column="1" bordered size="small">
          <a-descriptions-item label="威胁名称">{{ detailRecord.threatName }}</a-descriptions-item>
          <a-descriptions-item label="威胁类型">
            <a-tag :bordered="false">{{ threatTypeTextMap[detailRecord.threatType] || detailRecord.threatType }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="严重级别">
            <a-tag :color="severityColorMap[detailRecord.severity]" :bordered="false">
              {{ severityTextMap[detailRecord.severity] || detailRecord.severity }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="状态">
            <a-tag :color="statusColorMap[detailRecord.status]" :bordered="false">
              {{ statusTextMap[detailRecord.status] || detailRecord.status }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="原始路径">
            <span style="font-family: monospace; font-size: 12px; word-break: break-all">{{ detailRecord.originalPath }}</span>
          </a-descriptions-item>
          <a-descriptions-item v-if="detailRecord.quarantinePath" label="隔离路径">
            <span style="font-family: monospace; font-size: 12px; word-break: break-all">{{ detailRecord.quarantinePath }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="文件哈希">
            <span style="font-family: monospace; font-size: 12px">{{ detailRecord.fileHash || '-' }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="文件大小">{{ formatFileSize(detailRecord.fileSize) }}</a-descriptions-item>
          <a-descriptions-item label="文件权限">{{ detailRecord.filePermission || '-' }}</a-descriptions-item>
          <a-descriptions-item label="文件属主">{{ detailRecord.fileOwner || '-' }}</a-descriptions-item>
          <a-descriptions-item label="主机">
            <RouterLink :to="`/hosts/${detailRecord.hostId}`">{{ detailRecord.hostname || detailRecord.hostId }}</RouterLink>
            <span style="color: #86909C; margin-left: 8px">{{ detailRecord.ip }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="隔离人">{{ detailRecord.quarantinedBy || '-' }}</a-descriptions-item>
          <a-descriptions-item label="隔离时间">{{ detailRecord.quarantinedAt }}</a-descriptions-item>
          <a-descriptions-item v-if="detailRecord.restoredAt" label="恢复时间">{{ detailRecord.restoredAt }}</a-descriptions-item>
          <a-descriptions-item v-if="detailRecord.deletedAt" label="删除时间">{{ detailRecord.deletedAt }}</a-descriptions-item>
        </a-descriptions>

        <template v-if="detailRecord.status === 'quarantined'">
          <a-divider />
          <a-space>
            <a-button type="primary" @click="handleRestore(detailRecord.id); detailVisible = false">
              恢复文件
            </a-button>
            <a-button danger @click="handleDelete(detailRecord.id); detailVisible = false">
              永久删除
            </a-button>
          </a-space>
        </template>
      </template>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { RouterLink } from 'vue-router'
import { message, Modal } from 'ant-design-vue'
import { quarantineApi } from '@/api/quarantine'
import type { QuarantineFile, QuarantineStatistics } from '@/api/quarantine'

// === 状态 ===
const loading = ref(false)
const files = ref<QuarantineFile[]>([])
const selectedRowKeys = ref<number[]>([])

const statistics = ref<QuarantineStatistics>({
  total: 0,
  quarantined: 0,
  restored: 0,
  deleted: 0,
  totalSize: 0,
  severity: { critical: 0, high: 0, medium: 0, low: 0 },
  affectedHosts: 0,
})

// === 筛选 ===
const searchText = ref('')
const filterStatus = ref<string>()
const filterSeverity = ref<string>()
const filterThreatType = ref<string>()

// === 分页 ===
const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

// === 详情 ===
const detailVisible = ref(false)
const detailRecord = ref<QuarantineFile>()

// === 映射表 ===
const severityColorMap: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityTextMap: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }
const threatTypeTextMap: Record<string, string> = { virus: '病毒', trojan: '木马', worm: '蠕虫', ransomware: '勒索', rootkit: 'Rootkit', miner: '挖矿', backdoor: '后门', other: '其他' }
const statusColorMap: Record<string, string> = { quarantined: 'orange', restored: 'green', deleted: 'default' }
const statusTextMap: Record<string, string> = { quarantined: '隔离中', restored: '已恢复', deleted: '已删除' }

// === 列定义 ===
const columns = [
  { title: '威胁名称', key: 'threatName', width: 180 },
  { title: '严重级别', key: 'severity', width: 90 },
  { title: '威胁类型', key: 'threatType', width: 90 },
  { title: '主机', key: 'host', width: 160 },
  { title: '原始路径', key: 'originalPath', ellipsis: true },
  { title: '文件大小', key: 'fileSize', width: 100 },
  { title: '状态', key: 'status', width: 90 },
  { title: '隔离时间', dataIndex: 'quarantinedAt', width: 170 },
  { title: '操作', key: 'action', width: 160, fixed: 'right' as const },
]

// === 数据加载 ===
const loadStatistics = async () => {
  try {
    statistics.value = await quarantineApi.getStatistics()
  } catch {
    // 静默处理
  }
}

const loadFiles = async () => {
  loading.value = true
  try {
    const res = await quarantineApi.list({
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      keyword: searchText.value || undefined,
      status: filterStatus.value || undefined,
      severity: filterSeverity.value || undefined,
      threat_type: filterThreatType.value || undefined,
    })
    files.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch {
    files.value = []
  } finally {
    loading.value = false
  }
}

// === 事件处理 ===
const handleFilterChange = () => {
  pagination.value.current = 1
  selectedRowKeys.value = []
  loadFiles()
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadFiles()
}

const handleReset = () => {
  searchText.value = ''
  filterStatus.value = undefined
  filterSeverity.value = undefined
  filterThreatType.value = undefined
  selectedRowKeys.value = []
  pagination.value.current = 1
  loadFiles()
}

const onSelectChange = (keys: number[]) => {
  selectedRowKeys.value = keys
}

const getCheckboxProps = (record: QuarantineFile) => ({
  disabled: record.status !== 'quarantined',
})

const showDetail = async (record: QuarantineFile) => {
  try {
    detailRecord.value = await quarantineApi.get(record.id)
    detailVisible.value = true
  } catch {
    // 全局拦截器已处理
  }
}

const handleRestore = async (id: number) => {
  try {
    await quarantineApi.restore(id)
    message.success('文件已恢复')
    loadFiles()
    loadStatistics()
  } catch {
    // 全局拦截器已处理
  }
}

const handleDelete = async (id: number) => {
  try {
    await quarantineApi.delete(id)
    message.success('文件已永久删除')
    loadFiles()
    loadStatistics()
  } catch {
    // 全局拦截器已处理
  }
}

const handleBatchDelete = () => {
  Modal.confirm({
    title: '批量永久删除',
    content: `确认永久删除选中的 ${selectedRowKeys.value.length} 个隔离文件？此操作不可逆。`,
    okText: '确认删除',
    okType: 'danger',
    cancelText: '取消',
    onOk: async () => {
      try {
        const res = await quarantineApi.batchDelete(selectedRowKeys.value)
        message.success(`已删除 ${res.deleted} 个文件`)
        selectedRowKeys.value = []
        loadFiles()
        loadStatistics()
      } catch {
        // 全局拦截器已处理
      }
    },
  })
}

// === 工具函数 ===
const formatFileSize = (bytes: number) => {
  if (!bytes || bytes === 0) return '-'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let size = bytes
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024
    i++
  }
  return `${size.toFixed(1)} ${units[i]}`
}

// === 初始化 ===
onMounted(() => {
  loadStatistics()
  loadFiles()
})
</script>

<style scoped>
.quarantine-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.stat-card {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: #1D2129;
}
.stat-value.critical { color: #F53F3F; }
.stat-value.primary { color: #165DFF; }

.stat-label {
  margin-top: 8px;
  font-size: 12px;
  color: #86909C;
}

.dashboard-card {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
}

.card-body { padding: 20px; }

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}

.filter-actions {
  display: flex;
  gap: 8px;
  margin-left: auto;
}

@media (max-width: 960px) {
  .filter-actions { margin-left: 0; }
}
</style>
