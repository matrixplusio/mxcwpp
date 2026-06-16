<template>
  <div class="host-antivirus-scan">
    <a-row :gutter="[16, 16]" style="margin-bottom: 16px">
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value">{{ stats.total }}</div>
          <div class="stat-label">威胁总数</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value critical">{{ stats.critical }}</div>
          <div class="stat-label">紧急威胁</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value high">{{ stats.high }}</div>
          <div class="stat-label">高危威胁</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value quarantined">{{ stats.quarantined }}</div>
          <div class="stat-label">已隔离</div>
        </div>
      </a-col>
    </a-row>

    <a-card title="病毒查杀" :bordered="false">
      <div class="filter-bar">
        <a-input-search
          v-model:value="keyword"
          placeholder="搜索文件路径或威胁名称"
          style="width: 280px"
          allow-clear
          @search="handleFilterChange"
        />
        <a-select
          v-model:value="filterSeverity"
          style="width: 120px"
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
          v-model:value="filterAction"
          style="width: 120px"
          placeholder="处置状态"
          allow-clear
          @change="handleFilterChange"
        >
          <a-select-option value="detected">已检出</a-select-option>
          <a-select-option value="quarantined">已隔离</a-select-option>
          <a-select-option value="deleted">已删除</a-select-option>
          <a-select-option value="ignored">已忽略</a-select-option>
        </a-select>
        <a-button @click="handleReset">重置</a-button>
      </div>

      <a-table
        :columns="columns"
        :data-source="results"
        :loading="loading"
        :pagination="pagination"
        size="middle"
        row-key="id"
        @change="handleTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'severity'">
            <a-tag :color="severityColorMap[record.severity]" :bordered="false">
              {{ severityTextMap[record.severity] || record.severity }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-tag :color="actionColorMap[record.action]" :bordered="false">
              {{ actionTextMap[record.action] || record.action }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'operations'">
            <a-space>
              <a-button type="link" size="small" @click="openDetail(record)">详情</a-button>
              <a-button
                v-if="record.action === 'detected'"
                type="link"
                size="small"
                danger
                @click="handleQuarantine(record)"
              >
                隔离
              </a-button>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-drawer
      v-model:open="showDetail"
      :title="detailRecord?.threatName || '威胁详情'"
      width="640"
      placement="right"
    >
      <template v-if="detailRecord">
        <a-descriptions :column="1" bordered size="small">
          <a-descriptions-item label="威胁名称">{{ detailRecord.threatName }}</a-descriptions-item>
          <a-descriptions-item label="威胁类型">{{ detailRecord.threatType || '-' }}</a-descriptions-item>
          <a-descriptions-item label="严重级别">
            <a-tag :color="severityColorMap[detailRecord.severity]" :bordered="false">
              {{ severityTextMap[detailRecord.severity] || detailRecord.severity }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="文件路径">{{ detailRecord.filePath }}</a-descriptions-item>
          <a-descriptions-item label="文件哈希">{{ detailRecord.fileHash || '-' }}</a-descriptions-item>
          <a-descriptions-item label="文件大小">{{ formatFileSize(detailRecord.fileSize) }}</a-descriptions-item>
          <a-descriptions-item label="处置状态">
            <a-tag :color="actionColorMap[detailRecord.action]" :bordered="false">
              {{ actionTextMap[detailRecord.action] || detailRecord.action }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="检测时间">{{ detailRecord.detectedAt || '-' }}</a-descriptions-item>
        </a-descriptions>
      </template>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { message } from 'ant-design-vue'
import { antivirusApi } from '@/api/antivirus'
import type { AntivirusScanResult } from '@/api/antivirus'

const props = defineProps<{
  hostId: string
}>()

const keyword = ref('')
const filterSeverity = ref<string>()
const filterAction = ref<string>()
const loading = ref(false)
const results = ref<AntivirusScanResult[]>([])
const showDetail = ref(false)
const detailRecord = ref<AntivirusScanResult>()
const stats = ref({ total: 0, critical: 0, high: 0, quarantined: 0 })

const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const severityColorMap: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'blue',
}

const severityTextMap: Record<string, string> = {
  critical: '紧急',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const actionColorMap: Record<string, string> = {
  detected: 'red',
  quarantined: 'orange',
  deleted: 'default',
  ignored: 'default',
}

const actionTextMap: Record<string, string> = {
  detected: '已检出',
  quarantined: '已隔离',
  deleted: '已删除',
  ignored: '已忽略',
}

const columns = [
  { title: '文件路径', dataIndex: 'filePath', key: 'filePath', ellipsis: true },
  { title: '威胁名称', dataIndex: 'threatName', key: 'threatName', width: 180 },
  { title: '严重级别', key: 'severity', width: 100 },
  { title: '处置状态', key: 'action', width: 100 },
  { title: '检测时间', dataIndex: 'detectedAt', key: 'detectedAt', width: 170 },
  { title: '操作', key: 'operations', width: 120 },
]

const loadResults = async () => {
  if (!props.hostId) return
  loading.value = true
  try {
    const res = await antivirusApi.listResults({
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      host_id: props.hostId,
      keyword: keyword.value || undefined,
      severity: filterSeverity.value || undefined,
      action: filterAction.value || undefined,
    })
    results.value = res.items ?? []
    pagination.value.total = res.total ?? 0

    const all = results.value
    stats.value = {
      total: res.total ?? 0,
      critical: all.filter(r => r.severity === 'critical').length,
      high: all.filter(r => r.severity === 'high').length,
      quarantined: all.filter(r => r.action === 'quarantined').length,
    }
  } catch {
    results.value = []
  } finally {
    loading.value = false
  }
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadResults()
}

const handleFilterChange = () => {
  pagination.value.current = 1
  loadResults()
}

const handleReset = () => {
  keyword.value = ''
  filterSeverity.value = undefined
  filterAction.value = undefined
  pagination.value.current = 1
  loadResults()
}

const handleQuarantine = async (record: AntivirusScanResult) => {
  try {
    await antivirusApi.quarantineResult(record.id)
    message.success('已隔离该文件')
    loadResults()
  } catch (error) {
    console.error('隔离文件失败:', error)
  }
}

const openDetail = (record: AntivirusScanResult) => {
  detailRecord.value = record
  showDetail.value = true
}

const formatFileSize = (bytes: number): string => {
  if (!bytes) return '-'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

onMounted(() => {
  loadResults()
})

watch(
  () => props.hostId,
  () => {
    pagination.value.current = 1
    loadResults()
  }
)
</script>

<style scoped>
.host-antivirus-scan {
  width: 100%;
}

.stat-card {
  padding: 18px;
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  text-align: center;
}

.stat-value {
  font-size: 24px;
  font-weight: 700;
  color: var(--mxsec-text-1);
}

.stat-value.critical { color: #EF4444; }
.stat-value.high { color: #F59E0B; }
.stat-value.quarantined { color: #F59E0B; }

.stat-label {
  margin-top: 8px;
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}
</style>
