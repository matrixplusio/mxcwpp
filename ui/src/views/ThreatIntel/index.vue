<template>
  <div class="threat-intel-page">
    <!-- 统计卡片 (统一 StatCard) -->
    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="6"><StatCard title="IOC 总数" :value="stats.total" color="#3B82F6" /></a-col>
      <a-col :span="6"><StatCard title="IP 指标" :value="stats.ip" color="#22C55E" /></a-col>
      <a-col :span="6"><StatCard title="Hash 指标" :value="stats.hash" color="#06B6D4" /></a-col>
      <a-col :span="6"><StatCard title="域名指标" :value="stats.domain" color="#F59E0B" /></a-col>
    </a-row>

    <!-- 同步状态栏 -->
    <div class="sync-status-bar">
      <div class="sync-status-left">
        <span class="sync-status-label">MISP 同步状态</span>
        <template v-if="syncStatus && 'version' in syncStatus">
          <a-tag :color="syncStatusColor(syncStatus.status)" :bordered="false">
            {{ syncStatusText(syncStatus.status) }}
          </a-tag>
          <span v-if="syncStatus.version" class="sync-status-info">
            版本 {{ syncStatus.version }}
          </span>
          <span class="sync-status-info">
            {{ formatDateTime(syncStatus.startedAt) }}
          </span>
          <span v-if="syncStatus.duration" class="sync-status-info">
            耗时 {{ syncStatus.duration }}s
          </span>
          <span v-if="syncStatus.fileSize" class="sync-status-info">
            IOC {{ syncStatus.fileSize }} 条
          </span>
          <a-tooltip v-if="syncStatus.status === 'failed' && syncStatus.errorMsg" :title="syncStatus.errorMsg">
            <span class="sync-status-error">{{ syncStatus.errorMsg }}</span>
          </a-tooltip>
        </template>
        <span v-else class="sync-status-info">尚未执行过同步</span>
      </div>
      <div class="sync-status-actions">
        <a-button size="small" @click="showSyncHistory">历史记录</a-button>
        <a-button size="small" type="primary" :loading="syncing" @click="handleSync">
          同步 MISP
        </a-button>
      </div>
    </div>

    <a-card>
      <!-- 操作栏 -->
      <div style="display: flex; justify-content: space-between; margin-bottom: 16px">
        <a-space>
          <a-select v-model:value="iocType" style="width: 120px" @change="fetchIOCs">
            <a-select-option value="ip">IP</a-select-option>
            <a-select-option value="hash">Hash</a-select-option>
            <a-select-option value="domain">域名</a-select-option>
            <a-select-option value="url">URL</a-select-option>
          </a-select>
          <a-input-search v-model:value="checkValue" placeholder="输入 IOC 值进行碰撞查询" style="width: 320px" @search="handleCheck" />
        </a-space>
      </div>

      <!-- 碰撞结果 -->
      <a-alert v-if="checkResult !== null" :type="checkResult.hit ? 'error' : 'success'" :message="checkResult.hit ? `命中威胁情报: ${checkResult.value}` : `未命中: ${checkResult.value}`" closable style="margin-bottom: 16px" @close="checkResult = null" />

      <!-- IOC 列表 -->
      <a-table :columns="columns" :data-source="tableData" :loading="loading" :pagination="pagination" row-key="value" @change="handleTableChange" />
    </a-card>

    <!-- 同步历史抽屉 -->
    <a-drawer
      v-model:open="syncHistoryVisible"
      title="MISP 同步历史"
      width="1080"
      placement="right"
    >
      <a-table
        :columns="syncHistoryColumns"
        :data-source="syncHistoryData"
        :loading="syncHistoryLoading"
        :pagination="syncHistoryPagination"
        size="small"
        row-key="id"
        @change="handleSyncHistoryTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'">
            <a-tag :color="syncStatusColor(record.status)" :bordered="false">
              {{ syncStatusText(record.status) }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'iocCount'">
            {{ record.fileSize || '-' }}
          </template>
          <template v-else-if="column.key === 'errorMsg'">
            <a-tooltip v-if="record.errorMsg" :title="record.errorMsg">
              <span style="color: #EF4444; font-size: 12px; cursor: pointer">{{ record.errorMsg }}</span>
            </a-tooltip>
            <span v-else>-</span>
          </template>
        </template>
      </a-table>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { message } from 'ant-design-vue'
import { threatIntelApi } from '@/api/threat-intel'
import type { SecurityDBSyncRecord } from '@/api/antivirus'
import { formatDateTime } from '@/utils/date'
import StatCard from '@/components/StatCard.vue'

const stats = ref({ total: 0, ip: 0, hash: 0, domain: 0, url: 0 })
const iocType = ref('ip')
const iocs = ref<string[]>([])
const loading = ref(false)
const syncing = ref(false)
const checkValue = ref('')
const checkResult = ref<{ hit: boolean; value: string } | null>(null)
const total = ref(0)
const currentPage = ref(1)
const pageSize = ref(50)

// 同步状态
const syncStatus = ref<SecurityDBSyncRecord | null>(null)
const syncHistoryVisible = ref(false)
const syncHistoryLoading = ref(false)
const syncHistoryData = ref<SecurityDBSyncRecord[]>([])
const syncHistoryPagination = ref({
  current: 1,
  pageSize: 10,
  total: 0,
  showSizeChanger: false,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  { title: '序号', key: 'index', width: 80, customRender: ({ index }: { index: number }) => (currentPage.value - 1) * pageSize.value + index + 1 },
  { title: 'IOC 值', dataIndex: 'value', key: 'value' },
  { title: '类型', key: 'type', width: 100, customRender: () => iocType.value.toUpperCase() },
]

const syncHistoryColumns = [
  { title: '版本', dataIndex: 'version', width: 160 },
  { title: '状态', key: 'status', width: 80 },
  { title: 'IOC 数量', key: 'iocCount', width: 100 },
  { title: '耗时(秒)', dataIndex: 'duration', width: 80 },
  { title: '开始时间', dataIndex: 'startedAt', width: 170, customRender: ({ text }: { text: string }) => formatDateTime(text) },
  { title: '错误信息', key: 'errorMsg', ellipsis: true },
]

const syncStatusColor = (status: string) => {
  if (status === 'success') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'running') return 'processing'
  return 'default'
}

const syncStatusText = (status: string) => {
  const map: Record<string, string> = { success: '成功', failed: '失败', running: '同步中' }
  return map[status] || status
}

const tableData = computed(() => iocs.value.map(v => ({ value: v })))
const pagination = computed(() => ({ current: currentPage.value, pageSize: pageSize.value, total: total.value, showSizeChanger: true }))

async function fetchStats() {
  try {
    const res = await threatIntelApi.getStats()
    if (res) stats.value = res
  } catch { /* ignore */ }
}

async function fetchIOCs() {
  loading.value = true
  try {
    const res = await threatIntelApi.listIOCs({ type: iocType.value, page: currentPage.value, page_size: pageSize.value })
    if (res) {
      iocs.value = res.items || []
      total.value = res.total || 0
    }
  } catch { /* ignore */ } finally {
    loading.value = false
  }
}

async function handleCheck() {
  if (!checkValue.value) return
  try {
    const res = await threatIntelApi.checkIOC(iocType.value, checkValue.value)
    if (res) checkResult.value = res
  } catch (error) {
    console.error('IOC 碰撞查询失败:', error)
  }
}

async function handleSync() {
  syncing.value = true
  try {
    await threatIntelApi.triggerSync()
    message.success('IOC 同步已触发')
    setTimeout(() => { loadSyncStatus(); fetchStats(); fetchIOCs() }, 3000)
  } catch (error) {
    console.error('触发 IOC 同步失败:', error)
  } finally {
    syncing.value = false
  }
}

async function loadSyncStatus() {
  try {
    const res = await threatIntelApi.getSyncStatus()
    if (res && 'version' in res) {
      syncStatus.value = res as SecurityDBSyncRecord
    } else {
      syncStatus.value = null
    }
  } catch {
    syncStatus.value = null
  }
}

async function showSyncHistory() {
  syncHistoryVisible.value = true
  await loadSyncHistory()
}

async function loadSyncHistory() {
  syncHistoryLoading.value = true
  try {
    const res = await threatIntelApi.getSyncHistory({
      page: syncHistoryPagination.value.current,
      page_size: syncHistoryPagination.value.pageSize,
    })
    syncHistoryData.value = res.items ?? []
    syncHistoryPagination.value.total = res.total ?? 0
  } catch {
    syncHistoryData.value = []
  } finally {
    syncHistoryLoading.value = false
  }
}

function handleTableChange(pag: { current: number; pageSize: number }) {
  currentPage.value = pag.current
  pageSize.value = pag.pageSize
  fetchIOCs()
}

function handleSyncHistoryTableChange(pag: { current: number }) {
  syncHistoryPagination.value.current = pag.current
  loadSyncHistory()
}

onMounted(() => {
  fetchStats()
  fetchIOCs()
  loadSyncStatus()
})
</script>

<style scoped>
.threat-intel-page {
  padding: 0;
}

.sync-status-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 16px;
  background: var(--mxsec-fill-1);
  border: 1px solid var(--mxsec-border);
  border-radius: 6px;
  margin-bottom: 16px;
}

.sync-status-left {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 1;
  min-width: 0;
}

.sync-status-label {
  font-weight: 500;
  color: var(--mxsec-text-1);
  white-space: nowrap;
}

.sync-status-info {
  color: var(--mxsec-text-3);
  font-size: 13px;
  white-space: nowrap;
}

.sync-status-error {
  color: #EF4444;
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 300px;
  cursor: pointer;
}

.sync-status-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
  margin-left: 16px;
}
</style>
