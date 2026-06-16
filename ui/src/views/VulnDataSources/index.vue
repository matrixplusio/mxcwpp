<template>
  <div class="vuln-data-sources-page">
    <div class="page-header">
      <h2>漏洞源管理</h2>
      <span class="page-header-hint">配置国内/国外漏洞数据库同步策略 · 实时同步状态</span>
    </div>

    <!-- 顶部 4 个统计卡 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="12" :md="6">
        <div class="vds-stat-card">
          <div class="vds-stat-value">{{ sources.length }}</div>
          <div class="vds-stat-label">数据源总数</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="vds-stat-card">
          <div class="vds-stat-value primary">{{ stats.enabled }}</div>
          <div class="vds-stat-label">已启用</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="vds-stat-card">
          <div class="vds-stat-value success">{{ stats.success }}</div>
          <div class="vds-stat-label">同步成功</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="vds-stat-card">
          <div class="vds-stat-value danger">{{ stats.failed }}</div>
          <div class="vds-stat-label">同步失败</div>
        </div>
      </a-col>
    </a-row>

    <!-- 主表格 -->
    <div class="table-card section-row">
      <div class="toolbar">
        <a-space>
          <a-select
            v-model:value="filterCategory"
            placeholder="按分类筛选"
            style="width: 180px"
            allow-clear
          >
            <a-select-option value="os_advisory">OS 厂商漏洞库</a-select-option>
            <a-select-option value="cve_metadata">CVE 标准元数据</a-select-option>
            <a-select-option value="exploit">0day / 已剥削</a-select-option>
            <a-select-option value="cn_official">国内官方</a-select-option>
          </a-select>
          <a-select
            v-model:value="filterRegion"
            placeholder="区域"
            style="width: 120px"
            allow-clear
          >
            <a-select-option value="global">国外</a-select-option>
            <a-select-option value="cn">国内</a-select-option>
          </a-select>
          <a-select
            v-model:value="filterStatus"
            placeholder="状态"
            style="width: 120px"
            allow-clear
          >
            <a-select-option value="success">成功</a-select-option>
            <a-select-option value="failed">失败</a-select-option>
            <a-select-option value="running">同步中</a-select-option>
            <a-select-option value="never">从未</a-select-option>
          </a-select>
        </a-space>
        <a-button :loading="loading" @click="loadSources">
          <template #icon><ReloadOutlined /></template>
          刷新
        </a-button>
      </div>

      <a-table
        :columns="columns"
        :data-source="filteredSources"
        :loading="loading"
        :pagination="false"
        size="middle"
        row-key="id"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'name'">
            <div class="name-cell">
              <div class="name-main">
                {{ record.displayName }}
                <a-tooltip v-if="record.baseUrl" placement="top">
                  <template #title>
                    <div class="url-tooltip">
                      <span class="url-tooltip-text">{{ record.baseUrl }}</span>
                      <a-button size="small" type="link" @click.stop="copyUrl(record.baseUrl)">复制</a-button>
                    </div>
                  </template>
                  <LinkOutlined class="name-link-icon" />
                </a-tooltip>
              </div>
              <div class="name-slug">{{ record.name }}</div>
            </div>
          </template>

          <template v-else-if="column.key === 'category'">
            <a-tag :color="categoryColor(record.category)" :bordered="false">
              {{ categoryLabel(record.category) }}
            </a-tag>
          </template>

          <template v-else-if="column.key === 'region'">
            <a-tag :color="record.region === 'cn' ? 'red' : 'blue'" :bordered="false">
              {{ record.region === 'cn' ? '国内' : '国外' }}
            </a-tag>
          </template>

          <template v-else-if="column.key === 'enabled'">
            <a-switch
              :checked="record.enabled"
              :loading="updatingId === record.id"
              size="small"
              @change="(v: boolean) => handleToggle(record, v)"
            />
          </template>

          <template v-else-if="column.key === 'status'">
            <a-tag :color="statusColor(record.lastStatus)" :bordered="false">
              <span class="status-dot" :class="`status-dot-${record.lastStatus}`"></span>
              {{ statusLabel(record.lastStatus) }}
            </a-tag>
          </template>

          <template v-else-if="column.key === 'count'">
            <span v-if="record.lastCount > 0" class="num-cell">{{ record.lastCount.toLocaleString() }}</span>
            <span v-else class="text-muted">—</span>
          </template>

          <template v-else-if="column.key === 'duration'">
            <span v-if="record.lastDurationMs > 0" class="num-cell">{{ formatDuration(record.lastDurationMs) }}</span>
            <span v-else class="text-muted">—</span>
          </template>

          <template v-else-if="column.key === 'lastSync'">
            <span v-if="record.lastSyncAt" class="time-cell">{{ formatTime(record.lastSyncAt) }}</span>
            <span v-else class="text-muted">从未</span>
          </template>

          <template v-else-if="column.key === 'error'">
            <a-tooltip v-if="record.lastError" :title="record.lastError" placement="topLeft">
              <span class="error-text">{{ truncate(record.lastError, 32) }}</span>
            </a-tooltip>
            <span v-else class="text-muted">—</span>
          </template>

          <template v-else-if="column.key === 'action'">
            <a-space :size="4">
              <a-button type="link" size="small" :loading="testingId === record.id" @click="handleTest(record)">
                测试
              </a-button>
              <a-button
                type="link"
                size="small"
                :disabled="!record.enabled"
                :loading="syncingId === record.id"
                @click="handleSync(record)"
              >
                同步
              </a-button>
            </a-space>
          </template>
        </template>
      </a-table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ReloadOutlined, LinkOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { vulnDataSourcesApi, type VulnDataSource } from '@/api/vuln-data-sources'

const sources = ref<VulnDataSource[]>([])
const loading = ref(false)
const updatingId = ref<number | null>(null)
const testingId = ref<number | null>(null)
const syncingId = ref<number | null>(null)

const filterCategory = ref<string>()
const filterRegion = ref<string>()
const filterStatus = ref<string>()

const stats = computed(() => ({
  enabled: sources.value.filter(s => s.enabled).length,
  success: sources.value.filter(s => s.lastStatus === 'success').length,
  failed: sources.value.filter(s => s.lastStatus === 'failed').length,
}))

const filteredSources = computed(() => {
  return sources.value.filter(s => {
    if (filterCategory.value && s.category !== filterCategory.value) return false
    if (filterRegion.value && s.region !== filterRegion.value) return false
    if (filterStatus.value && s.lastStatus !== filterStatus.value) return false
    return true
  })
})

const columns = [
  { title: '名称', key: 'name' },
  { title: '分类', key: 'category', width: 140 },
  { title: '区域', key: 'region', width: 80 },
  { title: '启用', key: 'enabled', width: 70, align: 'center' as const },
  { title: '状态', key: 'status', width: 110 },
  { title: '同步条数', key: 'count', width: 110, align: 'right' as const },
  { title: '耗时', key: 'duration', width: 80, align: 'right' as const },
  { title: '上次同步', key: 'lastSync', width: 160 },
  { title: '错误信息', key: 'error', width: 200, ellipsis: true },
  { title: '操作', key: 'action', width: 130, align: 'right' as const },
]

const loadSources = async () => {
  loading.value = true
  try {
    sources.value = await vulnDataSourcesApi.list()
  } catch (error) {
    console.error('加载数据源失败:', error)
  } finally {
    loading.value = false
  }
}

const handleToggle = async (record: VulnDataSource, enabled: boolean) => {
  updatingId.value = record.id
  try {
    const updated = await vulnDataSourcesApi.update(record.id, { enabled })
    const idx = sources.value.findIndex(s => s.id === record.id)
    if (idx >= 0) sources.value[idx] = updated
    message.success(`${record.displayName} 已${enabled ? '启用' : '禁用'}`)
  } catch (error) {
    console.error('切换数据源状态失败:', error)
  } finally {
    updatingId.value = null
  }
}

const handleTest = async (record: VulnDataSource) => {
  testingId.value = record.id
  try {
    const r = await vulnDataSourcesApi.testConnection(record.id)
    if (r.reachable) {
      message.success(`${record.displayName} 连通 (HTTP ${r.http_status})`)
    } else {
      message.error(`${record.displayName} 不可达: ${r.error || 'HTTP ' + r.http_status}`)
    }
  } catch (error) {
    console.error('测试连接失败:', error)
  } finally {
    testingId.value = null
  }
}

const handleSync = async (record: VulnDataSource) => {
  syncingId.value = record.id
  try {
    const r = await vulnDataSourcesApi.triggerSync(record.id)
    message.success(r?.message || '同步已触发')
    setTimeout(loadSources, 3000)
  } catch (error) {
    console.error('触发同步失败:', error)
  } finally {
    syncingId.value = null
  }
}

const copyUrl = async (url: string) => {
  try {
    await navigator.clipboard.writeText(url)
    message.success('已复制')
  } catch {
    message.error('复制失败')
  }
}

const categoryLabel = (c: string) => {
  switch (c) {
    case 'os_advisory':  return 'OS 厂商'
    case 'cve_metadata': return 'CVE 元数据'
    case 'exploit':      return '0day / Exploit'
    case 'cn_official':  return '国内官方'
    default:             return c
  }
}
const categoryColor = (c: string) => {
  switch (c) {
    case 'os_advisory':  return 'blue'
    case 'cve_metadata': return 'green'
    case 'exploit':      return 'orange'
    case 'cn_official':  return 'red'
    default:             return 'default'
  }
}

const statusColor = (s: string) => {
  switch (s) {
    case 'success': return 'green'
    case 'running': return 'blue'
    case 'failed':  return 'red'
    default:        return 'default'
  }
}
const statusLabel = (s: string) => {
  switch (s) {
    case 'success': return '成功'
    case 'running': return '同步中'
    case 'failed':  return '失败'
    default:        return '从未'
  }
}

const formatTime = (iso: string) => (iso ? iso.replace('T', ' ').slice(0, 19) : '')

const truncate = (s: string, n: number) => (s.length <= n ? s : s.slice(0, n) + '…')

const formatDuration = (ms: number) => {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  return `${(ms / 60_000).toFixed(1)}m`
}

onMounted(loadSources)
</script>

<style scoped>
.vuln-data-sources-page {
  padding: 16px 20px;
}

/* 页头（与 VulnList 一致） */
.page-header {
  margin-bottom: 16px;
}
.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}
.page-header-hint {
  margin-left: 8px;
  font-size: 13px;
  color: var(--ant-color-text-secondary);
}

.section-row {
  margin-bottom: 16px;
}

/* stat-card 复用 vuln-stat-card 风格 */
.vds-stat-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}
.vds-stat-value {
  font-size: 28px;
  font-weight: 700;
  color: var(--ant-color-text);
  line-height: 1.2;
  font-variant-numeric: tabular-nums;
}
.vds-stat-value.primary { color: #1677ff; }
.vds-stat-value.success { color: #22C55E; }
.vds-stat-value.danger  { color: #EF4444; }
.vds-stat-label {
  margin-top: 6px;
  font-size: 13px;
  color: var(--ant-color-text-secondary);
}

/* 主表格卡片 */
.table-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 16px;
}
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

/* table cell 样式 */
.name-cell {
  line-height: 1.4;
}
.name-main {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 500;
  color: var(--ant-color-text);
}
.name-link-icon {
  font-size: 12px;
  color: var(--ant-color-text-tertiary);
  cursor: pointer;
}
.name-link-icon:hover {
  color: var(--ant-color-primary);
}
.name-slug {
  font-family: 'SF Mono', Monaco, Consolas, monospace;
  font-size: 11px;
  color: var(--ant-color-text-tertiary);
  margin-top: 2px;
}

.status-dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  margin-right: 5px;
  vertical-align: middle;
  background: #d9d9d9;
}
.status-dot-success { background: #22C55E; }
.status-dot-running {
  background: #1677ff;
  animation: pulse 1.5s ease-in-out infinite;
}
.status-dot-failed  { background: #EF4444; }
.status-dot-never   { background: #d9d9d9; }
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

.num-cell {
  font-family: 'SF Mono', Monaco, Consolas, monospace;
  font-variant-numeric: tabular-nums;
}
.time-cell {
  font-family: 'SF Mono', Monaco, Consolas, monospace;
  font-size: 12px;
  color: var(--ant-color-text-secondary);
}
.error-text {
  color: var(--ant-color-error);
  font-size: 12px;
  cursor: help;
}
.text-muted {
  color: var(--ant-color-text-quaternary);
}

.url-tooltip {
  display: flex;
  align-items: center;
  gap: 8px;
}
.url-tooltip-text {
  font-family: 'SF Mono', Monaco, Consolas, monospace;
  font-size: 12px;
  word-break: break-all;
  max-width: 400px;
}
</style>
