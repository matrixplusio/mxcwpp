<template>
  <div class="vuln-list-page">
    <div class="page-header">
      <h2>漏洞列表</h2>
      <span class="page-header-hint">主机漏洞扫描结果、CVE 明细与受影响主机</span>
    </div>

    <a-alert
      v-if="activeContextText"
      type="info"
      show-icon
      :message="activeContextText"
      style="margin-bottom: 16px"
    />

    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="12" :md="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value">{{ stats.total }}</div>
          <div class="vuln-stat-label">未修复漏洞</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value critical">{{ stats.critical }}</div>
          <div class="vuln-stat-label">紧急漏洞</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value high">{{ stats.high }}</div>
          <div class="vuln-stat-label">高危漏洞</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value primary">{{ stats.affectedHosts }}</div>
          <div class="vuln-stat-label">受影响主机</div>
        </div>
      </a-col>
    </a-row>

    <!-- 扫描状态栏 -->
    <div class="scan-status-bar section-row">
      <div class="scan-status-left">
        <span class="scan-status-label">漏洞库同步</span>
        <template v-if="scanStatus && 'version' in scanStatus">
          <a-tag :color="scanStatusColor(scanStatus.status)" :bordered="false">
            {{ scanStatusText(scanStatus.status) }}
          </a-tag>
          <span v-if="scanStatus.version" class="scan-status-info">
            版本 {{ scanStatus.version }}
          </span>
          <span class="scan-status-info">
            {{ formatDateTime(scanStatus.startedAt) }}
          </span>
          <span v-if="scanStatus.duration" class="scan-status-info">
            耗时 {{ scanStatus.duration }}s
          </span>
          <template v-if="scanStatus.errorMsg">
            <template v-if="parsedSourceResults.length > 0">
              <a-tag
                v-for="src in parsedSourceResults"
                :key="src.name"
                :color="src.status === 'success' ? 'green' : src.status === 'skipped' ? 'default' : 'red'"
                :bordered="false"
                size="small"
                style="margin-left: 4px"
              >
                <a-tooltip v-if="src.error" :title="src.error">
                  {{ src.name }}: {{ src.status === 'success' ? '成功' : src.status === 'skipped' ? '跳过' : '失败' }}
                </a-tooltip>
                <template v-else>
                  {{ src.name }}: {{ src.status === 'success' ? '成功' : src.status === 'skipped' ? '跳过' : '失败' }}
                </template>
              </a-tag>
            </template>
            <a-tooltip v-else :title="scanStatus.errorMsg">
              <span class="scan-status-error">{{ scanStatus.errorMsg }}</span>
            </a-tooltip>
          </template>
        </template>
        <span v-else class="scan-status-info">尚未执行过扫描</span>
      </div>
      <div class="scan-status-actions">
        <a-button size="small" @click="showScanHistory">历史记录</a-button>
        <a-button size="small" type="primary" @click="handleSync">手动同步</a-button>
      </div>
    </div>

    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search
            v-model:value="searchText"
            placeholder="搜索 CVE / CNVD / CNNVD / 组件 / 主机"
            style="width: 320px"
            allow-clear
            @search="handleFilterChange"
          />

          <a-input
            v-model:value="filterComponent"
            placeholder="组件 / 软件包"
            style="width: 220px"
            allow-clear
            @change="handleFilterChange"
          />

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
            v-model:value="filterStatus"
            style="width: 140px"
            placeholder="修复状态"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="unpatched">未修复</a-select-option>
            <a-select-option value="patched">已修复</a-select-option>
            <a-select-option value="ignored">已忽略</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterExploitStatus"
            style="width: 140px"
            placeholder="利用状态"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="in_kev">在野利用</a-select-option>
            <a-select-option value="has_exploit">有 Exploit</a-select-option>
            <a-select-option value="none">无 Exploit</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterPriority"
            style="width: 140px"
            placeholder="优先级"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="high">高</a-select-option>
            <a-select-option value="medium-high">中高</a-select-option>
            <a-select-option value="medium">中</a-select-option>
            <a-select-option value="low">低</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterSort"
            style="width: 160px"
            placeholder="排序方式"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="priority_score">按优先级</a-select-option>
            <a-select-option value="cvss_score">按 CVSS</a-select-option>
          </a-select>

          <div class="filter-actions">
            <a-button @click="handleReset">重置</a-button>
            <a-button @click="handleExport">导出当前结果</a-button>
            <a-dropdown>
              <a-button type="primary">立即扫描 <DownOutlined /></a-button>
              <template #overlay>
                <a-menu @click="handleScanMenu">
                  <a-menu-item key="full_scan">全量扫描</a-menu-item>
                  <a-menu-item key="incremental_scan">增量扫描</a-menu-item>
                </a-menu>
              </template>
            </a-dropdown>
          </div>
        </div>

        <div v-if="selectedRowKeys.length > 0" class="batch-action-bar">
          <span>已选择 {{ selectedRowKeys.length }} 项</span>
          <a-button type="primary" size="small" :loading="batchLoading" @click="handleBatchRemediate">
            批量创建修复任务
          </a-button>
          <a-button size="small" @click="selectedRowKeys = []">取消选择</a-button>
        </div>

        <a-table
          :columns="columns"
          :data-source="vulns"
          :loading="loading"
          :pagination="pagination"
          size="middle"
          row-key="id"
          :row-selection="{ selectedRowKeys, onChange: onSelectChange, getCheckboxProps: (record: Vulnerability) => ({ disabled: record.status !== 'unpatched' }) }"
          @change="handleTableChange"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'cve'">
              <RouterLink :to="`/vuln-list/${record.id}`">{{ record.cveId }}</RouterLink>
              <a-tag v-if="!record.cveId?.startsWith('CVE-')" color="orange" :bordered="false" style="margin-left: 4px; font-size: 10px; line-height: 16px">Advisory</a-tag>
            </template>

            <template v-else-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity] || 'default'" :bordered="false">
                {{ severityTextMap[record.severity] || record.severity }}
              </a-tag>
            </template>

            <template v-else-if="column.key === 'cvss'">
              <span :class="cvssClass(record.cvssScore)">{{ record.cvssScore }}</span>
            </template>

            <template v-else-if="column.key === 'exploit'">
              <a-tag v-if="record.inKev" color="red" :bordered="false">在野利用</a-tag>
              <a-tag v-else-if="record.hasExploit" color="orange" :bordered="false">有 Exploit</a-tag>
            </template>

            <template v-else-if="column.key === 'priority'">
              <a-tag :color="priorityColor(record.priorityScore)" :bordered="false">
                {{ priorityText(record.priorityScore) }}
              </a-tag>
              <span style="margin-left: 4px; font-size: 12px; color: #86909C">
                {{ (record.priorityScore ?? 0).toFixed(2) }}
              </span>
            </template>

            <template v-else-if="column.key === 'status'">
              <a-tag :color="statusColor(record.status)" :bordered="false">
                {{ statusTextMap[record.status] || record.status }}
              </a-tag>
            </template>

            <template v-else-if="column.key === 'hosts'">
              <span>{{ hostSummary(record) }}</span>
            </template>

            <template v-else-if="column.key === 'action'">
              <a-space>
                <RouterLink :to="`/vuln-list/${record.id}`">
                  <a-button type="link" size="small">详情</a-button>
                </RouterLink>
                <a-button
                  v-if="record.status === 'unpatched'"
                  type="link"
                  size="small"
                  @click="handleIgnore(record)"
                >
                  忽略
                </a-button>
                <a-button
                  v-if="record.status === 'ignored'"
                  type="link"
                  size="small"
                  @click="handleUnignore(record)"
                >
                  取消忽略
                </a-button>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 扫描历史抽屉 -->
    <a-drawer
      v-model:open="scanHistoryVisible"
      title="漏洞扫描历史"
      width="1080"
      placement="right"
    >
      <a-table
        :columns="scanHistoryColumns"
        :data-source="scanHistoryData"
        :loading="scanHistoryLoading"
        :pagination="scanHistoryPagination"
        size="small"
        row-key="id"
        @change="handleScanHistoryTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'">
            <a-tag :color="scanStatusColor(record.status)" :bordered="false">
              {{ scanStatusText(record.status) }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'errorMsg'">
            <template v-if="record.errorMsg && record.errorMsg.startsWith('[')">
              <a-tag
                v-for="src in JSON.parse(record.errorMsg)"
                :key="src.name"
                :color="src.status === 'success' ? 'green' : src.status === 'skipped' ? 'default' : 'red'"
                :bordered="false"
                size="small"
                style="margin-right: 4px"
              >
                <a-tooltip v-if="src.error" :title="src.error">{{ src.name }}</a-tooltip>
                <template v-else>{{ src.name }}</template>
              </a-tag>
            </template>
            <a-tooltip v-else-if="record.errorMsg" :title="record.errorMsg">
              <span style="color: #F53F3F; font-size: 12px; cursor: pointer">{{ record.errorMsg }}</span>
            </a-tooltip>
            <span v-else>-</span>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-button
              type="link"
              size="small"
              @click="goScanHistoryDetail(record.id)"
            >
              详情
            </a-button>
          </template>
        </template>
      </a-table>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { DownOutlined } from '@ant-design/icons-vue'
import { vulnerabilitiesApi } from '@/api/vulnerabilities'
import { remediationTasksApi } from '@/api/remediation-tasks'
import type { SecurityDBSyncRecord } from '@/api/antivirus'
import type { Vulnerability, VulnerabilityStats } from '@/api/types'
import { formatDateTime } from '@/utils/date'

const route = useRoute()
const router = useRouter()

const searchText = ref('')
const filterSeverity = ref<string>()
const filterStatus = ref<string>()
const filterComponent = ref('')
const filterExploitStatus = ref<string>()
const filterPriority = ref<string>()
const filterSort = ref<string>()
const filterHostId = ref<string>()

const loading = ref(false)
const vulns = ref<Vulnerability[]>([])
const stats = ref<VulnerabilityStats>({ total: 0, critical: 0, high: 0, affectedHosts: 0 })
const selectedRowKeys = ref<number[]>([])
const batchLoading = ref(false)

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

const statusTextMap: Record<string, string> = {
  unpatched: '未修复',
  patched: '已修复',
  ignored: '已忽略',
}

const activeContextText = computed(() => {
  const parts: string[] = []
  if (filterHostId.value) parts.push(`当前已按主机过滤: ${filterHostId.value}`)
  if (filterComponent.value) parts.push(`当前已按组件过滤: ${filterComponent.value}`)
  return parts.join(' | ')
})

const columns = [
  { title: '漏洞编号', key: 'cve', width: 180 },
  { title: '严重级别', key: 'severity', width: 90 },
  { title: 'CVSS', key: 'cvss', width: 70 },
  { title: '优先级', key: 'priority', width: 130 },
  { title: '利用状态', key: 'exploit', width: 100 },
  { title: '影响组件', dataIndex: 'component', key: 'component', width: 160 },
  { title: '受影响主机', key: 'hosts', width: 140 },
  { title: '状态', key: 'status', width: 90 },
  { title: '发现时间', dataIndex: 'discoveredAt', key: 'discoveredAt', width: 160 },
  { title: '操作', key: 'action', width: 120, fixed: 'right' },
]

// === 扫描状态 ===
const scanStatus = ref<SecurityDBSyncRecord | null>(null)

// 解析 errorMsg 中的数据源同步结果 JSON
const parsedSourceResults = computed(() => {
  const msg = scanStatus.value?.errorMsg
  if (!msg || !msg.startsWith('[')) return []
  try {
    return JSON.parse(msg) as { name: string; status: string; error?: string }[]
  } catch {
    return []
  }
})

const scanHistoryVisible = ref(false)
const scanHistoryLoading = ref(false)
const scanHistoryData = ref<SecurityDBSyncRecord[]>([])
const scanHistoryPagination = ref({
  current: 1,
  pageSize: 10,
  total: 0,
  showSizeChanger: false,
  showTotal: (total: number) => `共 ${total} 条`,
})

const scanHistoryColumns = [
  {
    title: '类型', dataIndex: 'dbType', width: 120,
    customRender: ({ text }: { text: string }) => {
      const m: Record<string, string> = { osv: '全量扫描', 'osv-incremental': '增量扫描', 'vuln-sync': '漏洞库同步' }
      return m[text] || text
    },
  },
  { title: '版本', dataIndex: 'version', width: 140 },
  { title: '状态', key: 'status', width: 80 },
  { title: '耗时(秒)', dataIndex: 'duration', width: 80 },
  { title: '开始时间', dataIndex: 'startedAt', width: 170, customRender: ({ text }: { text: string }) => formatDateTime(text) },
  { title: '扫描摘要', key: 'errorMsg', ellipsis: true },
  { title: '操作', key: 'action', width: 80, fixed: 'right' as const },
]

const scanStatusColor = (status: string) => {
  if (status === 'success') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'running') return 'processing'
  return 'default'
}

const scanStatusText = (status: string) => {
  const map: Record<string, string> = { success: '成功', failed: '失败', running: '扫描中' }
  return map[status] || status
}

const loadScanStatus = async () => {
  try {
    const res = await vulnerabilitiesApi.getScanStatus()
    if ('version' in res) {
      scanStatus.value = res as SecurityDBSyncRecord
    } else {
      scanStatus.value = null
    }
  } catch {
    scanStatus.value = null
  }
}

const showScanHistory = async () => {
  scanHistoryVisible.value = true
  await loadScanHistory()
}

const loadScanHistory = async () => {
  scanHistoryLoading.value = true
  try {
    const res = await vulnerabilitiesApi.getScanHistory({
      page: scanHistoryPagination.value.current,
      page_size: scanHistoryPagination.value.pageSize,
    })
    scanHistoryData.value = res.items ?? []
    scanHistoryPagination.value.total = res.total ?? 0
  } catch {
    scanHistoryData.value = []
  } finally {
    scanHistoryLoading.value = false
  }
}

const goScanHistoryDetail = (id: number) => {
  scanHistoryVisible.value = false
  router.push({ name: 'ScanHistoryDetail', params: { id } })
}

const handleScanHistoryTableChange = (pag: any) => {
  scanHistoryPagination.value.current = pag.current
  loadScanHistory()
}

const syncFiltersFromRoute = () => {
  searchText.value = typeof route.query.search === 'string' ? route.query.search : ''
  filterSeverity.value = typeof route.query.severity === 'string' ? route.query.severity : undefined
  filterStatus.value = typeof route.query.status === 'string' ? route.query.status : undefined
  filterComponent.value = typeof route.query.component === 'string' ? route.query.component : ''
  filterHostId.value = typeof route.query.host_id === 'string' ? route.query.host_id : undefined
}

const syncRouteQuery = () => {
  router.replace({
    query: {
      ...route.query,
      search: searchText.value || undefined,
      severity: filterSeverity.value || undefined,
      status: filterStatus.value || undefined,
      component: filterComponent.value || undefined,
      host_id: filterHostId.value || undefined,
    },
  })
}

const loadVulns = async () => {
  loading.value = true
  try {
    const res = await vulnerabilitiesApi.list({
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      host_id: filterHostId.value || undefined,
      search: searchText.value || undefined,
      severity: filterSeverity.value || undefined,
      status: filterStatus.value || undefined,
      component: filterComponent.value || undefined,
      exploit_status: filterExploitStatus.value || undefined,
      priority: filterPriority.value || undefined,
      sort: filterSort.value || undefined,
    })
    vulns.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    stats.value = res.stats ?? { total: 0, critical: 0, high: 0, affectedHosts: 0 }
  } catch {
    vulns.value = []
  } finally {
    loading.value = false
  }
}

const handleFilterChange = () => {
  pagination.value.current = 1
  syncRouteQuery()
  loadVulns()
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadVulns()
}

const handleIgnore = async (record: Vulnerability) => {
  try {
    await vulnerabilitiesApi.ignore(record.id)
    message.success('已忽略该漏洞')
    loadVulns()
  } catch {
    message.error('操作失败')
  }
}

const handleUnignore = async (record: Vulnerability) => {
  try {
    await vulnerabilitiesApi.unignore(record.id)
    message.success('已取消忽略')
    loadVulns()
  } catch {
    message.error('操作失败')
  }
}

const handleBatchRemediate = async () => {
  if (selectedRowKeys.value.length === 0) {
    message.warning('请先选择要修复的漏洞')
    return
  }
  batchLoading.value = true
  try {
    const res = await remediationTasksApi.batchCreate(selectedRowKeys.value)
    let msg = `已为 ${res.vulnCount} 个漏洞、${res.hostCount} 台主机创建 ${res.created} 个修复任务`
    if (res.skipped > 0) {
      msg += `，跳过 ${res.skipped} 个（已有进行中任务）`
    }
    msg += '，请前往修复任务页面确认执行'
    message.success(msg)
    selectedRowKeys.value = []
  } catch {
    message.error('批量创建修复任务失败')
  } finally {
    batchLoading.value = false
  }
}

const onSelectChange = (keys: number[]) => {
  selectedRowKeys.value = keys
}

const handleSync = async () => {
  try {
    await vulnerabilitiesApi.triggerSync()
    message.success('漏洞库同步任务已启动（NVD + Red Hat）')
    setTimeout(() => loadScanStatus(), 2000)
  } catch {
    message.error('启动漏洞库同步失败')
  }
}

const handleScanMenu = async ({ key }: { key: string }) => {
  const scanType = key as 'full_scan' | 'incremental_scan'
  const label = scanType === 'incremental_scan' ? '增量扫描' : '全量扫描'
  try {
    await vulnerabilitiesApi.triggerScan(scanType)
    message.success(`${label}任务已启动`)
    setTimeout(() => loadScanStatus(), 2000)
  } catch {
    message.error(`${label}任务启动失败`)
  }
}

const handleExport = () => {
  if (vulns.value.length === 0) {
    message.warning('当前没有可导出的漏洞数据')
    return
  }

  const rows = [
    ['CVE', 'CNVD', 'CNNVD', 'Severity', 'CVSS', 'PriorityScore', 'ExploitStatus', 'Component', 'AffectedHosts', 'Status', 'DiscoveredAt'],
    ...vulns.value.map((item) => [
      item.cveId,
      item.cnvdId || '',
      item.cnnvdId || '',
      item.severity,
      String(item.cvssScore ?? ''),
      String(item.priorityScore ?? ''),
      item.inKev ? '在野利用' : item.hasExploit ? '有Exploit' : '',
      item.component || '',
      String(item.affectedHosts ?? 0),
      item.status || '',
      item.discoveredAt || '',
    ]),
  ]

  const csv = rows
    .map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(','))
    .join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', `vulnerabilities_${new Date().toISOString().slice(0, 10)}.csv`)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
  message.success('已导出当前结果')
}

const handleReset = () => {
  searchText.value = ''
  filterSeverity.value = undefined
  filterStatus.value = undefined
  filterComponent.value = ''
  filterExploitStatus.value = undefined
  filterPriority.value = undefined
  filterSort.value = undefined
  filterHostId.value = undefined
  pagination.value.current = 1
  syncRouteQuery()
  loadVulns()
}

const hostSummary = (record: Vulnerability) => {
  // 全局视图：统一显示受影响主机数量
  if (!filterHostId.value) {
    const count = record.affectedHosts || record.hosts?.length || 0
    return `${count} 台主机`
  }
  // 按主机筛选时：显示主机名详情
  if (!record.hosts?.length) return `${record.affectedHosts || 0} 台主机`
  if (record.hosts.length === 1) {
    return `${record.hosts[0].hostname || record.hosts[0].hostId} (${record.hosts[0].ip || '-'})`
  }
  return `${record.hosts[0].hostname || record.hosts[0].hostId} 等 ${record.hosts.length} 台`
}

const statusColor = (status: string) => {
  if (status === 'patched') return 'green'
  if (status === 'ignored') return 'default'
  return 'red'
}

const cvssClass = (score: number) => {
  if (score >= 9) return 'score-critical'
  if (score >= 7) return 'score-high'
  return 'score-normal'
}

const priorityColor = (score?: number) => {
  if (!score) return 'default'
  if (score >= 0.75) return 'red'
  if (score >= 0.50) return 'orange'
  if (score >= 0.25) return 'gold'
  return 'blue'
}

const priorityText = (score?: number) => {
  if (!score) return '未评分'
  if (score >= 0.75) return '高'
  if (score >= 0.50) return '中高'
  if (score >= 0.25) return '中'
  return '低'
}

watch(
  () => route.query,
  () => {
    syncFiltersFromRoute()
    loadVulns()
  }
)

onMounted(() => {
  syncFiltersFromRoute()
  loadVulns()
  loadScanStatus()
})
</script>

<style scoped>
.vuln-list-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.vuln-stat-card {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}

.vuln-stat-value {
  font-size: 28px;
  font-weight: 700;
  color: #1D2129;
}

.vuln-stat-value.critical { color: #F53F3F; }
.vuln-stat-value.high { color: #FF7D00; }
.vuln-stat-value.primary { color: #165DFF; }

.vuln-stat-label {
  margin-top: 8px;
  font-size: 12px;
  color: #86909C;
}

.dashboard-card {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
}

.card-body {
  padding: 20px;
}

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

.score-critical {
  color: #F53F3F;
  font-weight: 700;
}

.score-high {
  color: #FF7D00;
  font-weight: 700;
}

.score-normal {
  color: #1D2129;
  font-weight: 600;
}

.batch-action-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  margin-bottom: 12px;
  background: #E8F3FF;
  border: 1px solid #BEDAFF;
  border-radius: 6px;
  font-size: 13px;
}

.scan-status-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  padding: 12px 20px;
}

.scan-status-left {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.scan-status-label {
  font-weight: 600;
  color: #1D2129;
}

.scan-status-info {
  color: #86909C;
  font-size: 13px;
}

.scan-status-error {
  color: #F53F3F;
  font-size: 13px;
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.scan-status-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}



@media (max-width: 960px) {
  .filter-actions {
    margin-left: 0;
  }
  .scan-status-bar { flex-direction: column; gap: 8px; align-items: flex-start; }
}
</style>
