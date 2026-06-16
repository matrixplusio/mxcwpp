<template>
  <div class="bulletin-list-page">
    <div class="page-header">
      <h2>漏洞通报</h2>
      <span class="page-header-hint">CVE 漏洞通报管理、SLA 跟踪与处置</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value">{{ statistics.active }}</div>
          <div class="stat-label">活跃通报</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value critical">{{ statistics.by_priority?.P0 ?? 0 }}</div>
          <div class="stat-label">P0 紧急</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value high">{{ statistics.by_priority?.P1 ?? 0 }}</div>
          <div class="stat-label">P1 高危</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value" :class="{ 'sla-breach': statistics.sla_breached > 0 }">
            {{ statistics.sla_breached }}
          </div>
          <div class="stat-label">SLA 超时</div>
        </div>
      </a-col>
    </a-row>

    <div class="dashboard-card">
      <div class="card-body">
        <!-- 筛选栏 -->
        <div class="filter-bar">
          <a-input-search
            v-model:value="searchText"
            placeholder="搜索 CVE / 组件 / 通报编号"
            style="width: 280px"
            allow-clear
            @search="handleFilterChange"
          />

          <a-select
            v-model:value="filterPriority"
            style="width: 120px"
            placeholder="优先级"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="P0">P0 紧急</a-select-option>
            <a-select-option value="P1">P1 高危</a-select-option>
            <a-select-option value="P2">P2 中危</a-select-option>
            <a-select-option value="P3">P3 低危</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterStatus"
            style="width: 120px"
            placeholder="状态"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="pending">待处理</a-select-option>
            <a-select-option value="notified">已通知</a-select-option>
            <a-select-option value="acknowledged">已确认</a-select-option>
            <a-select-option value="resolved">已修复</a-select-option>
            <a-select-option value="ignored">已忽略</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterSlaBreached"
            style="width: 120px"
            placeholder="SLA 状态"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="true">SLA 超时</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterSort"
            style="width: 140px"
            placeholder="排序方式"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="priority">按优先级</a-select-option>
            <a-select-option value="-cvss_score">按 CVSS</a-select-option>
            <a-select-option value="-created_at">最新创建</a-select-option>
          </a-select>

          <div class="filter-actions">
            <a-button @click="handleReset">重置</a-button>
            <a-button @click="handleExport">导出</a-button>
            <a-button type="primary" @click="showConfigDrawer">通报配置</a-button>
          </div>
        </div>

        <!-- 批量操作栏 -->
        <div v-if="selectedRowKeys.length > 0" class="batch-action-bar">
          <span>已选择 {{ selectedRowKeys.length }} 项</span>
          <a-button type="primary" size="small" :loading="batchLoading" @click="handleBatchAction('acknowledge')">
            批量确认
          </a-button>
          <a-button size="small" :loading="batchLoading" @click="handleBatchAction('resolve')">
            批量修复
          </a-button>
          <a-button size="small" :loading="batchLoading" @click="handleBatchAction('ignore')">
            批量忽略
          </a-button>
          <a-button size="small" @click="selectedRowKeys = []">取消选择</a-button>
        </div>

        <!-- 通报列表 -->
        <a-table
          :columns="columns"
          :data-source="bulletins"
          :loading="loading"
          :pagination="pagination"
          size="middle"
          row-key="id"
          :row-selection="{
            selectedRowKeys,
            onChange: onSelectChange,
            getCheckboxProps: (record: VulnBulletin) => ({
              disabled: record.status === 'resolved' || record.status === 'ignored',
            }),
          }"
          @change="handleTableChange"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'bulletinNo'">
              <RouterLink :to="`/vuln-bulletins/${record.id}`">{{ record.bulletinNo }}</RouterLink>
            </template>

            <template v-else-if="column.key === 'cveId'">
              <RouterLink :to="`/vuln-list/${record.vulnId}`">{{ record.cveId }}</RouterLink>
            </template>

            <template v-else-if="column.key === 'priority'">
              <a-tag :color="priorityColorMap[record.priority]" :bordered="false">
                {{ priorityTextMap[record.priority] }}
              </a-tag>
            </template>

            <template v-else-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity]" :bordered="false">
                {{ severityTextMap[record.severity] }}
              </a-tag>
            </template>

            <template v-else-if="column.key === 'cvssScore'">
              <span :class="cvssClass(record.cvssScore)">{{ record.cvssScore }}</span>
            </template>

            <template v-else-if="column.key === 'exploit'">
              <a-tag v-if="record.inKev" color="red" :bordered="false">在野利用</a-tag>
              <a-tag v-else-if="record.hasExploit" color="orange" :bordered="false">有 Exploit</a-tag>
              <span v-else style="color: #86909C">-</span>
            </template>

            <template v-else-if="column.key === 'status'">
              <a-tag :color="statusColorMap[record.status]" :bordered="false">
                {{ statusTextMap[record.status] }}
              </a-tag>
              <a-tag v-if="record.slaBreached" color="red" :bordered="false" style="margin-left: 4px">
                SLA
              </a-tag>
            </template>

            <template v-else-if="column.key === 'affectedAssets'">
              {{ record.affectedAssets }} 台
            </template>

            <template v-else-if="column.key === 'createdAt'">
              {{ formatDateTime(record.createdAt) }}
            </template>

            <template v-else-if="column.key === 'action'">
              <a-space>
                <RouterLink :to="`/vuln-bulletins/${record.id}`">
                  <a-button type="link" size="small">详情</a-button>
                </RouterLink>
                <a-button
                  v-if="record.status === 'pending' || record.status === 'notified'"
                  type="link"
                  size="small"
                  @click="handleAcknowledge(record)"
                >
                  确认
                </a-button>
                <a-button
                  v-if="record.status === 'acknowledged'"
                  type="link"
                  size="small"
                  @click="handleResolve(record)"
                >
                  修复
                </a-button>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 通报配置抽屉 -->
    <a-drawer
      v-model:open="configVisible"
      title="漏洞通报配置"
      width="560"
      placement="right"
    >
      <a-spin :spinning="configLoading">
        <a-form :label-col="{ span: 8 }" :wrapper-col="{ span: 16 }">
          <a-divider orientation="left">基本设置</a-divider>
          <a-form-item label="启用通报">
            <a-switch v-model:checked="configForm.enabled" />
          </a-form-item>
          <a-form-item label="自动创建">
            <a-switch v-model:checked="configForm.auto_create" />
          </a-form-item>
          <a-form-item label="通报等级">
            <a-checkbox-group v-model:value="configForm.notify_priorities">
              <a-checkbox value="P0"><a-tag color="red" :bordered="false">P0 紧急</a-tag></a-checkbox>
              <a-checkbox value="P1"><a-tag color="orange" :bordered="false">P1 高危</a-tag></a-checkbox>
              <a-checkbox value="P2"><a-tag color="blue" :bordered="false">P2 中危</a-tag></a-checkbox>
              <a-checkbox value="P3"><a-tag :bordered="false">P3 低危</a-tag></a-checkbox>
            </a-checkbox-group>
            <div style="margin-top: 4px; font-size: 12px; color: #86909C">
              仅勾选的等级会自动创建通报并发送通知
            </div>
          </a-form-item>

          <a-divider orientation="left">SLA 确认时限（小时）</a-divider>
          <a-form-item label="P0 确认">
            <a-input-number v-model:value="configForm.p0_ack_hours" :min="1" />
          </a-form-item>
          <a-form-item label="P1 确认">
            <a-input-number v-model:value="configForm.p1_ack_hours" :min="1" />
          </a-form-item>
          <a-form-item label="P2 确认">
            <a-input-number v-model:value="configForm.p2_ack_hours" :min="1" />
          </a-form-item>
          <a-form-item label="P3 确认">
            <a-input-number v-model:value="configForm.p3_ack_hours" :min="1" />
          </a-form-item>

          <a-divider orientation="left">SLA 修复时限（小时）</a-divider>
          <a-form-item label="P0 修复">
            <a-input-number v-model:value="configForm.p0_resolve_hours" :min="1" />
          </a-form-item>
          <a-form-item label="P1 修复">
            <a-input-number v-model:value="configForm.p1_resolve_hours" :min="1" />
          </a-form-item>
          <a-form-item label="P2 修复">
            <a-input-number v-model:value="configForm.p2_resolve_hours" :min="1" />
          </a-form-item>
          <a-form-item label="P3 修复">
            <a-input-number v-model:value="configForm.p3_resolve_hours" :min="1" />
          </a-form-item>

          <a-divider orientation="left">升级通知</a-divider>
          <a-form-item label="启用升级">
            <a-switch v-model:checked="configForm.escalation_enabled" />
          </a-form-item>
          <a-form-item label="P0 升级间隔(分)">
            <a-input-number v-model:value="configForm.p0_escalation_minutes" :min="5" />
          </a-form-item>
          <a-form-item label="P1 升级间隔(分)">
            <a-input-number v-model:value="configForm.p1_escalation_minutes" :min="5" />
          </a-form-item>

          <a-form-item :wrapper-col="{ offset: 8, span: 16 }">
            <a-space>
              <a-button type="primary" :loading="configSaving" @click="handleSaveConfig">保存</a-button>
              <a-button @click="configVisible = false">取消</a-button>
            </a-space>
          </a-form-item>
        </a-form>
      </a-spin>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { message, Modal } from 'ant-design-vue'
import { vulnBulletinsApi } from '@/api/vuln-bulletins'
import type { VulnBulletin, BulletinStatistics, VulnBulletinConfig } from '@/api/vuln-bulletins'
import { formatDateTime } from '@/utils/date'

const route = useRoute()
const router = useRouter()

// 筛选
const searchText = ref('')
const filterPriority = ref<string>()
const filterStatus = ref<string>()
const filterSlaBreached = ref<string>()
const filterSort = ref<string>()

// 数据
const loading = ref(false)
const bulletins = ref<VulnBulletin[]>([])
const statistics = ref<BulletinStatistics>({
  active: 0,
  sla_breached: 0,
  by_priority: {},
  by_status: {},
})
const selectedRowKeys = ref<number[]>([])
const batchLoading = ref(false)

// 分页
const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

// 配置抽屉
const configVisible = ref(false)
const configLoading = ref(false)
const configSaving = ref(false)
const configForm = ref<VulnBulletinConfig>({
  enabled: true,
  auto_create: true,
  notify_priorities: ['P0', 'P1', 'P2'],
  p0_ack_hours: 1,
  p0_resolve_hours: 24,
  p1_ack_hours: 4,
  p1_resolve_hours: 72,
  p2_ack_hours: 24,
  p2_resolve_hours: 168,
  p3_ack_hours: 72,
  p3_resolve_hours: 720,
  escalation_enabled: true,
  p0_escalation_minutes: 15,
  p1_escalation_minutes: 60,
})

// 颜色映射
const priorityColorMap: Record<string, string> = {
  P0: 'red',
  P1: 'orange',
  P2: 'blue',
  P3: 'default',
}

const priorityTextMap: Record<string, string> = {
  P0: 'P0 紧急',
  P1: 'P1 高危',
  P2: 'P2 中危',
  P3: 'P3 低危',
}

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

const statusColorMap: Record<string, string> = {
  pending: 'default',
  notified: 'processing',
  acknowledged: 'blue',
  resolved: 'success',
  ignored: 'default',
}

const statusTextMap: Record<string, string> = {
  pending: '待处理',
  notified: '已通知',
  acknowledged: '已确认',
  resolved: '已修复',
  ignored: '已忽略',
}

const columns = [
  { title: '通报编号', key: 'bulletinNo', width: 160 },
  { title: 'CVE', key: 'cveId', width: 160 },
  { title: '优先级', key: 'priority', width: 100 },
  { title: '严重级别', key: 'severity', width: 90 },
  { title: 'CVSS', key: 'cvssScore', width: 70 },
  { title: '威胁状态', key: 'exploit', width: 100 },
  { title: '影响组件', dataIndex: 'component', key: 'component', width: 150, ellipsis: true },
  { title: '受影响资产', key: 'affectedAssets', width: 100 },
  { title: '状态', key: 'status', width: 120 },
  { title: '创建时间', key: 'createdAt', width: 160 },
  { title: '操作', key: 'action', width: 130, fixed: 'right' as const },
]

const cvssClass = (score: number) => {
  if (score >= 9) return 'score-critical'
  if (score >= 7) return 'score-high'
  return 'score-normal'
}

// === 数据加载 ===

const loadBulletins = async () => {
  loading.value = true
  try {
    const res = await vulnBulletinsApi.list({
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      search: searchText.value || undefined,
      priority: filterPriority.value || undefined,
      status: filterStatus.value || undefined,
      sla_breached: filterSlaBreached.value || undefined,
      sort: filterSort.value || undefined,
    })
    bulletins.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch {
    bulletins.value = []
  } finally {
    loading.value = false
  }
}

const loadStatistics = async () => {
  try {
    const res = await vulnBulletinsApi.statistics()
    statistics.value = res
  } catch {
    // 忽略
  }
}

// === 事件处理 ===

const handleFilterChange = () => {
  pagination.value.current = 1
  syncRouteQuery()
  loadBulletins()
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadBulletins()
}

const onSelectChange = (keys: number[]) => {
  selectedRowKeys.value = keys
}

const handleAcknowledge = async (record: VulnBulletin) => {
  try {
    await vulnBulletinsApi.acknowledge(record.id)
    message.success('通报已确认')
    loadBulletins()
    loadStatistics()
  } catch (error) {
    console.error('确认通报失败:', error)
  }
}

const handleResolve = async (record: VulnBulletin) => {
  Modal.confirm({
    title: '确认修复',
    content: `确认将通报 ${record.bulletinNo} 标记为已修复？`,
    onOk: async () => {
      try {
        await vulnBulletinsApi.resolve(record.id)
        message.success('通报已标记为修复')
        loadBulletins()
        loadStatistics()
      } catch (error) {
        console.error('标记修复失败:', error)
      }
    },
  })
}

const handleBatchAction = async (action: string) => {
  if (selectedRowKeys.value.length === 0) return
  const actionText: Record<string, string> = {
    acknowledge: '确认',
    resolve: '修复',
    ignore: '忽略',
  }
  Modal.confirm({
    title: `批量${actionText[action]}`,
    content: `确认对选中的 ${selectedRowKeys.value.length} 条通报执行${actionText[action]}操作？`,
    onOk: async () => {
      batchLoading.value = true
      try {
        await vulnBulletinsApi.batch(selectedRowKeys.value, action)
        message.success(`批量${actionText[action]}完成`)
        selectedRowKeys.value = []
        loadBulletins()
        loadStatistics()
      } catch (error) {
        console.error('批量操作失败:', error)
      } finally {
        batchLoading.value = false
      }
    },
  })
}

const handleReset = () => {
  searchText.value = ''
  filterPriority.value = undefined
  filterStatus.value = undefined
  filterSlaBreached.value = undefined
  filterSort.value = undefined
  pagination.value.current = 1
  syncRouteQuery()
  loadBulletins()
}

const handleExport = () => {
  if (bulletins.value.length === 0) {
    message.warning('当前没有可导出的通报数据')
    return
  }

  const rows = [
    ['通报编号', 'CVE', '优先级', '严重级别', 'CVSS', '组件', '受影响资产', '状态', 'SLA超时', '创建时间'],
    ...bulletins.value.map((item) => [
      item.bulletinNo,
      item.cveId,
      item.priority,
      item.severity,
      String(item.cvssScore ?? ''),
      item.component || '',
      String(item.affectedAssets ?? 0),
      statusTextMap[item.status] || item.status,
      item.slaBreached ? '是' : '否',
      item.createdAt || '',
    ]),
  ]

  const csv = rows
    .map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(','))
    .join('\n')
  const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', `vuln_bulletins_${new Date().toISOString().slice(0, 10)}.csv`)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
  message.success('已导出当前结果')
}

// === 配置管理 ===

const showConfigDrawer = async () => {
  configVisible.value = true
  configLoading.value = true
  try {
    const cfg = await vulnBulletinsApi.getConfig()
    configForm.value = cfg
  } catch (error) {
    console.error('获取配置失败:', error)
  } finally {
    configLoading.value = false
  }
}

const handleSaveConfig = async () => {
  configSaving.value = true
  try {
    await vulnBulletinsApi.updateConfig(configForm.value)
    message.success('配置已保存')
    configVisible.value = false
  } catch (error) {
    console.error('保存配置失败:', error)
  } finally {
    configSaving.value = false
  }
}

// === 路由同步 ===

const syncFiltersFromRoute = () => {
  searchText.value = typeof route.query.search === 'string' ? route.query.search : ''
  filterPriority.value = typeof route.query.priority === 'string' ? route.query.priority : undefined
  filterStatus.value = typeof route.query.status === 'string' ? route.query.status : undefined
  filterSlaBreached.value = typeof route.query.sla_breached === 'string' ? route.query.sla_breached : undefined
  filterSort.value = typeof route.query.sort === 'string' ? route.query.sort : undefined
}

const syncRouteQuery = () => {
  router.replace({
    query: {
      ...route.query,
      search: searchText.value || undefined,
      priority: filterPriority.value || undefined,
      status: filterStatus.value || undefined,
      sla_breached: filterSlaBreached.value || undefined,
      sort: filterSort.value || undefined,
    },
  })
}

onMounted(() => {
  syncFiltersFromRoute()
  loadBulletins()
  loadStatistics()
})
</script>

<style scoped>
.bulletin-list-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.stat-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: var(--mxsec-text-1);
}

.stat-value.critical { color: #EF4444; }
.stat-value.high { color: #F59E0B; }
.stat-value.sla-breach { color: #EF4444; }

.stat-label {
  margin-top: 8px;
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
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

.batch-action-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  margin-bottom: 12px;
  background: var(--mxsec-primary-bg);
  border: 1px solid #BEDAFF;
  border-radius: 6px;
  font-size: 13px;
}

.score-critical { color: #EF4444; font-weight: 700; }
.score-high { color: #F59E0B; font-weight: 700; }
.score-normal { color: var(--mxsec-text-1); font-weight: 600; }

@media (max-width: 960px) {
  .filter-actions {
    margin-left: 0;
  }
}
</style>
