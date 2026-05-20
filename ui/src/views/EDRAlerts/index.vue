<template>
  <div class="edr-alerts-page">
    <div class="page-header">
      <h2 class="page-title">EDR 告警事件</h2>
    </div>

    <!-- 统计卡片 -->
    <div class="stats">
      <div class="stat-card stat-total">
        <div class="stat-icon-bg"><ThunderboltOutlined /></div>
        <div class="stat-info">
          <div class="stat-value">{{ statistics.total || 0 }}</div>
          <div class="stat-label">总事件数</div>
        </div>
      </div>
      <div class="stat-card stat-active">
        <div class="stat-icon-bg"><AlertOutlined /></div>
        <div class="stat-info">
          <div class="stat-value">{{ statistics.active || 0 }}</div>
          <div class="stat-label">活跃事件</div>
        </div>
      </div>
      <div class="stat-card stat-today">
        <div class="stat-icon-bg"><ClockCircleOutlined /></div>
        <div class="stat-info">
          <div class="stat-value">{{ statistics.today || 0 }}</div>
          <div class="stat-label">今日新增</div>
        </div>
      </div>
      <div class="stat-card stat-critical">
        <div class="stat-icon-bg"><CloseCircleOutlined /></div>
        <div class="stat-info">
          <div class="stat-value critical">{{ statistics.critical || 0 }}</div>
          <div class="stat-label">严重</div>
        </div>
      </div>
      <div class="stat-card stat-high">
        <div class="stat-icon-bg"><ExclamationCircleOutlined /></div>
        <div class="stat-info">
          <div class="stat-value high">{{ statistics.high || 0 }}</div>
          <div class="stat-label">高危</div>
        </div>
      </div>
      <div class="stat-card stat-medium">
        <div class="stat-icon-bg"><WarningOutlined /></div>
        <div class="stat-info">
          <div class="stat-value medium">{{ statistics.medium || 0 }}</div>
          <div class="stat-label">中危</div>
        </div>
      </div>
    </div>

    <!-- 筛选器 -->
    <div class="filters">
      <a-input
        v-model:value="filters.keyword"
        placeholder="搜索告警标题/描述"
        allow-clear
        style="width: 200px"
        @press-enter="handleSearch"
        @change="(e: any) => !e.target.value && handleSearch()"
      >
        <template #prefix><SearchOutlined /></template>
      </a-input>
      <a-select
        v-model:value="filters.severity"
        placeholder="严重级别"
        allow-clear
        style="width: 120px"
        @change="handleSearch"
      >
        <a-select-option value="critical">严重</a-select-option>
        <a-select-option value="high">高危</a-select-option>
        <a-select-option value="medium">中危</a-select-option>
        <a-select-option value="low">低危</a-select-option>
      </a-select>
      <a-select
        v-model:value="filters.category"
        placeholder="规则分类"
        allow-clear
        style="width: 140px"
        @change="handleSearch"
        :options="categoryOptions"
      />
      <a-select
        v-model:value="filters.eventType"
        placeholder="事件类型"
        allow-clear
        style="width: 130px"
        @change="handleSearch"
      >
        <a-select-option value="process">进程事件</a-select-option>
        <a-select-option value="file">文件事件</a-select-option>
        <a-select-option value="network">网络事件</a-select-option>
      </a-select>
      <a-select
        v-model:value="filters.business_line"
        placeholder="业务线"
        allow-clear
        style="width: 140px"
        @change="handleSearch"
        :options="businessLineOptions"
      />
      <a-select
        v-model:value="filters.mitre_id"
        placeholder="MITRE ATT&CK"
        allow-clear
        style="width: 140px"
        @change="handleSearch"
        :options="mitreOptions"
        show-search
      />
      <a-range-picker
        v-model:value="filters.timeRange"
        show-time
        format="YYYY-MM-DD HH:mm"
        style="width: 320px"
        @change="handleSearch"
      />
    </div>

    <!-- Tab 切换 -->
    <div class="tabs-header">
      <div
        :class="['tab-item', { active: activeTab === 'active' }]"
        @click="switchTab('active')"
      >
        活跃事件
      </div>
      <div
        :class="['tab-item', { active: activeTab === 'history' }]"
        @click="switchTab('history')"
      >
        历史事件
      </div>
    </div>

    <!-- 表格 -->
    <a-table
      :data-source="alerts"
      :columns="columns"
      :loading="loading"
      :pagination="tablePagination"
      @change="handleTableChange"
      row-key="id"
      :scroll="{ x: 1200 }"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.dataIndex === 'title'">
          <a-typography-text :ellipsis="{ tooltip: record.title }">
            {{ record.title }}
          </a-typography-text>
        </template>
        <template v-else-if="column.dataIndex === 'severity'">
          <a-tag :color="getSeverityColor(record.severity)">
            {{ getSeverityText(record.severity) }}
          </a-tag>
        </template>
        <template v-else-if="column.dataIndex === 'category'">
          {{ record.category || '-' }}
        </template>
        <template v-else-if="column.key === 'hostname'">
          <a v-if="record.host" @click="$router.push(`/hosts/${record.host_id}`)">
            {{ record.host.hostname }}
          </a>
          <span v-else>{{ record.host_id }}</span>
          <div v-if="record.host?.ipv4?.length" style="color: #86909C; font-size: 12px;">
            {{ record.host.ipv4[0] }}
          </div>
        </template>
        <template v-else-if="column.key === 'event_type'">
          <a-tag color="blue">{{ parseEventType(record.actual) }}</a-tag>
        </template>
        <template v-else-if="column.dataIndex === 'last_seen_at'">
          {{ formatDateTime(record.last_seen_at) }}
        </template>
        <template v-else-if="column.dataIndex === 'status'">
          <a-tag :color="getStatusColor(record.status)">
            {{ getStatusText(record.status) }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'action'">
          <a-space>
            <a @click="openDrawer(record.id)">查看详情</a>
            <template v-if="record.status === 'active'">
              <a-divider type="vertical" />
              <a @click="handleResolve(record)">解决</a>
              <a-divider type="vertical" />
              <a class="danger-link" @click="handleIgnore(record)">忽略</a>
            </template>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 事件详情抽屉 -->
    <EventDrawer
      v-model:open="drawerOpen"
      :alert-id="drawerAlertId"
      @refresh="handleRefresh"
    />

    <!-- 解决告警对话框 -->
    <a-modal
      v-model:open="resolveModalVisible"
      title="解决告警"
      @ok="handleResolveConfirm"
    >
      <a-form-item label="解决原因">
        <a-textarea v-model:value="resolveReason" placeholder="请输入解决原因（可选）" :rows="4" />
      </a-form-item>
    </a-modal>

    <!-- 忽略确认对话框 -->
    <a-modal
      v-model:open="ignoreModalVisible"
      title="确认忽略"
      @ok="handleIgnoreConfirm"
      ok-text="确认忽略"
      :ok-button-props="{ danger: true }"
    >
      <p>确定要忽略此告警吗？</p>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import type { Dayjs } from 'dayjs'
import {
  ThunderboltOutlined,
  AlertOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  WarningOutlined,
  SearchOutlined,
} from '@ant-design/icons-vue'
import { alertsApi, type Alert, type EDRAlertStatistics, type ListAlertsParams } from '@/api/alerts'
import { detectionRulesAPI } from '@/api/detection-rules'
import { businessLinesApi } from '@/api/business-lines'
import { formatDateTime } from '@/utils/date'
import EventDrawer from './components/EventDrawer.vue'

const route = useRoute()
const router = useRouter()

const loading = ref(false)
const alerts = ref<Alert[]>([])
const statistics = ref<EDRAlertStatistics>({
  total: 0, active: 0, today: 0, critical: 0, high: 0, medium: 0, low: 0,
})

const validTabs = ['active', 'history'] as const
const initTab = validTabs.includes(route.query.tab as any) ? (route.query.tab as 'active' | 'history') : 'active'
const activeTab = ref<'active' | 'history'>(initTab)

const pagination = ref({ current: 1, pageSize: 20, total: 0 })

const filters = reactive({
  keyword: undefined as string | undefined,
  severity: undefined as string | undefined,
  category: undefined as string | undefined,
  eventType: undefined as string | undefined,
  business_line: undefined as string | undefined,
  mitre_id: undefined as string | undefined,
  timeRange: null as [Dayjs, Dayjs] | null,
})

// 筛选器选项
const categoryOptions = ref<{ value: string; label: string }[]>([])
const businessLineOptions = ref<{ value: string; label: string }[]>([])
const mitreOptions = ref<{ value: string; label: string }[]>([])

// 抽屉
const drawerOpen = ref(false)
const drawerAlertId = ref<number | null>(null)

// 解决/忽略弹窗
const resolveModalVisible = ref(false)
const ignoreModalVisible = ref(false)
const resolveReason = ref('')
const operatingAlert = ref<Alert | null>(null)

const columns = [
  { title: '告警标题', dataIndex: 'title', width: 250, ellipsis: true },
  { title: '严重级别', dataIndex: 'severity', width: 90 },
  { title: '规则分类', dataIndex: 'category', width: 120 },
  { title: '主机名', key: 'hostname', width: 130 },
  { title: '事件类型', key: 'event_type', width: 100 },
  { title: '最后发现', dataIndex: 'last_seen_at', width: 170 },
  { title: '状态', dataIndex: 'status', width: 90 },
  { title: '操作', key: 'action', width: 180, fixed: 'right' as const },
]

const tablePagination = computed(() => ({
  current: pagination.value.current,
  pageSize: pagination.value.pageSize,
  total: pagination.value.total,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
}))

const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
  return colors[severity] || 'default'
}

const getSeverityText = (severity: string) => {
  const texts: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
  return texts[severity] || severity
}

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = { active: 'red', resolved: 'green', ignored: 'default' }
  return colors[status] || 'default'
}

const getStatusText = (status: string) => {
  const texts: Record<string, string> = { active: '活跃', resolved: '已解决', ignored: '已忽略' }
  return texts[status] || status
}

const parseEventType = (actual: string | undefined) => {
  if (!actual) return '-'
  try {
    const data = JSON.parse(actual)
    return data.event_type || '-'
  } catch {
    return '-'
  }
}

const loadStatistics = async () => {
  try {
    statistics.value = await alertsApi.edrStatistics()
  } catch (error: any) {
    console.error('加载 EDR 告警统计失败:', error)
  }
}

const loadAlerts = async () => {
  loading.value = true
  try {
    const params: ListAlertsParams = {
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      alert_type: 'edr',
    }

    if (activeTab.value === 'active') {
      params.status = 'active'
    } else {
      params.status = 'resolved,ignored' as any
    }

    if (filters.keyword) params.keyword = filters.keyword
    if (filters.severity) params.severity = filters.severity as any
    if (filters.category) params.category = filters.category
    if (filters.business_line) params.business_line = filters.business_line
    if (filters.mitre_id) params.mitre_id = filters.mitre_id
    if (filters.eventType) params.keyword = filters.eventType // event_type 通过 keyword 搜索
    if (filters.timeRange && filters.timeRange[0] && filters.timeRange[1]) {
      params.start_time = filters.timeRange[0].toISOString()
      params.end_time = filters.timeRange[1].toISOString()
    }

    const response = await alertsApi.list(params)
    alerts.value = response.items || []
    pagination.value.total = response.total || 0
  } catch (error: any) {
    message.error(error?.message || '加载告警列表失败')
  } finally {
    loading.value = false
  }
}

const loadFilterOptions = async () => {
  try {
    const [categories, mitreIds, blResponse] = await Promise.all([
      detectionRulesAPI.getCategories(),
      detectionRulesAPI.getMitreIDs(),
      businessLinesApi.list({ page_size: 100 }),
    ])
    categoryOptions.value = (categories || []).map((c: string) => ({ value: c, label: c }))
    mitreOptions.value = (mitreIds || []).map((m: string) => ({ value: m, label: m }))
    const items = blResponse?.items || blResponse || []
    businessLineOptions.value = (Array.isArray(items) ? items : []).map((b: any) => ({
      value: b.name,
      label: b.name,
    }))
  } catch (error: any) {
    console.error('加载筛选选项失败:', error)
  }
}

const handleSearch = () => {
  pagination.value.current = 1
  loadAlerts()
}

const switchTab = (tab: 'active' | 'history') => {
  activeTab.value = tab
  router.replace({ query: { ...route.query, tab } })
  pagination.value.current = 1
  loadAlerts()
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadAlerts()
}

const openDrawer = (id: number) => {
  drawerAlertId.value = id
  drawerOpen.value = true
}

const handleRefresh = () => {
  loadAlerts()
  loadStatistics()
}

const handleResolve = (alert: Alert) => {
  operatingAlert.value = alert
  resolveReason.value = ''
  resolveModalVisible.value = true
}

const handleResolveConfirm = async () => {
  if (!operatingAlert.value) return
  try {
    await alertsApi.resolve(operatingAlert.value.id, resolveReason.value || undefined)
    message.success('告警已解决')
    resolveModalVisible.value = false
    handleRefresh()
  } catch (error: any) {
    message.error(error?.message || '解决告警失败')
  }
}

const handleIgnore = (alert: Alert) => {
  operatingAlert.value = alert
  ignoreModalVisible.value = true
}

const handleIgnoreConfirm = async () => {
  if (!operatingAlert.value) return
  try {
    await alertsApi.ignore(operatingAlert.value.id)
    message.success('告警已忽略')
    ignoreModalVisible.value = false
    handleRefresh()
  } catch (error: any) {
    message.error(error?.message || '忽略告警失败')
  }
}

onMounted(() => {
  loadStatistics()
  loadAlerts()
  loadFilterOptions()
})
</script>

<style scoped lang="less">
.edr-alerts-page {
  padding: 0;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.page-title {
  font-size: 20px;
  font-weight: 600;
  margin: 0;
  color: #262626;
}

.stats {
  display: flex;
  gap: 16px;
  margin-bottom: 24px;
}

.stat-card {
  flex: 1;
  background: #fff;
  border: none;
  border-radius: 8px;
  padding: 20px;
  display: flex;
  align-items: center;
  gap: 16px;
  transition: all 0.3s ease;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
    0 2px 4px rgba(0, 0, 0, 0.04),
    0 4px 8px rgba(0, 0, 0, 0.04);

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08),
      0 8px 24px rgba(0, 0, 0, 0.06);
  }
}

.stat-icon-bg {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  flex-shrink: 0;
  color: #fff;
}

.stat-total .stat-icon-bg {
  background: linear-gradient(135deg, #722ED1, #531DAB);
}

.stat-active .stat-icon-bg {
  background: linear-gradient(135deg, #165DFF, #0E42D2);
}

.stat-today .stat-icon-bg {
  background: linear-gradient(135deg, #00B42A, #009A29);
}

.stat-critical .stat-icon-bg {
  background: linear-gradient(135deg, #F53F3F, #CB2634);
}

.stat-high .stat-icon-bg {
  background: linear-gradient(135deg, #ff7a45, #d4380d);
}

.stat-medium .stat-icon-bg {
  background: linear-gradient(135deg, #FF7D00, #d48806);
}

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: #262626;
  margin-bottom: 4px;
  line-height: 1;

  &.critical { color: #F53F3F; }
  &.high { color: #ff7a45; }
  &.medium { color: #FF7D00; }
}

.stat-label {
  font-size: 13px;
  color: #86909C;
  font-weight: 400;
}

.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 24px;
  padding: 16px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
    0 2px 4px rgba(0, 0, 0, 0.04);
}

.tabs-header {
  display: flex;
  gap: 0;
  margin-bottom: 24px;
  background: #fff;
  border: none;
  border-radius: 8px;
  padding: 4px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
    0 2px 4px rgba(0, 0, 0, 0.04);
}

.tab-item {
  flex: 1;
  padding: 10px 20px;
  text-align: center;
  cursor: pointer;
  border-radius: 6px;
  font-size: 14px;
  color: #595959;
  transition: all 0.3s ease;
  font-weight: 400;

  &:hover {
    color: #165DFF;
    background: #f5f7fa;
  }

  &.active {
    background: linear-gradient(135deg, #165DFF 0%, #0E42D2 100%);
    color: #fff;
    font-weight: 500;
    box-shadow: 0 2px 8px rgba(22, 93, 255, 0.3);

    &:hover {
      background: linear-gradient(135deg, #4080FF 0%, #165DFF 100%);
      color: #fff;
    }
  }
}

.danger-link {
  color: #F53F3F;

  &:hover {
    color: #CB2634;
  }
}
</style>
