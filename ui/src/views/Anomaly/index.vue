<template>
  <div class="anomaly-page">
    <div class="page-header">
      <h2>ML 异常检测</h2>
      <a-button @click="handleRefresh">
        <ReloadOutlined /> 刷新
      </a-button>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[12, 12]" class="section-row">
      <a-col :span="4">
        <StatCard title="总告警" :value="stats.total" color="#3B82F6" />
      </a-col>
      <a-col :span="4">
        <StatCard title="待处理" :value="stats.open" color="#F59E0B" />
      </a-col>
      <a-col :span="4">
        <StatCard title="严重告警" :value="stats.critical" color="#EF4444" />
      </a-col>
      <a-col :span="6">
        <div class="dist-card">
          <div class="dist-title">按类型分布</div>
          <div v-if="stats.by_type.length > 0" class="dist-list">
            <div v-for="item in stats.by_type" :key="item.alert_type" class="dist-item">
              <span>{{ getAlertTypeLabel(item.alert_type) }}</span>
              <a-tag>{{ item.count }}</a-tag>
            </div>
          </div>
          <span v-else class="empty-text">暂无数据</span>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="dist-card">
          <div class="dist-title">关联模式分布</div>
          <div v-if="stats.by_pattern.length > 0" class="dist-list">
            <div v-for="item in stats.by_pattern" :key="item.alert_type" class="dist-item">
              <span>{{ getPatternLabel(item.alert_type) }}</span>
              <a-tag>{{ item.count }}</a-tag>
            </div>
          </div>
          <span v-else class="empty-text">暂无数据</span>
        </div>
      </a-col>
    </a-row>

    <!-- 筛选栏 -->
    <div class="filter-bar">
      <a-input v-model:value="filters.host_id" placeholder="主机 ID" style="width: 200px" allow-clear @pressEnter="handleSearch" />
      <a-select v-model:value="filters.alert_type" placeholder="告警类型" style="width: 140px" allow-clear @change="handleSearch">
        <a-select-option value="isolation_forest">Isolation Forest</a-select-option>
        <a-select-option value="correlation">多维关联</a-select-option>
      </a-select>
      <a-select v-model:value="filters.severity" placeholder="严重度" style="width: 120px" allow-clear @change="handleSearch">
        <a-select-option value="critical">严重</a-select-option>
        <a-select-option value="high">高危</a-select-option>
        <a-select-option value="medium">中危</a-select-option>
        <a-select-option value="low">低危</a-select-option>
      </a-select>
      <a-select v-model:value="filters.status" placeholder="状态" style="width: 120px" allow-clear @change="handleSearch">
        <a-select-option value="open">待处理</a-select-option>
        <a-select-option value="confirmed">已确认</a-select-option>
        <a-select-option value="false_positive">误报</a-select-option>
      </a-select>
    </div>

    <!-- 告警表格 -->
    <a-table
      :columns="columns"
      :data-source="alerts"
      :loading="loading"
      :pagination="pagination"
      row-key="id"
      size="small"
      :row-class-name="(record: AnomalyAlert) => record.id === selectedId ? 'row-selected' : ''"
      @change="handleTableChange"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'severity'">
          <a-tag :color="getSeverityConfig(record.severity).tagColor">
            {{ getSeverityConfig(record.severity).label }}
          </a-tag>
        </template>
        <template v-if="column.key === 'alert_type'">
          <a-tag :color="record.alert_type === 'isolation_forest' ? 'purple' : 'geekblue'">
            {{ getAlertTypeLabel(record.alert_type) }}
          </a-tag>
        </template>
        <template v-if="column.key === 'anomaly_score'">
          <a-progress
            :percent="Math.round(record.anomaly_score * 100)"
            :stroke-color="record.anomaly_score >= 0.8 ? '#EF4444' : record.anomaly_score >= 0.7 ? '#F59E0B' : '#FADC19'"
            :size="[100, 6]"
            :show-info="true"
          />
        </template>
        <template v-if="column.key === 'detail'">
          <template v-if="record.alert_type === 'isolation_forest'">
            <span class="mono-text">{{ record.top_metric }}</span>
            <span v-if="record.top_value" class="detail-value"> = {{ record.top_value.toFixed(1) }}</span>
          </template>
          <template v-else>
            <span>{{ getPatternLabel(record.pattern_name) }}</span>
          </template>
        </template>
        <template v-if="column.key === 'status'">
          <a-tag :color="getStatusColor(record.status)">{{ getStatusLabel(record.status) }}</a-tag>
        </template>
        <template v-if="column.key === 'action'">
          <a-space>
            <a @click.stop="showDetail(record)">详情</a>
            <a v-if="record.status === 'open'" @click.stop="handleResolve(record, 'confirmed')">确认</a>
            <a v-if="record.status === 'open'" @click.stop="handleResolve(record, 'false_positive')" style="color: var(--mxsec-text-3)">误报</a>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 详情抽屉 -->
    <DetailDrawer v-model:open="drawerVisible" title="异常详情" :width="560">
      <template #header>
        <a-tag v-if="selectedAlert" :color="getSeverityConfig(selectedAlert.severity).tagColor">
          {{ getSeverityConfig(selectedAlert.severity).label }}
        </a-tag>
      </template>

      <template v-if="selectedAlert">
        <!-- 异常分环形仪表 -->
        <div class="score-gauge">
          <div class="gauge-ring">
            <svg width="90" height="90" viewBox="0 0 90 90">
              <circle cx="45" cy="45" r="38" fill="none" stroke="rgba(30,58,95,0.3)" stroke-width="6" />
              <circle
                cx="45" cy="45" r="38"
                fill="none"
                :stroke="scoreColor(selectedAlert.anomaly_score)"
                stroke-width="6"
                :stroke-dasharray="238.76"
                :stroke-dashoffset="238.76 * (1 - selectedAlert.anomaly_score)"
                stroke-linecap="round"
                transform="rotate(-90 45 45)"
              />
            </svg>
            <div class="gauge-value" :style="{ color: scoreColor(selectedAlert.anomaly_score) }">
              {{ selectedAlert.anomaly_score.toFixed(2) }}
            </div>
          </div>
          <div class="gauge-label" :style="{ color: scoreColor(selectedAlert.anomaly_score) }">
            {{ selectedAlert.anomaly_score >= 0.8 ? '高风险异常' : selectedAlert.anomaly_score >= 0.6 ? '中风险异常' : '低风险异常' }}
          </div>
        </div>

        <!-- 描述列表 -->
        <div class="detail-list">
          <div class="detail-row">
            <span class="dl-label">主机</span>
            <span class="dl-val">{{ selectedAlert.hostname }} ({{ selectedAlert.host_id }})</span>
          </div>
          <div class="detail-row">
            <span class="dl-label">类型</span>
            <span class="dl-val" style="color: #06B6D4;">{{ getAlertTypeLabel(selectedAlert.alert_type) }}</span>
          </div>
          <div class="detail-row">
            <span class="dl-label">检测时间</span>
            <span class="dl-val">{{ selectedAlert.created_at }}</span>
          </div>
          <div v-if="selectedAlert.top_metric" class="detail-row">
            <span class="dl-label">异常指标</span>
            <span class="dl-val mono-text">{{ selectedAlert.top_metric }}</span>
          </div>
          <div v-if="selectedAlert.top_value" class="detail-row">
            <span class="dl-label">异常值</span>
            <span class="dl-val" style="color: #EF4444; font-weight: 600;">{{ selectedAlert.top_value.toFixed(1) }}</span>
          </div>
          <div v-if="selectedAlert.pattern_name" class="detail-row">
            <span class="dl-label">关联模式</span>
            <span class="dl-val">{{ getPatternLabel(selectedAlert.pattern_name) }}</span>
          </div>
          <div v-if="selectedAlert.description" class="detail-row">
            <span class="dl-label">描述</span>
            <span class="dl-val">{{ selectedAlert.description }}</span>
          </div>
          <div class="detail-row">
            <span class="dl-label">状态</span>
            <span class="dl-val">
              <a-tag :color="getStatusColor(selectedAlert.status)">{{ getStatusLabel(selectedAlert.status) }}</a-tag>
            </span>
          </div>
        </div>
      </template>

      <template #footer v-if="selectedAlert && selectedAlert.status === 'open'">
        <a-button type="primary" danger @click="handleResolve(selectedAlert!, 'confirmed')">确认告警</a-button>
        <a-button @click="handleResolve(selectedAlert!, 'false_positive')">标记误报</a-button>
      </template>
    </DetailDrawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ReloadOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import StatCard from '@/components/StatCard.vue'
import DetailDrawer from '@/components/DetailDrawer.vue'
import { anomalyApi } from '@/api/anomaly'
import type { AnomalyAlert, AnomalyStats } from '@/api/anomaly'
import { getSeverityConfig } from '@/constants/severity'

const loading = ref(false)
const alerts = ref<AnomalyAlert[]>([])
const drawerVisible = ref(false)
const selectedAlert = ref<AnomalyAlert | null>(null)
const selectedId = ref<number | null>(null)

const stats = reactive<AnomalyStats>({
  total: 0, open: 0, critical: 0,
  by_type: [], by_pattern: [],
})

const filters = reactive({
  host_id: '',
  alert_type: undefined as string | undefined,
  severity: undefined as string | undefined,
  status: undefined as string | undefined,
})

const pagination = reactive({
  current: 1, pageSize: 20, total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  { title: '时间', dataIndex: 'created_at', width: 170 },
  { title: '主机', dataIndex: 'hostname', width: 120, ellipsis: true },
  { title: '类型', key: 'alert_type', width: 120 },
  { title: '严重度', key: 'severity', width: 80, align: 'center' as const },
  { title: '异常分数', key: 'anomaly_score', width: 150 },
  { title: '详情', key: 'detail', ellipsis: true },
  { title: '状态', key: 'status', width: 80, align: 'center' as const },
  { title: '操作', key: 'action', width: 140 },
]

const getAlertTypeLabel = (type: string) => type === 'isolation_forest' ? 'Isolation Forest' : '多维关联'
const getPatternLabel = (name: string) => {
  const labels: Record<string, string> = { c2_beacon: 'C2 信标', data_exfiltration: '数据外泄', privilege_escalation: '权限提升', reconnaissance: '侦察扫描' }
  return labels[name] || name
}
const getStatusColor = (status: string) => ({ open: 'orange', confirmed: 'red', false_positive: 'default' }[status] || 'default')
const getStatusLabel = (status: string) => ({ open: '待处理', confirmed: '已确认', false_positive: '误报' }[status] || status)
const scoreColor = (score: number): string => score >= 0.8 ? '#EF4444' : score >= 0.6 ? '#F59E0B' : '#FADC19'

const showDetail = (record: AnomalyAlert) => {
  selectedAlert.value = record
  selectedId.value = record.id
  drawerVisible.value = true
}

const fetchAlerts = async () => {
  loading.value = true
  try {
    const res = await anomalyApi.list({
      page: pagination.current, page_size: pagination.pageSize,
      host_id: filters.host_id || undefined,
      alert_type: filters.alert_type, severity: filters.severity, status: filters.status,
    })
    alerts.value = res.items || []
    pagination.total = res.total
  } catch { /* handled */ } finally { loading.value = false }
}

const fetchStats = async () => {
  try { const res = await anomalyApi.stats(); Object.assign(stats, res) } catch { /* silent */ }
}

const handleSearch = () => { pagination.current = 1; fetchAlerts() }
const handleRefresh = () => { fetchAlerts(); fetchStats() }
const handleTableChange = (pag: any) => { pagination.current = pag.current; pagination.pageSize = pag.pageSize; fetchAlerts() }

const handleResolve = async (record: AnomalyAlert, status: 'confirmed' | 'false_positive') => {
  try {
    await anomalyApi.resolve(record.id, status)
    message.success(status === 'confirmed' ? '已确认威胁' : '已标记为误报')
    drawerVisible.value = false
    fetchAlerts(); fetchStats()
  } catch { /* handled */ }
}

onMounted(() => { fetchAlerts(); fetchStats() })
</script>

<style scoped>
.anomaly-page { padding: 0; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.page-header h2 { margin: 0; font-size: 20px; }
.section-row { margin-bottom: 16px; }
.mono-text { font-family: monospace; font-size: 13px; }
.detail-value { color: #EF4444; font-weight: 500; }
.empty-text { color: var(--mxsec-text-4); font-size: 12px; }

.dist-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 10px; padding: 14px 16px; height: 100%; }
.dist-title { font-size: 12px; color: var(--mxsec-text-3); margin-bottom: 8px; font-weight: 500; }
.dist-list { display: flex; flex-direction: column; gap: 4px; }
.dist-item { display: flex; justify-content: space-between; align-items: center; font-size: 13px; color: var(--mxsec-text-2); }

:deep(.row-selected td) { background: rgba(59, 130, 246, 0.08) !important; }

.score-gauge { text-align: center; margin-bottom: 20px; padding: 20px; background: var(--mxsec-body-bg); border-radius: 10px; }
.gauge-ring { position: relative; width: 90px; height: 90px; margin: 0 auto; }
.gauge-value { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 22px; font-weight: 700; }
.gauge-label { font-size: 12px; margin-top: 8px; }

.detail-list { font-size: 13px; }
.detail-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--mxsec-border-light); }
.detail-row:last-child { border-bottom: none; }
.dl-label { color: var(--mxsec-text-3); min-width: 80px; }
.dl-val { color: var(--mxsec-text-1); text-align: right; word-break: break-all; }
</style>
