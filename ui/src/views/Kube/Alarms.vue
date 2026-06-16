<template>
  <div class="kube-alarms-page">
    <div class="page-header">
      <h2>容器集群安全告警</h2>
      <span class="page-header-hint">Kubernetes 集群入侵检测告警与基线违规</span>
    </div>

    <a-tabs v-model:activeKey="activeTab" @change="handleTabChange">
      <a-tab-pane key="detection" tab="检测告警">
    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="6">
        <div class="alarm-stat critical" @click="filterSeverity = 'critical'; loadAlarms()">
          <div class="alarm-stat-value">{{ stats.critical }}</div>
          <div class="alarm-stat-label">紧急</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="alarm-stat high" @click="filterSeverity = 'high'; loadAlarms()">
          <div class="alarm-stat-value">{{ stats.high }}</div>
          <div class="alarm-stat-label">高危</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="alarm-stat medium" @click="filterSeverity = 'medium'; loadAlarms()">
          <div class="alarm-stat-value">{{ stats.medium }}</div>
          <div class="alarm-stat-label">中危</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="alarm-stat low" @click="filterSeverity = 'low'; loadAlarms()">
          <div class="alarm-stat-value">{{ stats.low }}</div>
          <div class="alarm-stat-label">低危</div>
        </div>
      </a-col>
    </a-row>

    <!-- 表格 -->
    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search v-model:value="searchText" placeholder="搜索告警内容" style="width: 240px" allow-clear @search="loadAlarms" />
          <a-select v-model:value="filterCluster" style="width: 180px" placeholder="集群" allow-clear show-search @change="loadAlarms">
            <a-select-option v-for="c in clusterOptions" :key="c.value" :value="c.value">{{ c.label }}</a-select-option>
          </a-select>
          <a-select v-model:value="filterSeverity" style="width: 120px" placeholder="级别" allow-clear @change="loadAlarms">
            <a-select-option value="critical">紧急</a-select-option>
            <a-select-option value="high">高危</a-select-option>
            <a-select-option value="medium">中危</a-select-option>
            <a-select-option value="low">低危</a-select-option>
          </a-select>
          <a-select v-model:value="filterStatus" style="width: 120px" placeholder="状态" allow-clear @change="loadAlarms">
            <a-select-option value="pending">待处理</a-select-option>
            <a-select-option value="processed">已处理</a-select-option>
            <a-select-option value="ignored">已忽略</a-select-option>
          </a-select>
          <div style="flex: 1"></div>
          <a-button @click="handleBatchIgnore" :disabled="!selectedRowKeys.length">批量忽略</a-button>
          <a-button type="primary" @click="handleBatchProcess" :disabled="!selectedRowKeys.length">批量处理</a-button>
        </div>

        <a-table
          :columns="columns"
          :data-source="alarms"
          :loading="loading"
          :pagination="pagination"
          :row-selection="{ selectedRowKeys, onChange: onSelectChange }"
          @change="handleTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity]" :bordered="false">{{ severityTextMap[record.severity] }}</a-tag>
            </template>
            <template v-if="column.key === 'status'">
              <a-tag :color="record.status === 'pending' ? 'orange' : record.status === 'processed' ? 'green' : 'default'" :bordered="false">
                {{ statusTextMap[record.status] }}
              </a-tag>
            </template>
            <template v-if="column.key === 'alarmType'">
              <a-tag :color="alarmTypeColorMap[record.alarmType] || 'default'" :bordered="false">{{ alarmTypeTextMap[record.alarmType] || record.alarmType }}</a-tag>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="showAlarmDetail(record)">详情</a-button>
                <a-button type="link" size="small" @click="handleProcess(record)" v-if="record.status === 'pending'">处理</a-button>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 告警详情 Drawer -->
    <a-drawer v-model:open="showDetail" title="告警详情" width="680">
      <template v-if="detailRecord">
        <!-- 告警标题 -->
        <div class="alarm-detail-header">
          <a-tag :color="severityColorMap[detailRecord.severity]" :bordered="false" class="severity-tag">{{ severityTextMap[detailRecord.severity] }}</a-tag>
          <span class="alarm-detail-title">{{ detailRecord.title }}</span>
        </div>

        <!-- 告警摘要 -->
        <div class="alarm-detail-message">{{ detailRecord.message }}</div>

        <!-- 规则说明 -->
        <div class="alarm-detail-section" v-if="detailRecord.description">
          <div class="section-label">规则说明</div>
          <div class="section-content">{{ detailRecord.description }}</div>
        </div>

        <!-- 处置建议 -->
        <div class="alarm-detail-section remediation" v-if="detailRecord.remediation">
          <div class="section-label">处置建议</div>
          <div class="section-content remediation-content">{{ detailRecord.remediation }}</div>
        </div>

        <a-divider style="margin: 16px 0" />

        <!-- 基本信息 -->
        <a-descriptions :column="2" bordered size="small">
          <a-descriptions-item label="告警 ID">{{ detailRecord.id }}</a-descriptions-item>
          <a-descriptions-item label="告警类型">
            <a-tag :color="alarmTypeColorMap[detailRecord.alarmType] || 'default'" :bordered="false">{{ alarmTypeTextMap[detailRecord.alarmType] || detailRecord.alarmType }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="集群">{{ detailRecord.clusterName }}</a-descriptions-item>
          <a-descriptions-item label="Namespace">{{ detailRecord.namespace || '-' }}</a-descriptions-item>
          <a-descriptions-item label="影响对象" :span="2">{{ detailRecord.target || '-' }}</a-descriptions-item>
          <a-descriptions-item label="发现时间">{{ detailRecord.createdAt }}</a-descriptions-item>
          <a-descriptions-item label="状态">
            <a-tag :color="detailRecord.status === 'pending' ? 'orange' : detailRecord.status === 'processed' ? 'green' : 'default'" :bordered="false">
              {{ statusTextMap[detailRecord.status] }}
            </a-tag>
          </a-descriptions-item>
        </a-descriptions>

        <a-divider v-if="detailRecord.rawData" style="margin: 16px 0">原始审计事件</a-divider>
        <pre v-if="detailRecord.rawData" class="raw-json">{{ JSON.stringify(detailRecord.rawData, null, 2) }}</pre>
      </template>
    </a-drawer>
      </a-tab-pane>

      <a-tab-pane key="baseline" tab="基线违规">
        <!-- 基线告警统计 -->
        <a-row :gutter="[16, 16]" class="section-row">
          <a-col :span="8">
            <div class="alarm-stat critical">
              <div class="alarm-stat-value">{{ baselineStats.active }}</div>
              <div class="alarm-stat-label">活跃</div>
            </div>
          </a-col>
          <a-col :span="8">
            <div class="alarm-stat" style="border-color: #22C55E">
              <div class="alarm-stat-value" style="color: #22C55E">{{ baselineStats.resolved }}</div>
              <div class="alarm-stat-label">已恢复</div>
            </div>
          </a-col>
          <a-col :span="8">
            <div class="alarm-stat low">
              <div class="alarm-stat-value">{{ baselineStats.ignored }}</div>
              <div class="alarm-stat-label">已忽略</div>
            </div>
          </a-col>
        </a-row>

        <div class="dashboard-card">
          <div class="card-body">
            <div class="filter-bar">
              <a-input-search v-model:value="baselineSearch" placeholder="搜索检查项" style="width: 240px" allow-clear @search="loadBaselineAlerts" />
              <a-select v-model:value="baselineFilterSeverity" style="width: 120px" placeholder="级别" allow-clear @change="loadBaselineAlerts">
                <a-select-option value="critical">紧急</a-select-option>
                <a-select-option value="high">高危</a-select-option>
                <a-select-option value="medium">中危</a-select-option>
                <a-select-option value="low">低危</a-select-option>
              </a-select>
              <a-select v-model:value="baselineFilterStatus" style="width: 120px" placeholder="状态" allow-clear @change="loadBaselineAlerts">
                <a-select-option value="active">活跃</a-select-option>
                <a-select-option value="resolved">已恢复</a-select-option>
                <a-select-option value="ignored">已忽略</a-select-option>
              </a-select>
              <div style="flex: 1"></div>
              <a-button @click="handleBaselineBatchIgnore" :disabled="!baselineSelectedKeys.length">批量忽略</a-button>
            </div>

            <a-table
              :columns="baselineColumns"
              :data-source="baselineAlerts"
              :loading="baselineLoading"
              :pagination="baselinePagination"
              :row-selection="{ selectedRowKeys: baselineSelectedKeys, onChange: (keys: string[]) => { baselineSelectedKeys = keys } }"
              @change="handleBaselineTableChange"
              size="middle"
              row-key="id"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'severity'">
                  <a-tag :color="severityColorMap[record.severity]" :bordered="false">{{ severityTextMap[record.severity] }}</a-tag>
                </template>
                <template v-if="column.key === 'status'">
                  <a-tag :color="record.status === 'active' ? 'orange' : record.status === 'resolved' ? 'green' : 'default'" :bordered="false">
                    {{ baselineStatusTextMap[record.status] }}
                  </a-tag>
                </template>
                <template v-if="column.key === 'action'">
                  <a-space>
                    <a-button type="link" size="small" @click="showBaselineDetail(record)">详情</a-button>
                    <a-button type="link" size="small" @click="handleBaselineIgnore(record)" v-if="record.status === 'active'">忽略</a-button>
                  </a-space>
                </template>
              </template>
            </a-table>
          </div>
        </div>

        <!-- 基线告警详情 Drawer -->
        <a-drawer v-model:open="showBaselineDetailDrawer" title="基线违规详情" width="680">
          <template v-if="baselineDetailRecord">
            <div class="alarm-detail-header">
              <a-tag :color="severityColorMap[baselineDetailRecord.severity]" :bordered="false" class="severity-tag">{{ severityTextMap[baselineDetailRecord.severity] }}</a-tag>
              <span style="font-size: 12px; color: #86909C; font-family: monospace">{{ baselineDetailRecord.checkId }}</span>
              <span class="alarm-detail-title">{{ baselineDetailRecord.checkName }}</span>
            </div>

            <div class="alarm-detail-section" v-if="baselineDetailRecord.description">
              <div class="section-label">检查说明</div>
              <div class="section-content">{{ baselineDetailRecord.description }}</div>
            </div>

            <div class="alarm-detail-section remediation" v-if="baselineDetailRecord.remediation">
              <div class="section-label">修复建议</div>
              <div class="section-content remediation-content">{{ baselineDetailRecord.remediation }}</div>
            </div>

            <a-divider style="margin: 16px 0" />

            <a-descriptions :column="2" bordered size="small">
              <a-descriptions-item label="检查ID">{{ baselineDetailRecord.checkId }}</a-descriptions-item>
              <a-descriptions-item label="分类">{{ baselineDetailRecord.category }}</a-descriptions-item>
              <a-descriptions-item label="集群">{{ baselineDetailRecord.clusterName }}</a-descriptions-item>
              <a-descriptions-item label="状态">
                <a-tag :color="baselineDetailRecord.status === 'active' ? 'orange' : baselineDetailRecord.status === 'resolved' ? 'green' : 'default'" :bordered="false">
                  {{ baselineStatusTextMap[baselineDetailRecord.status] }}
                </a-tag>
              </a-descriptions-item>
              <a-descriptions-item label="首次发现">{{ baselineDetailRecord.firstSeenAt }}</a-descriptions-item>
              <a-descriptions-item label="最近检测">{{ baselineDetailRecord.lastSeenAt }}</a-descriptions-item>
            </a-descriptions>

            <template v-if="baselineDetailRecord.affectedResources && baselineDetailRecord.affectedResources.length > 0">
              <a-divider style="margin: 16px 0">受影响资源</a-divider>
              <a-table
                :columns="[
                  { title: '类型', dataIndex: 'kind', width: 120 },
                  { title: '名称', dataIndex: 'name' },
                  { title: '命名空间', dataIndex: 'namespace', width: 150 },
                ]"
                :data-source="baselineDetailRecord.affectedResources"
                :pagination="false"
                size="small"
                :row-key="(r: any) => `${r.kind}-${r.namespace}-${r.name}`"
              />
            </template>
          </template>
        </a-drawer>
      </a-tab-pane>
    </a-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import apiClient from '@/api/client'

const activeTab = ref('detection')
const searchText = ref('')
const filterCluster = ref<string>()
const filterSeverity = ref<string>()
const filterStatus = ref<string>()
const loading = ref(false)
const alarms = ref<any[]>([])
const clusterOptions = ref<any[]>([])
const selectedRowKeys = ref<string[]>([])
const showDetail = ref(false)
const detailRecord = ref<any>(null)
const stats = ref({ critical: 0, high: 0, medium: 0, low: 0 })

// 基线违规
const baselineSearch = ref('')
const baselineFilterSeverity = ref<string>()
const baselineFilterStatus = ref<string>()
const baselineLoading = ref(false)
const baselineAlerts = ref<any[]>([])
const baselineSelectedKeys = ref<string[]>([])
const baselineStats = ref({ active: 0, resolved: 0, ignored: 0 })
const baselinePagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })
const showBaselineDetailDrawer = ref(false)
const baselineDetailRecord = ref<any>(null)

const pagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const severityColorMap: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityTextMap: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }
const statusTextMap: Record<string, string> = { pending: '待处理', processed: '已处理', ignored: '已忽略' }
const alarmTypeTextMap: Record<string, string> = {
  container_escape: '容器逃逸',
  abnormal_process: '异常进程',
  abnormal_network: '异常网络',
  file_tamper: '文件篡改',
  privilege_escalation: '权限提升',
  reverse_shell: '反弹 Shell',
  crypto_mining: '挖矿行为',
}
const alarmTypeColorMap: Record<string, string> = {
  container_escape: 'red',
  abnormal_process: 'orange',
  abnormal_network: 'purple',
  file_tamper: 'gold',
  privilege_escalation: 'red',
  reverse_shell: 'red',
  crypto_mining: 'volcano',
}

const baselineStatusTextMap: Record<string, string> = { active: '活跃', resolved: '已恢复', ignored: '已忽略' }

const baselineColumns = [
  { title: '最近检测', dataIndex: 'lastSeenAt', key: 'lastSeenAt', width: 180 },
  { title: '级别', key: 'severity', width: 80 },
  { title: '检查ID', dataIndex: 'checkId', key: 'checkId', width: 130 },
  { title: '检查名称', dataIndex: 'checkName', key: 'checkName', ellipsis: true },
  { title: '分类', dataIndex: 'category', key: 'category', width: 120 },
  { title: '集群', dataIndex: 'clusterName', key: 'clusterName', width: 140 },
  { title: '状态', key: 'status', width: 100 },
  { title: '操作', key: 'action', width: 130 },
]

const columns = [
  { title: '告警时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
  { title: '级别', key: 'severity', width: 80 },
  { title: '集群', dataIndex: 'clusterName', key: 'clusterName', width: 140 },
  { title: '告警类型', key: 'alarmType', width: 120 },
  { title: '告警标题', dataIndex: 'title', key: 'title', width: 260, ellipsis: true },
  { title: '告警摘要', dataIndex: 'message', key: 'message', ellipsis: true },
  { title: '状态', key: 'status', width: 100 },
  { title: '操作', key: 'action', width: 130 },
]

const onSelectChange = (keys: string[]) => { selectedRowKeys.value = keys }

const loadAlarms = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/kube/alarms', {
      params: { page: pagination.value.current, page_size: pagination.value.pageSize, search: searchText.value || undefined, cluster_id: filterCluster.value || undefined, severity: filterSeverity.value || undefined, status: filterStatus.value || undefined },
    })
    alarms.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    if (res.stats) stats.value = res.stats
  } catch { alarms.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadAlarms() }
const showAlarmDetail = (record: any) => { detailRecord.value = record; showDetail.value = true }
const handleProcess = async (record: any) => { try { await apiClient.post(`/kube/alarms/${record.id}/process`); message.success('已处理'); loadAlarms() } catch (error) { console.error('处理告警失败:', error) } }
const handleBatchProcess = async () => { try { await apiClient.post('/kube/alarms/batch-process', { ids: selectedRowKeys.value }); message.success('批量处理成功'); selectedRowKeys.value = []; loadAlarms() } catch (error) { console.error('批量处理告警失败:', error) } }
const handleBatchIgnore = async () => { try { await apiClient.post('/kube/alarms/batch-ignore', { ids: selectedRowKeys.value }); message.success('批量忽略成功'); selectedRowKeys.value = []; loadAlarms() } catch (error) { console.error('批量忽略告警失败:', error) } }

const handleTabChange = (key: string) => {
  if (key === 'baseline') loadBaselineAlerts()
}

const loadBaselineAlerts = async () => {
  baselineLoading.value = true
  try {
    const res = await apiClient.get<any>('/kube/baseline-alerts', {
      params: { page: baselinePagination.value.current, page_size: baselinePagination.value.pageSize, search: baselineSearch.value || undefined, severity: baselineFilterSeverity.value || undefined, status: baselineFilterStatus.value || undefined },
    })
    baselineAlerts.value = res.items ?? []
    baselinePagination.value.total = res.total ?? 0
    if (res.stats) baselineStats.value = res.stats
  } catch { baselineAlerts.value = [] }
  finally { baselineLoading.value = false }
}

const handleBaselineTableChange = (pag: any) => { baselinePagination.value.current = pag.current; baselinePagination.value.pageSize = pag.pageSize; loadBaselineAlerts() }
const showBaselineDetail = (record: any) => { baselineDetailRecord.value = record; showBaselineDetailDrawer.value = true }
const handleBaselineIgnore = async (record: any) => { try { await apiClient.post(`/kube/baseline-alerts/${record.id}/ignore`); message.success('已忽略'); loadBaselineAlerts() } catch (error) { console.error('忽略基线告警失败:', error) } }
const handleBaselineBatchIgnore = async () => { try { await apiClient.post('/kube/baseline-alerts/batch-ignore', { ids: baselineSelectedKeys.value }); message.success('批量忽略成功'); baselineSelectedKeys.value = []; loadBaselineAlerts() } catch (error) { console.error('批量忽略基线告警失败:', error) } }

const loadClusters = async () => {
  try {
    const res = await apiClient.get<any>('/kube/clusters', { params: { page_size: 100 } })
    clusterOptions.value = (res.items ?? []).map((c: any) => ({ value: String(c.id), label: c.name }))
  } catch { /* ignore */ }
}

onMounted(() => { loadClusters(); loadAlarms() })
</script>

<style scoped>
.kube-alarms-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.alarm-stat { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 10px; padding: 20px; text-align: center; cursor: pointer; transition: all 0.2s; }
.alarm-stat:hover { transform: translateY(-2px); border-color: rgba(59, 130, 246, 0.4); }
.alarm-stat.critical .alarm-stat-value { color: #EF4444; }
.alarm-stat.high .alarm-stat-value { color: #F59E0B; }
.alarm-stat.medium .alarm-stat-value { color: #FADC19; }
.alarm-stat.low .alarm-stat-value { color: #3B82F6; }
.alarm-stat-value { font-size: 28px; font-weight: 700; line-height: 1.2; }
.alarm-stat-label { font-size: 13px; color: var(--mxsec-text-3); margin-top: 4px; }

.dashboard-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 10px; }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 16px; padding: 12px 16px; background: var(--mxsec-fill-1); border-radius: 6px; border: 1px solid var(--mxsec-border); flex-wrap: wrap; }

.raw-json { background: var(--mxsec-body-bg); padding: 16px; border-radius: 6px; font-size: 12px; font-family: 'SF Mono', 'Consolas', monospace; overflow-x: auto; max-height: 300px; color: var(--mxsec-text-1); }

.alarm-detail-header { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
.alarm-detail-title { font-size: 16px; font-weight: 600; color: var(--mxsec-text-1); }
.severity-tag { font-size: 13px; }
.alarm-detail-message { font-size: 14px; color: var(--mxsec-text-2); line-height: 1.6; margin-bottom: 16px; padding: 12px 16px; background: var(--mxsec-body-bg); border-radius: 6px; border-left: 3px solid #3B82F6; }

.alarm-detail-section { margin-bottom: 12px; }
.section-label { font-size: 13px; font-weight: 600; color: var(--mxsec-text-1); margin-bottom: 6px; }
.section-content { font-size: 13px; color: var(--mxsec-text-2); line-height: 1.8; padding: 10px 14px; background: var(--mxsec-body-bg); border-radius: 6px; }
.alarm-detail-section.remediation .section-content { background: rgba(245, 158, 11, 0.08); border-left: 3px solid #F59E0B; white-space: pre-line; }
</style>
