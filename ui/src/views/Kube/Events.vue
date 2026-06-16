<template>
  <div class="kube-events-page">
    <div class="page-header">
      <h2>容器集群安全事件</h2>
      <span class="page-header-hint">Kubernetes 安全事件追踪与处理</span>
    </div>

    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search v-model:value="searchText" placeholder="搜索事件内容" style="width: 240px" allow-clear @search="loadEvents" />
          <a-select v-model:value="filterCluster" style="width: 180px" placeholder="集群" allow-clear @change="loadEvents">
            <a-select-option v-for="c in clusterOptions" :key="c.value" :value="c.value">{{ c.label }}</a-select-option>
          </a-select>
          <a-select v-model:value="filterType" style="width: 160px" placeholder="事件类型" allow-clear @change="loadEvents">
            <a-select-option value="container_escape">容器逃逸</a-select-option>
            <a-select-option value="abnormal_process">异常进程</a-select-option>
            <a-select-option value="abnormal_network">异常网络</a-select-option>
            <a-select-option value="file_tamper">文件篡改</a-select-option>
            <a-select-option value="privilege_escalation">提权行为</a-select-option>
            <a-select-option value="reverse_shell">反弹 Shell</a-select-option>
            <a-select-option value="crypto_mining">挖矿行为</a-select-option>
          </a-select>
          <a-range-picker v-model:value="dateRange" style="width: 240px" @change="loadEvents" />
        </div>

        <a-table
          :columns="columns"
          :data-source="events"
          :loading="loading"
          :pagination="pagination"
          @change="handleTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity]" :bordered="false">{{ severityTextMap[record.severity] }}</a-tag>
            </template>
            <template v-if="column.key === 'eventType'">
              <a-tag :bordered="false" :color="eventTypeColorMap[record.eventType] || 'purple'">{{ eventTypeTextMap[record.eventType] || record.eventType }}</a-tag>
            </template>
            <template v-if="column.key === 'status'">
              <a-tag :color="record.status === 'unhandled' ? 'orange' : 'green'" :bordered="false">
                {{ record.status === 'unhandled' ? '未处理' : '已处理' }}
              </a-tag>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="showEventDetail(record)">详情</a-button>
                <a-button type="link" size="small" @click="handleEvent(record)" v-if="record.status === 'unhandled'">处理</a-button>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 事件详情 Drawer -->
    <a-drawer v-model:open="showDetail" title="安全事件详情" width="700">
      <template v-if="detailRecord">
        <a-descriptions :column="2" bordered size="small">
          <a-descriptions-item label="事件 ID">{{ detailRecord.id }}</a-descriptions-item>
          <a-descriptions-item label="集群">{{ detailRecord.clusterName }}</a-descriptions-item>
          <a-descriptions-item label="事件类型"><a-tag :bordered="false" :color="eventTypeColorMap[detailRecord.eventType] || 'purple'">{{ eventTypeTextMap[detailRecord.eventType] || detailRecord.eventType }}</a-tag></a-descriptions-item>
          <a-descriptions-item label="严重级别"><a-tag :color="severityColorMap[detailRecord.severity]" :bordered="false">{{ severityTextMap[detailRecord.severity] }}</a-tag></a-descriptions-item>
          <a-descriptions-item label="Namespace">{{ detailRecord.namespace }}</a-descriptions-item>
          <a-descriptions-item label="Pod">{{ detailRecord.podName }}</a-descriptions-item>
          <a-descriptions-item label="容器">{{ detailRecord.containerName }}</a-descriptions-item>
          <a-descriptions-item label="镜像">{{ detailRecord.image }}</a-descriptions-item>
          <a-descriptions-item label="事件描述" :span="2">{{ detailRecord.message }}</a-descriptions-item>
          <a-descriptions-item label="进程信息" :span="2">{{ detailRecord.processInfo }}</a-descriptions-item>
          <a-descriptions-item label="发现时间">{{ detailRecord.createdAt }}</a-descriptions-item>
          <a-descriptions-item label="状态">
            <a-tag :color="detailRecord.status === 'unhandled' ? 'orange' : 'green'" :bordered="false">
              {{ detailRecord.status === 'unhandled' ? '未处理' : '已处理' }}
            </a-tag>
          </a-descriptions-item>
        </a-descriptions>
        <a-divider v-if="detailRecord.rawData">原始数据</a-divider>
        <pre v-if="detailRecord.rawData" class="raw-json">{{ JSON.stringify(detailRecord.rawData, null, 2) }}</pre>
      </template>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import type { Dayjs } from 'dayjs'
import { message } from 'ant-design-vue'
import apiClient from '@/api/client'

const searchText = ref('')
const filterCluster = ref<string>()
const filterType = ref<string>()
const dateRange = ref<[Dayjs, Dayjs]>()
const loading = ref(false)
const events = ref<any[]>([])
const clusterOptions = ref<any[]>([])
const showDetail = ref(false)
const detailRecord = ref<any>(null)

const pagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const severityColorMap: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityTextMap: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }
const eventTypeTextMap: Record<string, string> = {
  audit: '审计事件',
  container_escape: '容器逃逸',
  abnormal_process: '异常进程',
  abnormal_network: '异常网络',
  file_tamper: '文件篡改',
  privilege_escalation: '权限提升',
  reverse_shell: '反弹 Shell',
  crypto_mining: '挖矿行为',
}
const eventTypeColorMap: Record<string, string> = {
  audit: 'blue',
  container_escape: 'red',
  abnormal_process: 'orange',
  abnormal_network: 'purple',
  file_tamper: 'gold',
  privilege_escalation: 'red',
  reverse_shell: 'red',
  crypto_mining: 'volcano',
}

const columns = [
  { title: '事件时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
  { title: '级别', key: 'severity', width: 80 },
  { title: '事件类型', key: 'eventType', width: 120 },
  { title: '集群', dataIndex: 'clusterName', key: 'clusterName', width: 140 },
  { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 120 },
  { title: '描述', dataIndex: 'title', key: 'title', ellipsis: true },
  { title: '详情', dataIndex: 'message', key: 'message', ellipsis: true },
  { title: '状态', key: 'status', width: 100 },
  { title: '操作', key: 'action', width: 130 },
]

const loadEvents = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/kube/events', {
      params: { page: pagination.value.current, page_size: pagination.value.pageSize, search: searchText.value || undefined, cluster_id: filterCluster.value || undefined, event_type: filterType.value || undefined },
    })
    events.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch { events.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadEvents() }
const showEventDetail = (record: any) => { detailRecord.value = record; showDetail.value = true }
const handleEvent = async (record: any) => { try { await apiClient.post(`/kube/events/${record.id}/handle`); message.success('已处理'); loadEvents() } catch (error) { console.error('处理事件失败:', error) } }

const loadClusters = async () => {
  try {
    const res = await apiClient.get<any>('/kube/clusters', { params: { page_size: 100 } })
    clusterOptions.value = (res.items ?? []).map((c: any) => ({ value: String(c.id), label: c.name }))
  } catch { /* ignore */ }
}

onMounted(() => { loadClusters(); loadEvents() })
</script>

<style scoped>
.kube-events-page { width: 100%; }
.dashboard-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 16px; padding: 12px 16px; background: var(--mxsec-fill-1); border-radius: 4px; border: 1px solid var(--mxsec-border); flex-wrap: wrap; }
.raw-json { background: var(--mxsec-fill-1); padding: 16px; border-radius: 4px; font-size: 12px; font-family: 'SF Mono', 'Consolas', monospace; overflow-x: auto; max-height: 300px; color: var(--mxsec-text-1); }
</style>
