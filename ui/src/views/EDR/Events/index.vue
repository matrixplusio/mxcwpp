<template>
  <div class="edr-events">
    <div class="page-header">
      <h2>EDR 事件</h2>
      <a-space>
        <a-select
          v-model:value="statsHours"
          style="width: 120px"
          @change="fetchStats"
        >
          <a-select-option :value="1">最近 1 小时</a-select-option>
          <a-select-option :value="6">最近 6 小时</a-select-option>
          <a-select-option :value="24">最近 24 小时</a-select-option>
          <a-select-option :value="72">最近 3 天</a-select-option>
          <a-select-option :value="168">最近 7 天</a-select-option>
        </a-select>
        <a-button @click="handleRefresh">
          <ReloadOutlined /> 刷新
        </a-button>
      </a-space>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="16" class="stat-cards">
      <a-col :span="4">
        <a-card size="small">
          <a-statistic title="总事件" :value="stats.total" />
        </a-card>
      </a-col>
      <a-col :span="5">
        <a-card size="small">
          <a-statistic title="进程执行" :value="stats.process_exec" :value-style="{ color: '#3B82F6' }" />
        </a-card>
      </a-col>
      <a-col :span="5">
        <a-card size="small">
          <a-statistic title="文件访问" :value="stats.file_open" :value-style="{ color: '#F59E0B' }" />
        </a-card>
      </a-col>
      <a-col :span="5">
        <a-card size="small">
          <a-statistic title="网络连接" :value="stats.network_connect" :value-style="{ color: '#0FC6C2' }" />
        </a-card>
      </a-col>
      <a-col :span="5">
        <a-card size="small">
          <a-statistic title="Top 进程" :value="stats.top_exes.length > 0 ? stats.top_exes[0].exe.split('/').pop() : '-'" :value-style="{ fontSize: '16px' }" />
          <div v-if="stats.top_exes.length > 0" style="color: #999; font-size: 12px">
            {{ stats.top_exes[0].count }} 次
          </div>
        </a-card>
      </a-col>
    </a-row>

    <!-- 筛选栏 -->
    <div class="filter-bar">
      <a-input
        v-model:value="filters.hostname"
        placeholder="主机名"
        style="width: 140px"
        allow-clear
        @change="handleSearch"
      >
        <template #prefix><SearchOutlined /></template>
      </a-input>
      <a-input
        v-model:value="filters.keyword"
        placeholder="关键词 (exe/cmdline/path)"
        style="width: 220px; margin-left: 8px"
        allow-clear
        @pressEnter="handleSearch"
        @change="handleSearch"
      />
      <a-select
        v-model:value="filters.event_type"
        placeholder="事件类型"
        style="width: 130px; margin-left: 8px"
        allow-clear
        @change="handleSearch"
      >
        <a-select-option value="process_exec">进程执行</a-select-option>
        <a-select-option value="file_open">文件访问</a-select-option>
        <a-select-option value="tcp_connect">TCP 连接</a-select-option>
        <a-select-option value="udp_send">UDP 发送</a-select-option>
        <a-select-option value="dns_query">DNS 查询</a-select-option>
      </a-select>
      <a-select
        v-model:value="filters.data_type"
        placeholder="DataType"
        style="width: 130px; margin-left: 8px"
        allow-clear
        @change="handleSearch"
      >
        <a-select-option :value="3000">3000 进程</a-select-option>
        <a-select-option :value="3001">3001 文件</a-select-option>
        <a-select-option :value="3002">3002 网络</a-select-option>
        <a-select-option :value="3003">3003 DNS</a-select-option>
      </a-select>
      <a-input
        v-model:value="filters.remote_addr"
        placeholder="远程 IP"
        style="width: 140px; margin-left: 8px"
        allow-clear
        @pressEnter="handleSearch"
      />
      <a-input
        v-model:value="filters.pid"
        placeholder="PID"
        style="width: 80px; margin-left: 8px"
        allow-clear
        @pressEnter="handleSearch"
      />
      <a-range-picker
        v-model:value="dateRange"
        style="margin-left: 8px"
        @change="handleDateChange"
      />
    </div>

    <!-- 事件表格 -->
    <a-table
      :columns="columns"
      :data-source="events"
      :loading="loading"
      :pagination="pagination"
      :row-key="(_: EDREvent, index: number) => index"
      size="small"
      @change="handleTableChange"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'hostname'">
          <a-tooltip :title="record.host_id">
            {{ record.hostname || record.host_id?.substring(0, 8) }}
          </a-tooltip>
        </template>
        <template v-if="column.key === 'event_type'">
          <a-tag :color="getEventTypeColor(record.event_type)">
            {{ getEventTypeText(record.event_type) }}
          </a-tag>
        </template>
        <template v-if="column.key === 'exe'">
          <a-tooltip :title="record.cmdline || record.exe">
            <span class="mono-text">{{ record.exe }}</span>
          </a-tooltip>
        </template>
        <template v-if="column.key === 'detail'">
          <span class="mono-text detail-cell">{{ getEventDetail(record) }}</span>
        </template>
        <template v-if="column.key === 'pid_info'">
          <span>{{ record.pid }}</span>
          <span v-if="record.ppid" class="ppid-text"> / {{ record.ppid }}</span>
        </template>
        <template v-if="column.key === 'uid'">
          {{ record.uid || '-' }}
        </template>
        <template v-if="column.key === 'action'">
          <a @click="showDetail(record)">详情</a>
        </template>
      </template>
    </a-table>

    <!-- 事件详情弹窗 -->
    <a-modal
      v-model:open="detailVisible"
      title="EDR 事件详情"
      :width="700"
      :footer="null"
    >
      <template v-if="selectedEvent">
        <a-descriptions :column="2" bordered size="small">
          <a-descriptions-item label="时间" :span="2">{{ selectedEvent.timestamp }}</a-descriptions-item>
          <a-descriptions-item label="主机名">{{ selectedEvent.hostname }}</a-descriptions-item>
          <a-descriptions-item label="主机 ID">
            <span class="mono-text" style="font-size: 12px">{{ selectedEvent.host_id }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="事件类型">
            <a-tag :color="getEventTypeColor(selectedEvent.event_type)">
              {{ getEventTypeText(selectedEvent.event_type) }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="DataType">{{ selectedEvent.data_type }}</a-descriptions-item>
          <a-descriptions-item label="PID">{{ selectedEvent.pid }}</a-descriptions-item>
          <a-descriptions-item label="PPID">{{ selectedEvent.ppid || '-' }}</a-descriptions-item>
          <a-descriptions-item label="可执行文件" :span="2">
            <code>{{ selectedEvent.exe || '-' }}</code>
          </a-descriptions-item>
          <a-descriptions-item label="命令行" :span="2">
            <code style="word-break: break-all">{{ selectedEvent.cmdline || '-' }}</code>
          </a-descriptions-item>
          <a-descriptions-item label="父进程" :span="2">
            <code>{{ selectedEvent.parent_exe || '-' }}</code>
          </a-descriptions-item>
          <template v-if="selectedEvent.file_path">
            <a-descriptions-item label="文件路径" :span="2">
              <code>{{ selectedEvent.file_path }}</code>
            </a-descriptions-item>
          </template>
          <template v-if="selectedEvent.remote_addr">
            <a-descriptions-item label="远程地址">{{ selectedEvent.remote_addr }}:{{ selectedEvent.remote_port }}</a-descriptions-item>
            <a-descriptions-item label="本地地址">{{ selectedEvent.local_addr }}:{{ selectedEvent.local_port }}</a-descriptions-item>
            <a-descriptions-item label="协议">{{ selectedEvent.protocol || '-' }}</a-descriptions-item>
          </template>
          <a-descriptions-item label="UID">{{ selectedEvent.uid || '-' }}</a-descriptions-item>
          <a-descriptions-item label="GID">{{ selectedEvent.gid || '-' }}</a-descriptions-item>
          <a-descriptions-item label="返回码">{{ selectedEvent.return_code || '-' }}</a-descriptions-item>
        </a-descriptions>
      </template>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { SearchOutlined, ReloadOutlined } from '@ant-design/icons-vue'
import { edrApi } from '@/api/edr'
import type { EDREvent, EDREventStats } from '@/api/types'
import type { Dayjs } from 'dayjs'

const loading = ref(false)
const events = ref<EDREvent[]>([])
const detailVisible = ref(false)
const selectedEvent = ref<EDREvent | null>(null)
const dateRange = ref<[Dayjs, Dayjs] | null>(null)
const statsHours = ref(24)

const stats = reactive<EDREventStats>({
  total: 0,
  process_exec: 0,
  file_open: 0,
  network_connect: 0,
  by_data_type: {},
  top_hosts: [],
  top_exes: [],
  trend: [],
})

const filters = reactive({
  hostname: '',
  keyword: '',
  event_type: undefined as string | undefined,
  data_type: undefined as number | undefined,
  remote_addr: '',
  pid: '',
  date_from: undefined as string | undefined,
  date_to: undefined as string | undefined,
})

const pagination = reactive({
  current: 1,
  pageSize: 50,
  total: 0,
  showSizeChanger: true,
  pageSizeOptions: ['20', '50', '100', '200'],
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  { title: '时间', dataIndex: 'timestamp', width: 170 },
  { title: '主机名', key: 'hostname', width: 120 },
  { title: '类型', key: 'event_type', width: 100, align: 'center' as const },
  { title: '可执行文件', key: 'exe', ellipsis: true, width: 200 },
  { title: '详情', key: 'detail', ellipsis: true },
  { title: 'PID/PPID', key: 'pid_info', width: 100 },
  { title: 'UID', key: 'uid', width: 60 },
  { title: '操作', key: 'action', width: 60 },
]

const getEventTypeColor = (type: string) => {
  const colors: Record<string, string> = {
    process_exec: 'blue',
    file_open: 'orange',
    file_rename: 'orange',
    file_unlink: 'red',
    file_chmod: 'orange',
    tcp_connect: 'cyan',
    tcp_accept: 'cyan',
    udp_send: 'green',
    dns_query: 'purple',
  }
  return colors[type] || 'default'
}

const getEventTypeText = (type: string) => {
  const texts: Record<string, string> = {
    process_exec: '进程执行',
    file_open: '文件访问',
    file_rename: '文件重命名',
    file_unlink: '文件删除',
    file_chmod: '权限修改',
    tcp_connect: 'TCP 连接',
    tcp_accept: 'TCP 接收',
    udp_send: 'UDP 发送',
    dns_query: 'DNS 查询',
  }
  return texts[type] || type
}

const getEventDetail = (record: EDREvent) => {
  if (record.event_type === 'process_exec') {
    return record.cmdline || record.exe
  }
  if (record.event_type === 'file_open' || record.event_type === 'file_rename' || record.event_type === 'file_unlink' || record.event_type === 'file_chmod') {
    return record.file_path || '-'
  }
  if (record.event_type === 'dns_query') {
    return record.remote_addr ? `DNS → ${record.remote_addr}` : '-'
  }
  if (record.event_type === 'tcp_connect' || record.event_type === 'tcp_accept' || record.event_type === 'udp_send') {
    return record.remote_addr ? `${record.remote_addr}:${record.remote_port} (${record.protocol || 'tcp'})` : '-'
  }
  return record.cmdline || record.file_path || '-'
}

const fetchEvents = async () => {
  loading.value = true
  try {
    const res = await edrApi.listEvents({
      page: pagination.current,
      page_size: pagination.pageSize,
      hostname: filters.hostname || undefined,
      keyword: filters.keyword || undefined,
      event_type: filters.event_type,
      data_type: filters.data_type,
      remote_addr: filters.remote_addr || undefined,
      pid: filters.pid || undefined,
      date_from: filters.date_from,
      date_to: filters.date_to,
    })
    events.value = res.items || []
    pagination.total = res.total
  } catch {
    // API 客户端已处理错误提示
  } finally {
    loading.value = false
  }
}

const fetchStats = async () => {
  try {
    const res = await edrApi.getEventStats(statsHours.value)
    Object.assign(stats, res)
  } catch {
    // 静默处理
  }
}

const handleSearch = () => {
  pagination.current = 1
  fetchEvents()
}

const handleRefresh = () => {
  fetchEvents()
  fetchStats()
}

const handleDateChange = (dates: [Dayjs, Dayjs] | null) => {
  if (dates) {
    filters.date_from = dates[0].format('YYYY-MM-DD')
    filters.date_to = dates[1].format('YYYY-MM-DD')
  } else {
    filters.date_from = undefined
    filters.date_to = undefined
  }
  handleSearch()
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  fetchEvents()
}

const showDetail = (event: EDREvent) => {
  selectedEvent.value = event
  detailVisible.value = true
}

onMounted(() => {
  fetchEvents()
  fetchStats()
})
</script>

<style scoped>
.edr-events { padding: 0; }

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.page-header h2 { margin: 0; font-size: 20px; }
.stat-cards { margin-bottom: 16px; }

.filter-bar {
  display: flex;
  align-items: center;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 4px;
}

.mono-text { font-family: monospace; font-size: 13px; }
.detail-cell { color: #555; }
.ppid-text { color: #999; font-size: 12px; }
</style>
