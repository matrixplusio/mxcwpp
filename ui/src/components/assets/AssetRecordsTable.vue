<template>
  <div class="asset-records-table">
    <div class="filter-bar">
      <a-input-search
        v-model:value="searchText"
        :placeholder="searchPlaceholder"
        style="width: 280px"
        allow-clear
        @search="handleSearch"
      />

      <a-select
        v-if="allowBusinessLineFilter"
        :value="selectedBusinessLine"
        style="width: 200px"
        placeholder="按业务线筛选"
        allow-clear
        show-search
        option-filter-prop="label"
        @change="handleBusinessLineChange"
      >
        <a-select-option
          v-for="line in businessLineOptions"
          :key="line.value"
          :value="line.value"
          :label="line.label"
        >
          {{ line.label }}
        </a-select-option>
      </a-select>

      <a-select
        v-if="allowHostFilter"
        :value="selectedHostId"
        style="width: 240px"
        placeholder="按主机筛选"
        allow-clear
        show-search
        option-filter-prop="label"
        @change="handleHostChange"
      >
        <a-select-option
          v-for="host in hostOptions"
          :key="host.value"
          :value="host.value"
          :label="host.label"
        >
          {{ host.label }}
        </a-select-option>
      </a-select>

      <template v-for="filter in activeFilters" :key="filter.key">
        <a-select
          v-model:value="filterState[filter.key]"
          :placeholder="filter.label"
          style="width: 160px"
          allow-clear
          @change="handleFilterChange"
        >
          <a-select-option
            v-for="option in filter.options"
            :key="option.value"
            :value="option.value"
          >
            {{ option.label }}
          </a-select-option>
        </a-select>
      </template>

      <a-button @click="handleReset">重置</a-button>
      <a-button :loading="exportLoading" @click="handleExport">导出</a-button>
    </div>

    <a-table
      :columns="columns"
      :data-source="tableData"
      :loading="loading"
      :pagination="pagination"
      :scroll="{ x: 1280 }"
      size="middle"
      row-key="id"
      @change="handleTableChange"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'host_display'">
          <div class="host-cell">
            <RouterLink :to="`/hosts/${record.host_id}`" class="host-link">
              {{ formatHostTitle(record.host_id) }}
            </RouterLink>
            <div class="host-meta">
              {{ formatHostMeta(record.host_id) }}
            </div>
          </div>
        </template>

        <template v-else-if="column.key === 'protocol'">
          <a-tag :color="record.protocol === 'tcp' ? 'blue' : 'green'">
            {{ String(record.protocol || '-').toUpperCase() }}
          </a-tag>
        </template>

        <template v-else-if="column.key === 'port'">
          <a-tag color="orange">{{ record.port }}</a-tag>
        </template>

        <template v-else-if="column.key === 'status'">
          <a-tag :color="statusColor(record.status)">
            {{ record.status || '-' }}
          </a-tag>
        </template>

        <template v-else-if="column.key === 'enabled'">
          <a-tag :color="record.enabled ? 'green' : 'default'">
            {{ record.enabled ? '是' : '否' }}
          </a-tag>
        </template>

        <template v-else-if="column.key === 'has_password'">
          <a-tag :color="record.has_password ? 'green' : 'red'">
            {{ record.has_password ? '有密码' : '无密码' }}
          </a-tag>
        </template>

        <template v-else-if="column.key === 'container_id'">
          <a-tooltip :title="record.container_id">
            <a-tag v-if="record.container_id" color="blue">
              {{ shorten(record.container_id, 12) }}
            </a-tag>
            <span v-else class="empty-text">-</span>
          </a-tooltip>
        </template>

        <template v-else-if="column.key === 'image' || column.key === 'cmdline' || column.key === 'config_path' || column.key === 'data_path' || column.key === 'description' || column.key === 'command' || column.key === 'exe'">
          <a-tooltip :title="record[column.dataIndex]">
            <span class="ellipsis-text">
              {{ record[column.dataIndex] || '-' }}
            </span>
          </a-tooltip>
        </template>

        <template v-else-if="column.key === 'ipv4_addresses' || column.key === 'ipv6_addresses'">
          <template v-if="record[column.dataIndex]?.length">
            <a-tooltip :title="record[column.dataIndex].join(', ')">
              <span>{{ record[column.dataIndex][0] }}</span>
            </a-tooltip>
            <a-tag
              v-if="record[column.dataIndex].length > 1"
              color="blue"
              size="small"
              style="margin-left: 6px"
            >
              +{{ record[column.dataIndex].length - 1 }}
            </a-tag>
          </template>
          <span v-else class="empty-text">-</span>
        </template>

        <template v-else-if="column.key === 'size' || column.key === 'total_size' || column.key === 'used_size' || column.key === 'available_size'">
          {{ formatBytes(record[column.dataIndex]) }}
        </template>

        <template v-else-if="column.key === 'usage_percent'">
          {{ formatPercent(record.usage_percent) }}
        </template>

        <template v-else-if="column.key === 'created_at' || column.key === 'install_time' || column.key === 'collected_at'">
          {{ formatTime(record[column.dataIndex]) }}
        </template>

        <template v-else-if="column.key === 'hostname'">
          {{ formatHostTitle(record.host_id) }}
        </template>
      </template>

      <template #emptyText>
        <a-empty :description="emptyDescription" />
      </template>
    </a-table>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { assetsApi } from '@/api/assets'
import apiClient from '@/api/client'
import type { PaginatedResponse } from '@/api/types'
import { message } from 'ant-design-vue'

type AssetType =
  | 'ports'
  | 'processes'
  | 'users'
  | 'packages'
  | 'containers'
  | 'apps'
  | 'network-interfaces'
  | 'volumes'
  | 'kmods'
  | 'services'
  | 'crontabs'

interface HostOption {
  value: string
  label: string
}

interface BusinessLineOption {
  value: string
  label: string
}

interface HostMapItem {
  hostname?: string
  ipv4?: string[]
  business_line?: string
}

interface AssetFilterOption {
  value: string
  label: string
}

interface AssetFilterDef {
  key: string
  label: string
  options: AssetFilterOption[]
}

const props = withDefaults(defineProps<{
  assetType: AssetType
  selectedHostId?: string
  selectedBusinessLine?: string
  allowHostFilter?: boolean
  allowBusinessLineFilter?: boolean
  hostOptions?: HostOption[]
  businessLineOptions?: BusinessLineOption[]
  hostMap?: Record<string, HostMapItem>
}>(), {
  allowHostFilter: false,
  allowBusinessLineFilter: false,
  selectedHostId: undefined,
  selectedBusinessLine: undefined,
  hostOptions: () => [],
  businessLineOptions: () => [],
  hostMap: () => ({}),
})

const emit = defineEmits<{
  'update:selectedHostId': [value?: string]
  'update:selectedBusinessLine': [value?: string]
}>()

const loading = ref(false)
const exportLoading = ref(false)
const searchText = ref('')
const tableData = ref<any[]>([])
const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const filterState = reactive<Record<string, string | undefined>>({
  protocol: undefined,
  package_type: undefined,
  runtime: undefined,
  status: undefined,
  service_type: undefined,
  cron_type: undefined,
})

const tableRouteMap: Record<AssetType, string> = {
  ports: '/assets/ports',
  processes: '/assets/processes',
  users: '/assets/users',
  packages: '/assets/software',
  containers: '/assets/containers',
  apps: '/assets/apps',
  'network-interfaces': '/assets/network-interfaces',
  volumes: '/assets/volumes',
  kmods: '/assets/kmods',
  services: '/assets/services',
  crontabs: '/assets/crons',
}

const exportTypeMap: Record<AssetType, string> = {
  ports: 'ports',
  processes: 'processes',
  users: 'users',
  packages: 'software',
  containers: 'containers',
  apps: 'apps',
  'network-interfaces': 'network-interfaces',
  volumes: 'volumes',
  kmods: 'kmods',
  services: 'services',
  crontabs: 'crons',
}

const searchPlaceholderMap: Record<AssetType, string> = {
  ports: '搜索端口号、进程名或状态',
  processes: '搜索进程名、PID、命令行或用户',
  users: '搜索用户名、UID、组名或 shell',
  packages: '搜索软件包名、版本或厂商',
  containers: '搜索容器名、镜像或容器 ID',
  apps: '搜索应用名、类型、端口或配置路径',
  'network-interfaces': '搜索网卡名、MAC 或 IP 地址',
  volumes: '搜索挂载点、设备或文件系统',
  kmods: '搜索内核模块名或状态',
  services: '搜索服务名、状态或描述',
  crontabs: '搜索用户、调度或命令',
}

const emptyTextMap: Record<AssetType, string> = {
  ports: '暂无端口数据',
  processes: '暂无进程数据',
  users: '暂无用户数据',
  packages: '暂无软件包数据',
  containers: '暂无容器数据',
  apps: '暂无应用数据',
  'network-interfaces': '暂无网卡数据',
  volumes: '暂无磁盘卷数据',
  kmods: '暂无内核模块数据',
  services: '暂无服务数据',
  crontabs: '暂无定时任务数据',
}

const filterDefsMap: Partial<Record<AssetType, AssetFilterDef[]>> = {
  ports: [
    { key: 'protocol', label: '协议', options: [{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }] },
  ],
  packages: [
    {
      key: 'package_type',
      label: '包类型',
      options: [
        { value: 'rpm', label: 'RPM' },
        { value: 'deb', label: 'DEB' },
        { value: 'apk', label: 'APK' },
        { value: 'pip', label: 'PIP' },
        { value: 'npm', label: 'NPM' },
        { value: 'jar', label: 'JAR' },
        { value: 'go', label: 'Go' },
        { value: 'cargo', label: 'Cargo' },
      ],
    },
  ],
  containers: [
    {
      key: 'runtime',
      label: '运行时',
      options: [
        { value: 'docker', label: 'Docker' },
        { value: 'containerd', label: 'containerd' },
        { value: 'cri-o', label: 'CRI-O' },
      ],
    },
    {
      key: 'status',
      label: '状态',
      options: [
        { value: 'running', label: 'running' },
        { value: 'exited', label: 'exited' },
        { value: 'stopped', label: 'stopped' },
        { value: 'paused', label: 'paused' },
      ],
    },
  ],
  services: [
    {
      key: 'service_type',
      label: '服务类型',
      options: [
        { value: 'systemd', label: 'systemd' },
        { value: 'sysv', label: 'sysv' },
      ],
    },
    {
      key: 'status',
      label: '状态',
      options: [
        { value: 'active', label: 'active' },
        { value: 'inactive', label: 'inactive' },
        { value: 'failed', label: 'failed' },
      ],
    },
  ],
  crontabs: [
    {
      key: 'cron_type',
      label: '任务类型',
      options: [
        { value: 'crontab', label: 'crontab' },
        { value: 'systemd-timer', label: 'systemd-timer' },
      ],
    },
  ],
}

const baseColumnsMap: Record<AssetType, Array<Record<string, any>>> = {
  ports: [
    { title: '端口', dataIndex: 'port', key: 'port', width: 90 },
    { title: '协议', dataIndex: 'protocol', key: 'protocol', width: 90 },
    { title: '进程名', dataIndex: 'process_name', key: 'process_name', width: 180 },
    { title: 'PID', dataIndex: 'pid', key: 'pid', width: 90 },
    { title: '状态', dataIndex: 'state', key: 'status', width: 120 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
  processes: [
    { title: '进程名', dataIndex: 'exe', key: 'exe', width: 180 },
    { title: 'PID', dataIndex: 'pid', key: 'pid', width: 90 },
    { title: '用户', dataIndex: 'username', key: 'username', width: 120 },
    { title: '命令行', dataIndex: 'cmdline', key: 'cmdline', width: 320 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
  users: [
    { title: '用户名', dataIndex: 'username', key: 'username', width: 140 },
    { title: 'UID', dataIndex: 'uid', key: 'uid', width: 90 },
    { title: 'GID', dataIndex: 'gid', key: 'gid', width: 90 },
    { title: 'Shell', dataIndex: 'shell', key: 'shell', width: 160 },
    { title: '主目录', dataIndex: 'home_dir', key: 'home_dir', width: 220 },
    { title: '密码', dataIndex: 'has_password', key: 'has_password', width: 100 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
  packages: [
    { title: '包名', dataIndex: 'name', key: 'name', width: 220 },
    { title: '版本', dataIndex: 'version', key: 'version', width: 180 },
    { title: '类型', dataIndex: 'package_type', key: 'package_type', width: 100 },
    { title: '架构', dataIndex: 'architecture', key: 'architecture', width: 100 },
    { title: '厂商', dataIndex: 'vendor', key: 'vendor', width: 160 },
    { title: '安装时间', dataIndex: 'install_time', key: 'install_time', width: 180 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
  containers: [
    { title: '容器名', dataIndex: 'container_name', key: 'container_name', width: 180 },
    { title: '运行时', dataIndex: 'runtime', key: 'runtime', width: 120 },
    { title: '状态', dataIndex: 'status', key: 'status', width: 120 },
    { title: '镜像', dataIndex: 'image', key: 'image', width: 260 },
    { title: '容器ID', dataIndex: 'container_id', key: 'container_id', width: 150 },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 180 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
  apps: [
    { title: '应用名', dataIndex: 'app_name', key: 'app_name', width: 180 },
    { title: '类型', dataIndex: 'app_type', key: 'app_type', width: 140 },
    { title: '版本', dataIndex: 'version', key: 'version', width: 140 },
    { title: '端口', dataIndex: 'port', key: 'port', width: 90 },
    { title: '进程ID', dataIndex: 'process_id', key: 'process_id', width: 100 },
    { title: '配置路径', dataIndex: 'config_path', key: 'config_path', width: 260 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
  'network-interfaces': [
    { title: '网卡名', dataIndex: 'interface_name', key: 'interface_name', width: 140 },
    { title: 'MAC', dataIndex: 'mac_address', key: 'mac_address', width: 160 },
    { title: 'IPv4', dataIndex: 'ipv4_addresses', key: 'ipv4_addresses', width: 180 },
    { title: 'IPv6', dataIndex: 'ipv6_addresses', key: 'ipv6_addresses', width: 220 },
    { title: '状态', dataIndex: 'state', key: 'status', width: 100 },
    { title: 'MTU', dataIndex: 'mtu', key: 'mtu', width: 80 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
  volumes: [
    { title: '挂载点', dataIndex: 'mount_point', key: 'mount_point', width: 180 },
    { title: '设备', dataIndex: 'device', key: 'device', width: 180 },
    { title: '文件系统', dataIndex: 'file_system', key: 'file_system', width: 120 },
    { title: '总容量', dataIndex: 'total_size', key: 'total_size', width: 120 },
    { title: '已用', dataIndex: 'used_size', key: 'used_size', width: 120 },
    { title: '可用', dataIndex: 'available_size', key: 'available_size', width: 120 },
    { title: '使用率', dataIndex: 'usage_percent', key: 'usage_percent', width: 100 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
  kmods: [
    { title: '模块名', dataIndex: 'module_name', key: 'module_name', width: 220 },
    { title: '状态', dataIndex: 'state', key: 'status', width: 120 },
    { title: '大小', dataIndex: 'size', key: 'size', width: 120 },
    { title: '引用数', dataIndex: 'used_by', key: 'used_by', width: 100 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
  services: [
    { title: '服务名', dataIndex: 'service_name', key: 'service_name', width: 220 },
    { title: '状态', dataIndex: 'status', key: 'status', width: 120 },
    { title: '类型', dataIndex: 'service_type', key: 'service_type', width: 100 },
    { title: '自启', dataIndex: 'enabled', key: 'enabled', width: 90 },
    { title: '描述', dataIndex: 'description', key: 'description', width: 260 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
  crontabs: [
    { title: '用户', dataIndex: 'user', key: 'user', width: 120 },
    { title: '任务类型', dataIndex: 'cron_type', key: 'cron_type', width: 120 },
    { title: '调度', dataIndex: 'schedule', key: 'schedule', width: 160 },
    { title: '启用', dataIndex: 'enabled', key: 'enabled', width: 90 },
    { title: '命令', dataIndex: 'command', key: 'command', width: 320 },
    { title: '采集时间', dataIndex: 'collected_at', key: 'collected_at', width: 180 },
  ],
}

const activeFilters = computed(() => filterDefsMap[props.assetType] ?? [])
const searchPlaceholder = computed(() => searchPlaceholderMap[props.assetType])
const emptyDescription = computed(() => emptyTextMap[props.assetType])
const columns = computed(() => {
  const baseColumns = baseColumnsMap[props.assetType] ?? []
  if (!props.allowHostFilter) {
    return baseColumns
  }
  return [
    { title: '主机', dataIndex: 'host_id', key: 'host_display', width: 220, fixed: 'left' },
    ...baseColumns,
  ]
})

const buildQueryParams = () => {
  const params: Record<string, unknown> = {
    page: pagination.current,
    page_size: pagination.pageSize,
    search: searchText.value || undefined,
    host_id: props.selectedHostId || undefined,
    business_line: props.selectedBusinessLine || undefined,
  }

  for (const filter of activeFilters.value) {
    params[filter.key] = filterState[filter.key] || undefined
  }

  return params
}

const loadData = async () => {
  loading.value = true
  try {
    const route = tableRouteMap[props.assetType]
    const response = await apiClient.get<PaginatedResponse<any>>(route, { params: buildQueryParams() })
    tableData.value = response.items ?? []
    pagination.total = response.total ?? 0
  } catch (error) {
    console.error('加载资产列表失败:', error)
    tableData.value = []
  } finally {
    loading.value = false
  }
}

const resetLocalFilters = () => {
  searchText.value = ''
  Object.keys(filterState).forEach((key) => {
    filterState[key] = undefined
  })
}

const handleSearch = () => {
  pagination.current = 1
  loadData()
}

const handleFilterChange = () => {
  pagination.current = 1
  loadData()
}

const handleReset = () => {
  resetLocalFilters()
  if (props.allowHostFilter) {
    emit('update:selectedHostId', undefined)
  }
  pagination.current = 1
  loadData()
}

const handleHostChange = (value?: string) => {
  emit('update:selectedHostId', value || undefined)
}

const handleBusinessLineChange = (value?: string) => {
  emit('update:selectedBusinessLine', value || undefined)
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  loadData()
}

const handleExport = async () => {
  exportLoading.value = true
  try {
    const blob = await assetsApi.exportAssets({
      type: exportTypeMap[props.assetType],
      host_id: props.selectedHostId,
      business_line: props.selectedBusinessLine,
      format: 'csv',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `assets_${exportTypeMap[props.assetType]}_${new Date().toISOString().slice(0, 10)}.csv`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    message.success('导出成功')
  } catch (error) {
    console.error('导出资产失败:', error)
    message.error('导出失败')
  } finally {
    exportLoading.value = false
  }
}

const resolveHost = (hostId?: string) => {
  if (!hostId) return undefined
  return props.hostMap[hostId]
}

const shorten = (value?: string, max = 8) => {
  if (!value) return '-'
  if (value.length <= max) return value
  return `${value.slice(0, max)}...`
}

const formatHostTitle = (hostId?: string) => {
  const host = resolveHost(hostId)
  return host?.hostname || shorten(hostId, 12)
}

const formatHostMeta = (hostId?: string) => {
  const host = resolveHost(hostId)
  const parts = [host?.ipv4?.[0], shorten(hostId, 12)].filter(Boolean)
  return parts.join(' | ') || '-'
}

const formatBytes = (value?: number) => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) return '-'
  const bytes = Number(value)
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let current = bytes / 1024
  let unitIndex = 0
  while (current >= 1024 && unitIndex < units.length - 1) {
    current /= 1024
    unitIndex += 1
  }
  return `${current.toFixed(1)} ${units[unitIndex]}`
}

const formatPercent = (value?: number) => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) return '-'
  return `${Number(value).toFixed(1)}%`
}

const formatTime = (value?: string) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('zh-CN')
}

const statusColor = (value?: string) => {
  switch (value) {
    case 'running':
    case 'active':
    case 'LISTEN':
    case 'up':
    case 'Live':
      return 'green'
    case 'paused':
    case 'inactive':
    case 'Loading':
      return 'orange'
    case 'failed':
    case 'stopped':
    case 'exited':
    case 'down':
    case 'Unloading':
      return 'red'
    default:
      return 'default'
  }
}

watch(() => props.assetType, () => {
  resetLocalFilters()
  pagination.current = 1
  loadData()
})

watch(() => props.selectedHostId, () => {
  pagination.current = 1
  loadData()
})

watch(() => props.selectedBusinessLine, () => {
  pagination.current = 1
  loadData()
})

onMounted(() => {
  loadData()
})
</script>

<style scoped>
.asset-records-table {
  width: 100%;
}

.filter-bar {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 16px;
  padding: 12px 16px;
  background: var(--mxsec-fill-1);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  flex-wrap: wrap;
}

.host-cell {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.host-link {
  color: #165DFF;
  font-weight: 600;
  text-decoration: none;
}

.host-meta {
  color: var(--mxsec-text-3);
  font-size: 12px;
  margin-top: 2px;
}

.ellipsis-text {
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.empty-text {
  color: var(--mxsec-text-3);
}
</style>
