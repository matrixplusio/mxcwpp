<template>
  <div>
    <!-- 搜索和过滤 -->
    <div class="toolbar">
      <a-input
        v-model:value="localFilters.keyword"
        placeholder="搜索告警标题或描述"
        allow-clear
        @press-enter="handleSearch"
        style="width: 300px"
      >
        <template #prefix>
          <SearchOutlined />
        </template>
      </a-input>
      <a-select
        v-model:value="localFilters.severity"
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
        v-model:value="localFilters.alert_type"
        placeholder="告警来源"
        allow-clear
        style="width: 150px"
        @change="handleAlertTypeChange"
      >
        <a-select-option value="baseline">基线安全</a-select-option>
        <a-select-option value="detection">检测告警</a-select-option>
        <a-select-option value="agent">Agent 状态</a-select-option>
        <a-select-option value="vulnerability">漏洞管理</a-select-option>
        <a-select-option value="fim">文件完整性</a-select-option>
        <a-select-option value="virus">病毒查杀</a-select-option>
        <a-select-option value="kube">容器安全</a-select-option>
      </a-select>
      <a-select
        v-if="localFilters.alert_type && localFilters.alert_type !== 'agent'"
        v-model:value="localFilters.category"
        placeholder="类别"
        allow-clear
        style="width: 150px"
        @change="handleSearch"
      >
        <template v-if="localFilters.alert_type === 'runtime'">
          <a-select-option value="reverse_shell">反弹 Shell</a-select-option>
          <a-select-option value="cryptomining">挖矿检测</a-select-option>
          <a-select-option value="c2_communication">C2 通信</a-select-option>
          <a-select-option value="credential_access">凭证窃取</a-select-option>
          <a-select-option value="privilege_escalation">权限提升</a-select-option>
          <a-select-option value="persistence">持久化</a-select-option>
          <a-select-option value="defense_evasion">防御规避</a-select-option>
          <a-select-option value="execution">命令执行</a-select-option>
          <a-select-option value="lateral_movement">横向移动</a-select-option>
          <a-select-option value="webshell">Webshell</a-select-option>
          <a-select-option value="exfiltration">数据外泄</a-select-option>
          <a-select-option value="network_scan">网络探测</a-select-option>
          <a-select-option value="resource_hijacking">资源劫持</a-select-option>
          <a-select-option value="malware">恶意软件</a-select-option>
          <a-select-option value="ransomware">勒索软件</a-select-option>
        </template>
        <template v-else-if="localFilters.alert_type === 'baseline'">
          <a-select-option value="ssh">SSH</a-select-option>
          <a-select-option value="password">密码策略</a-select-option>
          <a-select-option value="file_permission">文件权限</a-select-option>
          <a-select-option value="sysctl">内核参数</a-select-option>
          <a-select-option value="service">服务状态</a-select-option>
        </template>
        <template v-else-if="localFilters.alert_type === 'vulnerability'">
          <a-select-option value="os_package">操作系统包</a-select-option>
          <a-select-option value="middleware">中间件</a-select-option>
          <a-select-option value="library">依赖库</a-select-option>
          <a-select-option value="kernel">内核</a-select-option>
        </template>
        <template v-else-if="localFilters.alert_type === 'fim'">
          <a-select-option value="file_created">文件创建</a-select-option>
          <a-select-option value="file_modified">文件修改</a-select-option>
          <a-select-option value="file_deleted">文件删除</a-select-option>
          <a-select-option value="permission_changed">权限变更</a-select-option>
          <a-select-option value="ownership_changed">属主变更</a-select-option>
        </template>
        <template v-else-if="localFilters.alert_type === 'virus'">
          <a-select-option value="trojan">木马</a-select-option>
          <a-select-option value="worm">蠕虫</a-select-option>
          <a-select-option value="ransomware">勒索软件</a-select-option>
          <a-select-option value="backdoor">后门</a-select-option>
          <a-select-option value="miner">挖矿程序</a-select-option>
          <a-select-option value="rootkit">Rootkit</a-select-option>
          <a-select-option value="pua">潜在有害</a-select-option>
        </template>
        <template v-else-if="localFilters.alert_type === 'kube'">
          <a-select-option value="container_escape">容器逃逸</a-select-option>
          <a-select-option value="image_vuln">镜像漏洞</a-select-option>
          <a-select-option value="rbac_misconfig">RBAC 配置</a-select-option>
          <a-select-option value="privileged_container">特权容器</a-select-option>
          <a-select-option value="secret_exposure">密钥泄露</a-select-option>
          <a-select-option value="network_policy">网络策略</a-select-option>
        </template>
      </a-select>
      <a-select
        v-model:value="localFilters.runtime_type"
        placeholder="运行环境"
        allow-clear
        style="width: 130px"
        @change="handleSearch"
      >
        <a-select-option value="vm">物理机/VM</a-select-option>
        <a-select-option value="docker">Docker</a-select-option>
        <a-select-option value="k8s">K8s</a-select-option>
      </a-select>
      <a-button @click="handleSearch">搜索</a-button>
      <a-button @click="handleRefresh">
        <template #icon>
          <ReloadOutlined />
        </template>
        刷新
      </a-button>
    </div>

    <!-- 批量操作栏 -->
    <div v-if="selectedRowKeys.length > 0" class="batch-actions">
      <span class="selection-info">
        已选择 <strong>{{ selectedRowKeys.length }}</strong> 项
      </span>
      <a-space>
        <a-button v-if="status === 'active'" type="primary" @click="handleBatchResolve" :loading="batchLoading">
          <template #icon><CheckOutlined /></template>
          批量解决
        </a-button>
        <a-button v-if="status === 'active'" @click="handleBatchIgnore" :loading="batchLoading">
          <template #icon><EyeInvisibleOutlined /></template>
          批量忽略
        </a-button>
        <a-button danger @click="handleBatchDelete" :loading="batchLoading">
          <template #icon><DeleteOutlined /></template>
          批量删除
        </a-button>
        <a-button @click="clearSelection">取消选择</a-button>
      </a-space>
    </div>

    <!-- 告警表格 -->
    <a-table
      :columns="columns"
      :data-source="alerts"
      :loading="loading"
      :pagination="pagination"
      :row-selection="rowSelection"
      row-key="id"
      @change="handleTableChange"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'source'">
          <a-tag :color="getSourceColor(record.source)">
            {{ getSourceText(record.source) }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'severity'">
          <a-tag :color="getSeverityColor(record.severity)">
            {{ getSeverityText(record.severity) }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'status'">
          <a-tag :color="getStatusColor(record.status)">
            {{ getStatusText(record.status) }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'host'">
          <a @click="handleViewHost(record.host_id)">
            {{ record.host?.hostname || record.host_id }}
          </a>
          <div v-if="record.host?.ipv4?.length" style="color: #86909C; font-size: 12px;">
            {{ record.host.ipv4[0] }}
          </div>
        </template>
        <template v-else-if="column.key === 'first_seen_at'">
          {{ formatDateTime(record.first_seen_at) }}
        </template>
        <template v-else-if="column.key === 'last_seen_at'">
          {{ formatDateTime(record.last_seen_at) }}
        </template>
        <template v-else-if="column.key === 'actions'">
          <a-space>
            <a-button type="link" size="small" @click="handleViewDetail(record)">
              查看详情
            </a-button>
            <template v-if="status === 'active'">
              <a-button type="link" size="small" @click="handleResolveClick(record)">
                解决
              </a-button>
              <a-button type="link" size="small" danger @click="handleIgnoreClick(record)">
                忽略
              </a-button>
            </template>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 解决告警对话框 -->
    <a-modal
      v-model:open="resolveModalVisible"
      title="解决告警"
      @ok="handleResolveConfirm"
      @cancel="resolveModalVisible = false"
    >
      <a-form-item label="解决原因">
        <a-textarea
          v-model:value="resolveReason"
          placeholder="请输入解决原因（可选）"
          :rows="4"
        />
      </a-form-item>
    </a-modal>

    <!-- 忽略确认对话框 -->
    <a-modal
      v-model:open="ignoreModalVisible"
      title="确认忽略"
      @ok="handleIgnoreConfirm"
      @cancel="ignoreModalVisible = false"
      ok-text="确认忽略"
      :ok-button-props="{ danger: true }"
    >
      <p>确定要忽略告警「{{ ignoreAlert?.title }}」吗？</p>
      <p style="color: #86909C; font-size: 13px;">忽略后告警将移至历史记录。</p>
      <a-alert
        type="warning"
        message="忽略告警不会解决实际的安全问题，建议优先解决告警。"
        show-icon
        style="margin-top: 12px"
      />
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { useRouter } from 'vue-router'
import { message, Modal } from 'ant-design-vue'
import {
  SearchOutlined,
  ReloadOutlined,
  CheckOutlined,
  EyeInvisibleOutlined,
  DeleteOutlined,
} from '@ant-design/icons-vue'
import { formatDateTime } from '@/utils/date'
import { alertsApi, type Alert } from '@/api/alerts'
import type { TableProps } from 'ant-design-vue'

const props = defineProps<{
  alerts: Alert[]
  loading: boolean
  pagination: any
  filters: any
  status: 'active' | 'history'
}>()

const emit = defineEmits<{
  change: [filters: any]
  resolve: [alert: Alert, reason?: string]
  ignore: [alert: Alert]
  refresh: []
}>()

const router = useRouter()
const localFilters = ref({ ...props.filters })
const resolveModalVisible = ref(false)
const ignoreModalVisible = ref(false)
const currentAlert = ref<Alert | null>(null)
const ignoreAlert = ref<Alert | null>(null)
const resolveReason = ref('')

// 批量选择相关
const selectedRowKeys = ref<number[]>([])
const batchLoading = ref(false)

// 行选择配置
const rowSelection = computed(() => ({
  selectedRowKeys: selectedRowKeys.value,
  onChange: (keys: number[]) => {
    selectedRowKeys.value = keys
  },
}))

// 清除选择
const clearSelection = () => {
  selectedRowKeys.value = []
}

// 批量解决
const handleBatchResolve = () => {
  Modal.confirm({
    title: '批量解决告警',
    content: `确定要解决选中的 ${selectedRowKeys.value.length} 个告警吗？`,
    okText: '确认解决',
    cancelText: '取消',
    async onOk() {
      batchLoading.value = true
      try {
        await alertsApi.batchResolve(selectedRowKeys.value)
        message.success(`成功解决 ${selectedRowKeys.value.length} 个告警`)
        clearSelection()
        emit('refresh')
      } catch (error) {
        console.error('批量解决告警失败:', error)
      } finally {
        batchLoading.value = false
      }
    },
  })
}

// 批量忽略
const handleBatchIgnore = () => {
  Modal.confirm({
    title: '批量忽略告警',
    content: `确定要忽略选中的 ${selectedRowKeys.value.length} 个告警吗？`,
    okText: '确认忽略',
    okButtonProps: { danger: true },
    cancelText: '取消',
    async onOk() {
      batchLoading.value = true
      try {
        await alertsApi.batchIgnore(selectedRowKeys.value)
        message.success(`成功忽略 ${selectedRowKeys.value.length} 个告警`)
        clearSelection()
        emit('refresh')
      } catch (error) {
        console.error('批量忽略告警失败:', error)
      } finally {
        batchLoading.value = false
      }
    },
  })
}

// 批量删除
const handleBatchDelete = () => {
  Modal.confirm({
    title: '批量删除告警',
    content: `确定要删除选中的 ${selectedRowKeys.value.length} 个告警吗？此操作不可恢复！`,
    okText: '确认删除',
    okButtonProps: { danger: true },
    cancelText: '取消',
    async onOk() {
      batchLoading.value = true
      try {
        await alertsApi.batchDelete(selectedRowKeys.value)
        message.success(`成功删除 ${selectedRowKeys.value.length} 个告警`)
        clearSelection()
        emit('refresh')
      } catch (error) {
        console.error('批量删除告警失败:', error)
      } finally {
        batchLoading.value = false
      }
    },
  })
}

watch(
  () => props.filters,
  (newFilters) => {
    localFilters.value = { ...newFilters }
  },
  { deep: true }
)

const columns = [
  {
    title: '告警标题',
    dataIndex: 'title',
    key: 'title',
    width: 250,
    ellipsis: true,
  },
  {
    title: '告警来源',
    key: 'source',
    width: 110,
  },
  {
    title: '严重级别',
    key: 'severity',
    width: 100,
  },
  {
    title: '类别',
    dataIndex: 'category',
    key: 'category',
    width: 120,
  },
  {
    title: '主机',
    key: 'host',
    width: 150,
  },
  {
    title: '首次发现',
    key: 'first_seen_at',
    width: 180,
  },
  {
    title: '最后发现',
    key: 'last_seen_at',
    width: 180,
  },
  {
    title: '状态',
    key: 'status',
    width: 100,
  },
  {
    title: '操作',
    key: 'actions',
    width: 200,
    fixed: 'right',
  },
]

const getSourceColor = (source: string) => {
  const colors: Record<string, string> = {
    baseline: 'blue',
    runtime: 'red',
    agent: 'orange',
    vulnerability: 'volcano',
    fim: 'purple',
    virus: 'magenta',
    kube: 'cyan',
  }
  return colors[source] || 'default'
}

const getSourceText = (source: string) => {
  const texts: Record<string, string> = {
    baseline: '基线安全',
    detection: '检测告警',
    agent: 'Agent 状态',
    vulnerability: '漏洞管理',
    fim: '文件完整性',
    virus: '病毒查杀',
    kube: '容器安全',
  }
  return texts[source] || source || '未知'
}

const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'blue',
  }
  return colors[severity] || 'default'
}

const getSeverityText = (severity: string) => {
  const texts: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  }
  return texts[severity] || severity
}

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    active: 'red',
    resolved: 'green',
    ignored: 'default',
  }
  return colors[status] || 'default'
}

const getStatusText = (status: string) => {
  const texts: Record<string, string> = {
    active: '活跃',
    resolved: '已解决',
    ignored: '已忽略',
  }
  return texts[status] || status
}

const handleAlertTypeChange = () => {
  localFilters.value.category = undefined
  handleSearch()
}

const handleSearch = () => {
  emit('change', localFilters.value)
}

const handleRefresh = () => {
  emit('refresh')
}

const handleTableChange: TableProps['onChange'] = (pag, _filters, _sorter) => {
  if (pag) {
    emit('change', { ...localFilters.value, page: pag.current, pageSize: pag.pageSize })
  }
}

const handleViewHost = (hostId: string) => {
  router.push(`/hosts/${hostId}`)
}

const handleViewDetail = (alert: Alert) => {
  router.push(`/alerts/${alert.id}`)
}

const handleResolveClick = (alert: Alert) => {
  currentAlert.value = alert
  resolveReason.value = ''
  resolveModalVisible.value = true
}

const handleResolveConfirm = () => {
  if (currentAlert.value) {
    emit('resolve', currentAlert.value, resolveReason.value || undefined)
    resolveModalVisible.value = false
    currentAlert.value = null
    resolveReason.value = ''
  }
}

const handleIgnoreClick = (alert: Alert) => {
  ignoreAlert.value = alert
  ignoreModalVisible.value = true
}

const handleIgnoreConfirm = () => {
  if (ignoreAlert.value) {
    emit('ignore', ignoreAlert.value)
    ignoreModalVisible.value = false
    ignoreAlert.value = null
  }
}
</script>

<style scoped lang="less">
.toolbar {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  align-items: center;
}

.batch-actions {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px 16px;
  background: var(--mxsec-primary-bg);
  border: 1px solid #91d5ff;
  border-radius: 4px;
  margin-bottom: 16px;
}

.selection-info {
  color: var(--mxsec-primary);
  font-size: 14px;
  
  strong {
    font-weight: 600;
  }
}
</style>
