<template>
  <a-drawer
    :open="open"
    :width="640"
    :title="null"
    @close="$emit('update:open', false)"
    class="event-drawer"
  >
    <a-spin :spinning="loading">
      <template v-if="alert">
        <!-- 标题区域 -->
        <div class="drawer-header">
          <div class="title-row">
            <h3 class="alert-title">{{ alert.title }}</h3>
            <a-tag :color="getSeverityColor(alert.severity)">{{ getSeverityText(alert.severity) }}</a-tag>
            <a-tag :color="getStatusColor(alert.status)">{{ getStatusText(alert.status) }}</a-tag>
          </div>
          <p class="alert-desc" v-if="alert.description">{{ alert.description }}</p>
        </div>

        <a-divider />

        <!-- 基本信息 -->
        <h4>基本信息</h4>
        <a-descriptions bordered :column="2" size="small">
          <a-descriptions-item label="告警ID">{{ alert.id }}</a-descriptions-item>
          <a-descriptions-item label="规则ID">{{ alert.rule_id }}</a-descriptions-item>
          <a-descriptions-item label="类别">{{ alert.category }}</a-descriptions-item>
          <a-descriptions-item label="MITRE">
            {{ eventDetail?.mitre_id || '-' }}
          </a-descriptions-item>
          <a-descriptions-item label="主机">
            <a v-if="alert.host" @click="handleViewHost">
              {{ alert.host.hostname }} ({{ alert.host.ipv4?.[0] || '-' }})
            </a>
            <span v-else>{{ alert.host_id }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="严重级别">
            <a-tag :color="getSeverityColor(alert.severity)">{{ getSeverityText(alert.severity) }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="首次发现">{{ formatDateTime(alert.first_seen_at) }}</a-descriptions-item>
          <a-descriptions-item label="最后发现">{{ formatDateTime(alert.last_seen_at) }}</a-descriptions-item>
        </a-descriptions>

        <!-- 事件详情 -->
        <template v-if="eventDetail">
          <a-divider />
          <h4>事件详情</h4>

          <!-- 进程信息 -->
          <a-card v-if="eventDetail.exe" title="进程信息" size="small" class="detail-card">
            <a-descriptions bordered :column="2" size="small">
              <a-descriptions-item label="可执行文件">
                <code>{{ eventDetail.exe }}</code>
              </a-descriptions-item>
              <a-descriptions-item label="命令行">
                <code>{{ eventDetail.cmdline }}</code>
              </a-descriptions-item>
              <a-descriptions-item label="PID">{{ eventDetail.pid }}</a-descriptions-item>
              <a-descriptions-item label="PPID">{{ eventDetail.ppid }}</a-descriptions-item>
              <a-descriptions-item label="父进程">
                <code>{{ eventDetail.parent_exe }}</code>
              </a-descriptions-item>
              <a-descriptions-item label="UID">{{ eventDetail.uid }}</a-descriptions-item>
            </a-descriptions>
          </a-card>

          <!-- 网络信息 -->
          <a-card v-if="eventDetail.remote_addr" title="网络信息" size="small" class="detail-card">
            <a-descriptions bordered :column="2" size="small">
              <a-descriptions-item label="远程地址">{{ eventDetail.remote_addr }}</a-descriptions-item>
              <a-descriptions-item label="远程端口">{{ eventDetail.remote_port }}</a-descriptions-item>
              <a-descriptions-item label="本地地址">{{ eventDetail.local_addr }}</a-descriptions-item>
              <a-descriptions-item label="本地端口">{{ eventDetail.local_port }}</a-descriptions-item>
              <a-descriptions-item label="协议">
                <a-tag>{{ eventDetail.protocol }}</a-tag>
              </a-descriptions-item>
            </a-descriptions>
          </a-card>

          <!-- 文件信息 -->
          <a-card v-if="eventDetail.file_path" title="文件信息" size="small" class="detail-card">
            <a-descriptions bordered :column="1" size="small">
              <a-descriptions-item label="文件路径">
                <code>{{ eventDetail.file_path }}</code>
              </a-descriptions-item>
            </a-descriptions>
          </a-card>
        </template>

        <!-- 原始数据 -->
        <a-divider />
        <a-collapse ghost>
          <a-collapse-panel key="raw" header="原始数据">
            <pre class="raw-json">{{ formatRawData(alert.actual) }}</pre>
          </a-collapse-panel>
        </a-collapse>

        <!-- 操作按钮 -->
        <div class="drawer-actions" v-if="alert.status === 'active'">
          <a-divider />
          <a-space>
            <a-button type="primary" @click="handleResolve">
              <CheckOutlined /> 解决告警
            </a-button>
            <a-button danger @click="handleIgnore">
              <CloseOutlined /> 忽略告警
            </a-button>
          </a-space>
        </div>
      </template>
      <a-empty v-else-if="!loading" description="告警不存在" />
    </a-spin>

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
  </a-drawer>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { CheckOutlined, CloseOutlined } from '@ant-design/icons-vue'
import { alertsApi, type Alert } from '@/api/alerts'
import { formatDateTime } from '@/utils/date'

const props = defineProps<{
  open: boolean
  alertId: number | null
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
  refresh: []
}>()

const router = useRouter()
const loading = ref(false)
const alert = ref<Alert | null>(null)
const resolveModalVisible = ref(false)
const ignoreModalVisible = ref(false)
const resolveReason = ref('')

const eventDetail = computed(() => {
  if (!alert.value?.actual) return null
  try {
    return JSON.parse(alert.value.actual)
  } catch {
    return null
  }
})

const loadAlert = async (id: number) => {
  loading.value = true
  try {
    alert.value = await alertsApi.get(id)
  } catch (error: any) {
    console.error('加载告警详情失败:', error)
    message.error(error?.message || '加载告警详情失败')
  } finally {
    loading.value = false
  }
}

watch(() => props.alertId, (newId) => {
  if (newId && props.open) {
    loadAlert(newId)
  }
})

watch(() => props.open, (newOpen) => {
  if (newOpen && props.alertId) {
    loadAlert(props.alertId)
  }
  if (!newOpen) {
    alert.value = null
  }
})

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

const formatRawData = (data: string | undefined) => {
  if (!data) return '-'
  try {
    return JSON.stringify(JSON.parse(data), null, 2)
  } catch {
    return data
  }
}

const handleViewHost = () => {
  if (alert.value?.host_id) {
    router.push(`/hosts/${alert.value.host_id}`)
  }
}

const handleResolve = () => {
  resolveReason.value = ''
  resolveModalVisible.value = true
}

const handleResolveConfirm = async () => {
  if (!alert.value) return
  try {
    await alertsApi.resolve(alert.value.id, resolveReason.value || undefined)
    message.success('告警已解决')
    resolveModalVisible.value = false
    emit('refresh')
    emit('update:open', false)
  } catch (error: any) {
    message.error(error?.message || '解决告警失败')
  }
}

const handleIgnore = () => {
  ignoreModalVisible.value = true
}

const handleIgnoreConfirm = async () => {
  if (!alert.value) return
  try {
    await alertsApi.ignore(alert.value.id)
    message.success('告警已忽略')
    ignoreModalVisible.value = false
    emit('refresh')
    emit('update:open', false)
  } catch (error: any) {
    message.error(error?.message || '忽略告警失败')
  }
}
</script>

<style scoped lang="less">
.drawer-header {
  .title-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .alert-title {
    font-size: 18px;
    font-weight: 600;
    margin: 0;
    flex: 1;
    min-width: 200px;
  }
  .alert-desc {
    color: #666;
    margin: 8px 0 0;
    font-size: 14px;
  }
}

h4 {
  font-size: 15px;
  font-weight: 600;
  margin: 0 0 12px;
  color: #262626;
}

.detail-card {
  margin-top: 12px;
}

.raw-json {
  background: #f5f5f5;
  padding: 12px;
  border-radius: 6px;
  font-size: 12px;
  max-height: 400px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
}

.drawer-actions {
  padding-bottom: 16px;
}
</style>
