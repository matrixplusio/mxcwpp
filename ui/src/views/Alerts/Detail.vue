<template>
  <div class="alert-detail-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <a-button type="text" @click="handleBack">
        <ArrowLeftOutlined /> 返回告警列表
      </a-button>
    </div>

    <a-spin :spinning="loading">
      <template v-if="alert">
        <!-- 告警基本信息卡片 -->
        <a-card :bordered="false" class="info-card">
          <div class="alert-header">
            <div class="alert-title-row">
              <a-tag :color="getSeverityColor(alert.severity)" class="severity-tag">
                {{ getSeverityText(alert.severity) }}
              </a-tag>
              <h2 class="alert-title">{{ alert.title }}</h2>
              <a-tag :color="getStatusColor(alert.status)">
                {{ getStatusText(alert.status) }}
              </a-tag>
            </div>
            <p class="alert-description" v-if="alert.description">{{ alert.description }}</p>
          </div>

          <a-divider />

          <a-descriptions :column="2" :label-style="{ width: '120px' }">
            <a-descriptions-item label="告警ID">{{ alert.id }}</a-descriptions-item>
            <a-descriptions-item label="规则ID">{{ alert.rule_id }}</a-descriptions-item>
            <a-descriptions-item label="类别">{{ alert.category }}</a-descriptions-item>
            <a-descriptions-item label="关联主机">
              <a @click="handleViewHost" v-if="alert.host">
                {{ alert.host.hostname }} ({{ alert.host_id }})
              </a>
              <span v-else>{{ alert.host_id }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="首次发现">{{ formatDateTime(alert.first_seen_at) }}</a-descriptions-item>
            <a-descriptions-item label="最后发现">{{ formatDateTime(alert.last_seen_at) }}</a-descriptions-item>
            <a-descriptions-item label="策略ID">{{ alert.policy_id }}</a-descriptions-item>
            <a-descriptions-item label="结果ID">{{ alert.result_id }}</a-descriptions-item>
          </a-descriptions>
        </a-card>

        <!-- 检查结果卡片 -->
        <a-card title="检查结果" :bordered="false" class="info-card">
          <a-descriptions :column="1">
            <a-descriptions-item label="期望值">
              <a-typography-text code v-if="alert.expected">{{ alert.expected }}</a-typography-text>
              <span v-else class="text-muted">-</span>
            </a-descriptions-item>
            <a-descriptions-item label="实际值">
              <a-typography-text code type="danger" v-if="alert.actual">{{ alert.actual }}</a-typography-text>
              <span v-else class="text-muted">-</span>
            </a-descriptions-item>
          </a-descriptions>
        </a-card>

        <!-- 事件详情卡片（仅 CEL 规则检测告警） -->
        <template v-if="isCELAlert && eventDetail">
          <a-card title="事件详情" :bordered="false" class="info-card">
            <a-descriptions bordered :column="2">
              <a-descriptions-item label="事件类型">
                <a-tag color="blue">{{ eventDetail.event_type }}</a-tag>
              </a-descriptions-item>
              <a-descriptions-item label="时间">
                {{ formatDateTime(eventDetail.timestamp) }}
              </a-descriptions-item>
            </a-descriptions>

            <!-- 进程信息 -->
            <a-card v-if="eventDetail.exe" title="进程信息" size="small" style="margin-top: 12px">
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
            <a-card v-if="eventDetail.remote_addr" title="网络信息" size="small" style="margin-top: 12px">
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
            <a-card v-if="eventDetail.file_path" title="文件信息" size="small" style="margin-top: 12px">
              <a-descriptions bordered :column="1" size="small">
                <a-descriptions-item label="文件路径">
                  <code>{{ eventDetail.file_path }}</code>
                </a-descriptions-item>
              </a-descriptions>
            </a-card>

            <!-- 主机信息 -->
            <a-card title="触发主机" size="small" style="margin-top: 12px">
              <a-descriptions bordered :column="2" size="small">
                <a-descriptions-item label="主机名">{{ eventDetail.hostname }}</a-descriptions-item>
                <a-descriptions-item label="Agent ID">
                  <span class="agent-id">{{ eventDetail.agent_id }}</span>
                </a-descriptions-item>
              </a-descriptions>
            </a-card>
          </a-card>
        </template>

        <!-- FIM 文件完整性变更详情卡片（source=fim 时） -->
        <template v-if="isFIMAlert && fimEventDetail">
          <a-card title="文件完整性变更详情" :bordered="false" class="info-card">
            <a-descriptions bordered :column="2">
              <a-descriptions-item label="文件路径" :span="2">
                <code>{{ fimEventDetail.file_path }}</code>
              </a-descriptions-item>
              <a-descriptions-item label="变更类型">
                <a-tag :color="fimChangeColor(fimEventDetail.change_type)">
                  {{ fimChangeText(fimEventDetail.change_type) }}
                </a-tag>
              </a-descriptions-item>
              <a-descriptions-item label="严重级别">
                <a-tag>{{ fimEventDetail.severity }}</a-tag>
              </a-descriptions-item>
              <a-descriptions-item label="变更检测时间">
                {{ formatDateTime(fimEventDetail.detected_at) }}
              </a-descriptions-item>
              <a-descriptions-item label="事件 ID">
                <code>{{ fimEventDetail.event_id }}</code>
              </a-descriptions-item>
              <a-descriptions-item label="任务 ID" :span="2">
                <code class="text-muted">{{ fimEventDetail.task_id }}</code>
              </a-descriptions-item>
              <a-descriptions-item label="主机名" :span="2">
                {{ fimEventDetail.hostname }}
              </a-descriptions-item>
            </a-descriptions>

            <!-- change_detail JSON 解析对比 -->
            <a-card
              v-if="fimEventDetail.change_detail && Object.keys(fimEventDetail.change_detail).length"
              title="变更明细"
              size="small"
              style="margin-top: 12px"
            >
              <a-descriptions bordered :column="1" size="small">
                <a-descriptions-item label="Hash 变更">
                  <a-tag :color="fimEventDetail.change_detail.hash_changed ? 'red' : 'default'">
                    {{ fimEventDetail.change_detail.hash_changed ? '是' : '否' }}
                  </a-tag>
                </a-descriptions-item>
                <a-descriptions-item label="权限变更">
                  <a-tag :color="fimEventDetail.change_detail.permission_changed ? 'orange' : 'default'">
                    {{ fimEventDetail.change_detail.permission_changed ? '是' : '否' }}
                  </a-tag>
                </a-descriptions-item>
                <a-descriptions-item label="属主变更">
                  <a-tag :color="fimEventDetail.change_detail.owner_changed ? 'orange' : 'default'">
                    {{ fimEventDetail.change_detail.owner_changed ? '是' : '否' }}
                  </a-tag>
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="fimEventDetail.change_detail.old_hash || fimEventDetail.change_detail.new_hash"
                  label="Hash 对比"
                >
                  <div>旧: <code>{{ fimEventDetail.change_detail.old_hash || '-' }}</code></div>
                  <div>新: <code>{{ fimEventDetail.change_detail.new_hash || '-' }}</code></div>
                </a-descriptions-item>
              </a-descriptions>
            </a-card>

            <!-- 事件状态 -->
            <a-alert
              v-if="fimEventDetail.status === 'escalated'"
              type="warning"
              show-icon
              :message="`事件超时未确认，已自动升级为告警（${fimEventDetail.status}）`"
              :description="alert?.description"
              style="margin-top: 12px"
            />
            <a-alert
              v-else-if="fimEventDetail.status === 'confirmed'"
              type="success"
              show-icon
              :message="`已确认：${fimEventDetail.confirmed_by}`"
              :description="`原因：${fimEventDetail.confirm_reason || '无'} (${formatDateTime(fimEventDetail.confirmed_at)})`"
              style="margin-top: 12px"
            />
          </a-card>
        </template>
        <a-alert
          v-else-if="isFIMAlert && fimDetailError"
          type="error"
          show-icon
          :message="`无法加载 FIM 事件详情：${fimDetailError}`"
          style="margin-bottom: 16px"
        />

        <!-- 修复建议卡片 -->
        <a-card title="修复建议" :bordered="false" class="info-card" v-if="alert.fix_suggestion">
          <div class="fix-suggestion">
            <pre>{{ alert.fix_suggestion }}</pre>
          </div>
        </a-card>

        <!-- 解决信息卡片（如果已解决） -->
        <a-card title="处理信息" :bordered="false" class="info-card" v-if="alert.status !== 'active'">
          <a-descriptions :column="2">
            <a-descriptions-item label="处理状态">
              <a-tag :color="getStatusColor(alert.status)">{{ getStatusText(alert.status) }}</a-tag>
            </a-descriptions-item>
            <a-descriptions-item label="处理时间" v-if="alert.resolved_at">
              {{ formatDateTime(alert.resolved_at) }}
            </a-descriptions-item>
            <a-descriptions-item label="处理人" v-if="alert.resolved_by">
              {{ alert.resolved_by }}
            </a-descriptions-item>
            <a-descriptions-item label="处理原因" v-if="alert.resolve_reason" :span="2">
              {{ alert.resolve_reason }}
            </a-descriptions-item>
          </a-descriptions>
        </a-card>

        <!-- 操作按钮 -->
        <div class="action-bar" v-if="alert.status === 'active'">
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
      <p>确定要忽略此告警吗？忽略后告警将移至历史记录。</p>
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
import { ref, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { message } from 'ant-design-vue'
import {
  ArrowLeftOutlined,
  CheckOutlined,
  CloseOutlined,
} from '@ant-design/icons-vue'
import { alertsApi, type Alert } from '@/api/alerts'
import apiClient from '@/api/client'
import { formatDateTime } from '@/utils/date'

const router = useRouter()
const route = useRoute()

const loading = ref(false)
const alert = ref<Alert | null>(null)
const resolveModalVisible = ref(false)
const ignoreModalVisible = ref(false)
const resolveReason = ref('')

const isCELAlert = computed(() => alert.value?.rule_id?.startsWith('cel-'))

const eventDetail = computed(() => {
  if (!isCELAlert.value || !alert.value?.actual) return null
  try {
    return JSON.parse(alert.value.actual)
  } catch {
    return null
  }
})

// FIM 告警识别 + 详情加载（result_id 形如 fim-escalation-evt-000004 → event_id evt-000004）
const isFIMAlert = computed(() => alert.value?.source === 'fim')
const fimEventDetail = ref<any>(null)
const fimDetailError = ref<string>('')

const loadFIMEventDetail = async () => {
  fimEventDetail.value = null
  fimDetailError.value = ''
  if (!alert.value || alert.value.source !== 'fim') return
  // result_id 格式：fim-escalation-<event_id> 或直接 event_id
  const rid = alert.value.result_id || ''
  let eventId = rid
  const m = rid.match(/^fim-(?:escalation-)?(.+)$/)
  if (m) eventId = m[1]
  if (!eventId) return
  try {
    const res = await apiClient.get<any>(`/fim/events/${eventId}`)
    fimEventDetail.value = res
  } catch (e: any) {
    fimDetailError.value = e?.message || 'FIM 事件详情查询失败'
  }
}

const fimChangeColor = (t: string) => ({
  added: 'green', removed: 'red', changed: 'orange',
  permission_changed: 'gold', ownership_changed: 'gold',
} as Record<string, string>)[t] || 'default'

const fimChangeText = (t: string) => ({
  added: '新增', removed: '删除', changed: '内容变更',
  permission_changed: '权限变更', ownership_changed: '属主变更',
} as Record<string, string>)[t] || t

const loadAlert = async () => {
  const alertId = Number(route.params.alertId)
  if (!alertId || isNaN(alertId)) {
    message.error('无效的告警ID')
    return
  }

  loading.value = true
  try {
    alert.value = await alertsApi.get(alertId)
    // FIM 告警额外加载关联的 fim_event 详情
    if (isFIMAlert.value) {
      loadFIMEventDetail()
    }
  } catch (error) {
    console.error('加载告警详情失败:', error)
  } finally {
    loading.value = false
  }
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

const handleBack = () => {
  router.push('/alerts')
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
    loadAlert()
  } catch (error) {
    console.error('解决告警失败:', error)
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
    loadAlert()
  } catch (error) {
    console.error('忽略告警失败:', error)
  }
}

onMounted(() => {
  loadAlert()
})
</script>

<style scoped lang="less">
.alert-detail-page {
  padding: 24px;
}

.page-header {
  margin-bottom: 16px;
}

.info-card {
  margin-bottom: 16px;
}

.alert-header {
  .alert-title-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }

  .severity-tag {
    font-size: 14px;
    padding: 4px 12px;
  }

  .alert-title {
    font-size: 20px;
    font-weight: 600;
    margin: 0;
    flex: 1;
  }

  .alert-description {
    color: #666;
    margin: 0;
    font-size: 14px;
  }
}

.fix-suggestion {
  pre {
    background: var(--mxsec-fill-2);
    padding: 16px;
    border-radius: 6px;
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 13px;
  }
}

.action-bar {
  padding: 16px 0;
  border-top: 1px solid var(--mxsec-border);
  margin-top: 16px;
}

.text-muted {
  color: #999;
}

.agent-id {
  font-family: monospace;
  font-size: 12px;
  color: #666;
}
</style>
