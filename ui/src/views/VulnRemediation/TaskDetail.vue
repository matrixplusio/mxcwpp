<template>
  <div class="task-detail-page">
    <div class="page-header">
      <a-button type="link" @click="router.back()" style="padding: 0; margin-right: 8px">
        <template #icon><ArrowLeftOutlined /></template>
        返回
      </a-button>
      <h2>修复任务 #{{ task?.id }}</h2>
      <a-tag v-if="task" :color="taskStatusColor(task.status)" :bordered="false" style="margin-left: 12px">
        {{ taskStatusText(task.status) }}
      </a-tag>
    </div>

    <a-spin :spinning="loading">
      <template v-if="task">
        <!-- 任务信息 -->
        <div class="detail-card">
          <h4>任务信息</h4>
          <a-descriptions :column="2" bordered size="small">
            <a-descriptions-item label="任务 ID">#{{ task.id }}</a-descriptions-item>
            <a-descriptions-item label="漏洞编号">
              <RouterLink :to="`/vuln-list/${task.vulnId}`">{{ task.cveId }}</RouterLink>
            </a-descriptions-item>
            <a-descriptions-item label="组件">{{ task.component }}</a-descriptions-item>
            <a-descriptions-item label="修复版本">{{ task.fixedVersion || '最新版本' }}</a-descriptions-item>
            <a-descriptions-item label="创建者">{{ task.createdBy || '-' }}</a-descriptions-item>
            <a-descriptions-item label="创建时间">{{ task.createdAt }}</a-descriptions-item>
          </a-descriptions>
        </div>

        <!-- 任务状态追踪 -->
        <div class="detail-card" style="margin-top: 16px">
          <h4>状态追踪</h4>
          <div class="steps-wrapper">
            <a-steps :current="currentStep" :status="stepsStatus" size="small">
              <a-step title="创建任务">
                <template #description>
                  <div class="step-desc">
                    <div>{{ task.createdBy || '-' }}</div>
                    <div>{{ task.createdAt }}</div>
                  </div>
                </template>
              </a-step>
              <a-step title="确认执行">
                <template #description>
                  <div v-if="task.confirmedAt" class="step-desc">
                    <div>{{ task.confirmedBy || '-' }}</div>
                    <div>{{ task.confirmedAt }}</div>
                  </div>
                  <div v-else-if="task.status === 'pending'" class="step-desc">
                    <div style="color: #FF7D00">等待管理员确认</div>
                  </div>
                </template>
              </a-step>
              <a-step title="Agent 接收">
                <template #description>
                  <div v-if="task.startedAt" class="step-desc">
                    <div>{{ task.hostname }}</div>
                    <div>{{ task.startedAt }}</div>
                  </div>
                  <div v-else-if="task.status === 'confirmed'" class="step-desc">
                    <div style="color: #165DFF">等待 Agent 拉取任务</div>
                  </div>
                </template>
              </a-step>
              <a-step :title="finalStepTitle">
                <template #description>
                  <div v-if="task.finishedAt" class="step-desc">
                    <div v-if="task.exitCode != null">
                      退出码:
                      <a-tag :color="task.exitCode === 0 ? 'green' : 'red'" :bordered="false" style="margin-left: 4px">
                        {{ task.exitCode }}
                      </a-tag>
                    </div>
                    <div>{{ task.finishedAt }}</div>
                  </div>
                  <div v-else-if="task.status === 'running'" class="step-desc">
                    <div style="color: #722ED1">正在执行修复命令...</div>
                  </div>
                </template>
              </a-step>
            </a-steps>
          </div>

          <template v-if="task.status === 'cancelled'">
            <a-alert type="warning" message="任务已取消" show-icon style="margin-top: 16px" />
          </template>
          <template v-if="task.status === 'failed' && task.execOutput?.includes('任务超时')">
            <a-alert type="error" :message="task.execOutput" show-icon style="margin-top: 16px" />
          </template>
        </div>

        <!-- 执行详情 -->
        <div class="detail-card" style="margin-top: 16px">
          <h4>执行详情</h4>
          <a-descriptions :column="2" bordered size="small">
            <a-descriptions-item label="目标主机">
              <RouterLink :to="`/hosts/${task.hostId}`">{{ task.hostname }}</RouterLink>
              <span style="color: #86909C; margin-left: 8px">{{ task.ip }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="当前状态">
              <a-tag :color="taskStatusColor(task.status)" :bordered="false">
                {{ taskStatusText(task.status) }}
              </a-tag>
            </a-descriptions-item>
          </a-descriptions>

          <!-- 修复命令 -->
          <div class="command-section">
            <div class="command-header">
              <span class="command-label">修复命令</span>
              <a-button type="link" size="small" @click="copyCommand(task.command)">复制</a-button>
            </div>
            <div class="command-block">
              <code>{{ task.command }}</code>
            </div>
          </div>

          <!-- 执行输出 -->
          <template v-if="task.execOutput">
            <div class="command-section">
              <span class="command-label">执行输出</span>
              <pre class="exec-output">{{ task.execOutput }}</pre>
            </div>
          </template>

          <!-- 操作按钮 -->
          <div v-if="task.status === 'pending' || task.status === 'confirmed' || task.status === 'failed'" class="action-bar">
            <a-space>
              <a-button v-if="task.status === 'pending'" type="primary" @click="handleConfirm">
                确认执行
              </a-button>
              <a-button v-if="task.status === 'failed'" type="primary" @click="handleRetry">
                重试
              </a-button>
              <a-button v-if="task.status === 'pending' || task.status === 'confirmed'" danger @click="handleCancel">
                取消任务
              </a-button>
            </a-space>
          </div>
        </div>

        <!-- 同漏洞的所有修复主机 -->
        <div class="detail-card" style="margin-top: 16px">
          <h4>修复主机列表 ({{ relatedTasks.length }})</h4>
          <a-table
            :columns="hostTaskColumns"
            :data-source="relatedTasks"
            :loading="relatedLoading"
            :pagination="false"
            size="small"
            row-key="id"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'host'">
                <RouterLink :to="`/hosts/${record.hostId}`">{{ record.hostname || record.hostId }}</RouterLink>
                <div class="text-muted">{{ record.ip }}</div>
              </template>
              <template v-else-if="column.key === 'status'">
                <a-tag :color="taskStatusColor(record.status)" :bordered="false">
                  {{ taskStatusText(record.status) }}
                </a-tag>
              </template>
              <template v-else-if="column.key === 'action'">
                <RouterLink v-if="record.id !== task.id" :to="`/vuln-remediation/tasks/${record.id}`">
                  <a-button type="link" size="small">查看</a-button>
                </RouterLink>
                <span v-else style="color: #86909C; font-size: 12px">当前任务</span>
              </template>
            </template>
          </a-table>
        </div>
      </template>
    </a-spin>

    <!-- 确认执行弹窗 -->
    <a-modal
      v-model:open="confirmModalVisible"
      title="确认执行修复"
      @ok="doConfirm"
      :confirm-loading="confirmLoading"
    >
      <p>确认在主机 <strong>{{ task?.hostname }}</strong> 上执行以下修复命令？</p>
      <a-input
        v-model:value="confirmCommand"
        type="textarea"
        :rows="3"
        placeholder="修复命令"
      />
      <p class="confirm-warning">执行后将通过 Agent 远程执行该命令，请确认命令正确。</p>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter, RouterLink } from 'vue-router'
import { message } from 'ant-design-vue'
import { ArrowLeftOutlined } from '@ant-design/icons-vue'
import { remediationTasksApi } from '@/api/remediation-tasks'
import type { RemediationTaskItem } from '@/api/remediation-tasks'

const route = useRoute()
const router = useRouter()

const loading = ref(false)
const task = ref<RemediationTaskItem | null>(null)
const relatedTasks = ref<RemediationTaskItem[]>([])
const relatedLoading = ref(false)
const confirmModalVisible = ref(false)
const confirmCommand = ref('')
const confirmLoading = ref(false)

const hostTaskColumns = [
  { title: '主机', key: 'host', width: 200 },
  { title: '组件', dataIndex: 'component', width: 120 },
  { title: '修复命令', dataIndex: 'command', width: 250, ellipsis: true },
  { title: '状态', key: 'status', width: 100 },
  { title: '创建时间', dataIndex: 'createdAt', width: 170 },
  { title: '操作', key: 'action', width: 80 },
]

const currentStep = computed(() => {
  const map: Record<string, number> = {
    pending: 0,
    confirmed: 1,
    running: 2,
    success: 3,
    failed: 3,
    cancelled: 3,
  }
  return map[task.value?.status ?? ''] ?? 0
})

const stepsStatus = computed<'process' | 'finish' | 'error'>(() => {
  const status = task.value?.status
  if (status === 'failed') return 'error'
  if (status === 'success') return 'finish'
  return 'process'
})

const finalStepTitle = computed(() => {
  const status = task.value?.status
  if (status === 'success') return '执行完成'
  if (status === 'failed') return '执行失败'
  if (status === 'running') return '执行中'
  return '等待执行'
})

const taskStatusColor = (status: string) => {
  const map: Record<string, string> = {
    pending: 'warning',
    confirmed: 'blue',
    running: 'processing',
    success: 'success',
    failed: 'error',
    cancelled: 'default',
  }
  return map[status] || 'default'
}

const taskStatusText = (status: string) => {
  const map: Record<string, string> = {
    pending: '待确认',
    confirmed: '已确认',
    running: '执行中',
    success: '已完成',
    failed: '失败',
    cancelled: '已取消',
  }
  return map[status] || status
}

const loadTask = async () => {
  const id = Number(route.params.id)
  if (!id) return
  loading.value = true
  try {
    task.value = await remediationTasksApi.get(id)
    loadRelatedTasks()
  } catch {
    message.error('获取任务详情失败')
  } finally {
    loading.value = false
  }
}

const loadRelatedTasks = async () => {
  if (!task.value) return
  relatedLoading.value = true
  try {
    const res = await remediationTasksApi.list({
      vuln_id: String(task.value.vulnId),
      page_size: 100,
    })
    relatedTasks.value = res.items ?? []
  } catch {
    relatedTasks.value = []
  } finally {
    relatedLoading.value = false
  }
}

const handleConfirm = () => {
  if (!task.value) return
  confirmCommand.value = task.value.command
  confirmModalVisible.value = true
}

const doConfirm = async () => {
  if (!task.value) return
  confirmLoading.value = true
  try {
    await remediationTasksApi.confirm(task.value.id, confirmCommand.value)
    message.success('任务已确认，等待 Agent 执行')
    confirmModalVisible.value = false
    loadTask()
  } catch {
    message.error('确认失败')
  } finally {
    confirmLoading.value = false
  }
}

const handleRetry = async () => {
  if (!task.value) return
  try {
    await remediationTasksApi.retry(task.value.id)
    message.success('任务已重置为待确认状态')
    loadTask()
  } catch {
    message.error('重试失败')
  }
}

const handleCancel = async () => {
  if (!task.value) return
  try {
    await remediationTasksApi.cancel(task.value.id)
    message.success('任务已取消')
    loadTask()
  } catch {
    message.error('取消失败')
  }
}

const copyCommand = (cmd: string) => {
  navigator.clipboard.writeText(cmd)
  message.success('已复制到剪贴板')
}

onMounted(() => {
  loadTask()
})
</script>

<style scoped>
.task-detail-page { width: 100%; }

.page-header {
  display: flex;
  align-items: center;
  margin-bottom: 20px;
}

.page-header h2 { margin: 0; }

.detail-card {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  padding: 20px;
}

.detail-card h4 {
  margin-bottom: 12px;
  font-weight: 600;
  color: #1D2129;
}

.steps-wrapper {
  padding: 8px 0;
}

.step-desc {
  font-size: 12px;
  color: #86909C;
  line-height: 1.6;
}

.command-section {
  margin-top: 16px;
}

.command-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.command-label {
  font-weight: 600;
  font-size: 13px;
  color: #1D2129;
}

.command-block {
  background: #F7F8FA;
  padding: 12px 16px;
  border-radius: 6px;
  word-break: break-all;
}

.command-block code {
  font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
  font-size: 13px;
  color: #1D2129;
}

.exec-output {
  background: #1D2129;
  color: #E8F3E8;
  padding: 16px;
  border-radius: 6px;
  font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
  font-size: 12px;
  max-height: 500px;
  overflow: auto;
  white-space: pre-wrap;
  margin-top: 8px;
}

.action-bar {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid #E5E8EF;
}

.text-muted { font-size: 12px; color: #86909C; }

.confirm-warning {
  margin-top: 12px;
  color: #FF7D00;
  font-size: 13px;
}
</style>
