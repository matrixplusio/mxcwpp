<template>
  <div class="remediation-policies-page">
    <div class="page-header">
      <h2>修复策略</h2>
      <span class="page-header-hint">配置自动化修复策略，按条件批量生成修复任务</span>
    </div>

    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <div class="filter-actions">
            <a-button @click="loadPolicies">刷新</a-button>
            <a-button type="primary" @click="openCreateModal">
              <template #icon><PlusOutlined /></template>
              新建策略
            </a-button>
          </div>
        </div>

        <a-table
          :columns="columns"
          :data-source="policies"
          :loading="loading"
          size="middle"
          row-key="id"
          :pagination="false"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'targetType'">
              <a-tag :color="targetTypeColor(record.targetType)">
                {{ targetTypeText(record.targetType) }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'severityMin'">
              <a-tag :color="severityColor(record.severityMin)">
                {{ severityText(record.severityMin) }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'rolloutType'">
              <a-tag>{{ rolloutTypeText(record.rolloutType) }}</a-tag>
            </template>
            <template v-else-if="column.key === 'enabled'">
              <a-tag :color="record.enabled ? 'green' : 'default'" :bordered="false">
                {{ record.enabled ? '已启用' : '已禁用' }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'lastRunAt'">
              {{ formatDate(record.lastRunAt) }}
            </template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="showExecutions(record)">
                  历史
                </a-button>
                <a-button
                  type="link"
                  size="small"
                  :loading="previewLoadingId === record.id"
                  @click="handlePreview(record)"
                >
                  预览
                </a-button>
                <a-popconfirm
                  title="确定要执行此策略？将根据策略规则生成修复任务。"
                  @confirm="handleExecute(record)"
                >
                  <a-button
                    type="link"
                    size="small"
                    :loading="executeLoadingId === record.id"
                  >
                    执行
                  </a-button>
                </a-popconfirm>
                <a-popconfirm
                  title="确定要删除此修复策略吗？"
                  @confirm="handleDelete(record)"
                >
                  <a-button type="link" size="small" danger>删除</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 新建策略弹窗 -->
    <a-modal
      v-model:open="createModalVisible"
      title="新建修复策略"
      :confirm-loading="submitting"
      :width="600"
      @ok="handleCreate"
      @cancel="resetForm"
    >
      <a-form layout="vertical">
        <a-form-item label="策略名称" required>
          <a-input v-model:value="form.name" placeholder="请输入策略名称" />
        </a-form-item>
        <a-form-item label="策略描述">
          <a-textarea
            v-model:value="form.description"
            placeholder="可选：添加策略描述"
            :rows="2"
          />
        </a-form-item>
        <a-form-item label="目标范围" required>
          <a-select v-model:value="form.targetType" placeholder="请选择目标范围">
            <a-select-option value="all">全部主机</a-select-option>
            <a-select-option value="business_line">按业务线</a-select-option>
            <a-select-option value="host_ids">指定主机</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="最低严重等级" required>
          <a-select v-model:value="form.severityMin" placeholder="请选择最低严重等级">
            <a-select-option value="critical">严重 (Critical)</a-select-option>
            <a-select-option value="high">高危 (High)</a-select-option>
            <a-select-option value="medium">中危 (Medium)</a-select-option>
            <a-select-option value="low">低危 (Low)</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="发布策略" required>
          <a-select v-model:value="form.rolloutType" placeholder="请选择发布策略">
            <a-select-option value="immediate">立即执行</a-select-option>
            <a-select-option value="canary">金丝雀发布</a-select-option>
            <a-select-option value="rolling">滚动发布</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="最大并行数">
          <a-input-number
            v-model:value="form.maxParallel"
            :min="1"
            :max="100"
            placeholder="默认 10"
            style="width: 100%"
          />
        </a-form-item>
        <a-form-item>
          <a-checkbox v-model:checked="form.autoConfirm">
            自动确认任务（跳过人工确认步骤）
          </a-checkbox>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 预览结果弹窗 -->
    <a-modal
      v-model:open="previewModalVisible"
      title="策略预览"
      :footer="null"
      :width="400"
    >
      <a-descriptions :column="1" bordered size="small">
        <a-descriptions-item label="匹配主机数">
          {{ previewResult.hostCount }} 台
        </a-descriptions-item>
        <a-descriptions-item label="匹配漏洞数">
          {{ previewResult.vulnCount }} 个
        </a-descriptions-item>
        <a-descriptions-item label="预计生成任务数">
          {{ previewResult.taskCount }} 个
        </a-descriptions-item>
      </a-descriptions>
    </a-modal>

    <!-- 执行历史抽屉 -->
    <a-drawer
      v-model:open="execDrawerVisible"
      :title="'执行历史 - ' + execDrawerTitle"
      width="800"
      :destroy-on-close="true"
    >
      <a-table
        :columns="execColumns"
        :data-source="execData"
        :loading="execLoading"
        size="small"
        row-key="id"
        :pagination="{
          current: execPagination.current,
          pageSize: execPagination.pageSize,
          total: execPagination.total,
          showSizeChanger: false,
        }"
        @change="handleExecTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'">
            <a-tag :color="execStatusColor(record.status)" :bordered="false">
              {{ execStatusText(record.status) }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'startedAt'">
            {{ formatDate(record.startedAt) }}
          </template>
          <template v-else-if="column.key === 'duration'">
            {{ record.duration ? record.duration + 's' : '-' }}
          </template>
          <template v-else-if="column.key === 'errorMsg'">
            <a-tooltip v-if="record.errorMsg" :title="record.errorMsg">
              <span class="exec-error-text">{{ record.errorMsg }}</span>
            </a-tooltip>
            <span v-else>-</span>
          </template>
        </template>
      </a-table>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, reactive } from 'vue'
import { message } from 'ant-design-vue'
import { PlusOutlined } from '@ant-design/icons-vue'
import { remediationPoliciesApi } from '@/api/remediation-policies'
import type { RemediationPolicy, PolicyPreview, PolicyExecution } from '@/api/remediation-policies'

const loading = ref(false)
const policies = ref<RemediationPolicy[]>([])
const createModalVisible = ref(false)
const submitting = ref(false)
const previewModalVisible = ref(false)
const previewLoadingId = ref<number | null>(null)
const executeLoadingId = ref<number | null>(null)
const previewResult = reactive<PolicyPreview>({
  hostCount: 0,
  vulnCount: 0,
  taskCount: 0,
})

const form = reactive({
  name: '',
  description: '',
  targetType: undefined as string | undefined,
  severityMin: undefined as string | undefined,
  rolloutType: undefined as string | undefined,
  maxParallel: 10,
  autoConfirm: false,
})

const columns = [
  { title: 'ID', dataIndex: 'id', width: 60 },
  { title: '策略名称', dataIndex: 'name', width: 160 },
  { title: '目标范围', key: 'targetType', width: 110 },
  { title: '最低等级', key: 'severityMin', width: 110 },
  { title: '发布策略', key: 'rolloutType', width: 110 },
  { title: '状态', key: 'enabled', width: 90 },
  { title: '上次执行', key: 'lastRunAt', width: 170 },
  { title: '操作', key: 'action', width: 180, fixed: 'right' as const },
]

const targetTypeColor = (type: string) => {
  const map: Record<string, string> = {
    all: 'blue',
    business_line: 'green',
    host_ids: 'orange',
  }
  return map[type] || 'default'
}

const targetTypeText = (type: string) => {
  const map: Record<string, string> = {
    all: '全部主机',
    business_line: '业务线',
    host_ids: '指定主机',
  }
  return map[type] || type
}

const severityColor = (severity: string) => {
  const map: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'blue',
  }
  return map[severity] || 'default'
}

const severityText = (severity: string) => {
  const map: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  }
  return map[severity] || severity
}

const rolloutTypeText = (type: string) => {
  const map: Record<string, string> = {
    immediate: '立即执行',
    canary: '金丝雀',
    rolling: '滚动发布',
  }
  return map[type] || type
}

const formatDate = (dateStr?: string): string => {
  if (!dateStr) return '-'
  return dateStr.replace('T', ' ').substring(0, 19)
}

const loadPolicies = async () => {
  loading.value = true
  try {
    const data = await remediationPoliciesApi.list()
    policies.value = data ?? []
  } catch {
    policies.value = []
  } finally {
    loading.value = false
  }
}

const openCreateModal = () => {
  resetForm()
  createModalVisible.value = true
}

const resetForm = () => {
  form.name = ''
  form.description = ''
  form.targetType = undefined
  form.severityMin = undefined
  form.rolloutType = undefined
  form.maxParallel = 10
  form.autoConfirm = false
}

const handleCreate = async () => {
  if (!form.name || !form.targetType || !form.severityMin || !form.rolloutType) {
    message.warning('请填写完整的策略信息')
    return
  }
  submitting.value = true
  try {
    await remediationPoliciesApi.create({
      name: form.name,
      description: form.description,
      targetType: form.targetType,
      severityMin: form.severityMin,
      rolloutType: form.rolloutType,
      maxParallel: form.maxParallel,
      autoConfirm: form.autoConfirm,
    })
    message.success('修复策略已创建')
    createModalVisible.value = false
    resetForm()
    loadPolicies()
  } catch {
    message.error('创建失败')
  } finally {
    submitting.value = false
  }
}

const handlePreview = async (record: RemediationPolicy) => {
  previewLoadingId.value = record.id
  try {
    const result = await remediationPoliciesApi.preview(record.id)
    previewResult.hostCount = result.hostCount
    previewResult.vulnCount = result.vulnCount
    previewResult.taskCount = result.taskCount
    previewModalVisible.value = true
  } catch {
    message.error('预览失败')
  } finally {
    previewLoadingId.value = null
  }
}

const handleExecute = async (record: RemediationPolicy) => {
  executeLoadingId.value = record.id
  try {
    await remediationPoliciesApi.execute(record.id)
    message.success('策略已执行，修复任务生成中')
    loadPolicies()
  } catch {
    message.error('执行失败')
  } finally {
    executeLoadingId.value = null
  }
}

const handleDelete = async (record: RemediationPolicy) => {
  try {
    await remediationPoliciesApi.delete(record.id)
    message.success('修复策略已删除')
    loadPolicies()
  } catch {
    message.error('删除失败')
  }
}

// === 执行历史 ===
const execDrawerVisible = ref(false)
const execDrawerTitle = ref('')
const execLoading = ref(false)
const execData = ref<PolicyExecution[]>([])
const execPolicyId = ref(0)
const execPagination = reactive({ current: 1, pageSize: 20, total: 0 })

const execColumns = [
  { title: 'ID', dataIndex: 'id', width: 60 },
  { title: '状态', key: 'status', width: 80 },
  { title: '匹配主机', dataIndex: 'hostCount', width: 90 },
  { title: '匹配漏洞', dataIndex: 'vulnCount', width: 90 },
  { title: '生成任务', dataIndex: 'taskCount', width: 90 },
  { title: '执行人', dataIndex: 'createdBy', width: 100 },
  { title: '执行时间', key: 'startedAt', width: 170 },
  { title: '耗时', key: 'duration', width: 70 },
  { title: '备注', key: 'errorMsg', ellipsis: true },
]

const execStatusColor = (status: string) => {
  const map: Record<string, string> = { success: 'green', failed: 'red', running: 'blue' }
  return map[status] || 'default'
}

const execStatusText = (status: string) => {
  const map: Record<string, string> = { success: '成功', failed: '失败', running: '执行中' }
  return map[status] || status
}

const showExecutions = async (record: RemediationPolicy) => {
  execPolicyId.value = record.id
  execDrawerTitle.value = record.name
  execPagination.current = 1
  execDrawerVisible.value = true
  await loadExecutions()
}

const loadExecutions = async () => {
  execLoading.value = true
  try {
    const data = await remediationPoliciesApi.listExecutions(
      execPolicyId.value,
      execPagination.current,
      execPagination.pageSize,
    )
    execData.value = data?.items ?? []
    execPagination.total = data?.total ?? 0
  } catch {
    execData.value = []
  } finally {
    execLoading.value = false
  }
}

const handleExecTableChange = (pag: { current: number }) => {
  execPagination.current = pag.current
  loadExecutions()
}

onMounted(() => {
  loadPolicies()
})
</script>

<style scoped>
.remediation-policies-page { width: 100%; }

.page-header {
  display: flex;
  align-items: baseline;
  gap: 12px;
  margin-bottom: 24px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.page-header-hint {
  font-size: 13px;
  color: #86909C;
}

.dashboard-card { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 12px; margin-bottom: 16px; }
.filter-actions { margin-left: auto; display: flex; gap: 8px; }

.exec-error-text {
  color: #F53F3F;
  font-size: 12px;
  cursor: pointer;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 200px;
  display: inline-block;
}
</style>
