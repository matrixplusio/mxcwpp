<template>
  <div class="config-change-page">
    <a-page-header
      title="配置变更审批"
      sub-title="高敏感配置 (mode/data_source/kms 等) 双审批; 普通配置单审批"
    >
      <template #extra>
        <a-button type="primary" @click="onNewRequest">
          <PlusOutlined /> 提交变更
        </a-button>
      </template>
    </a-page-header>

    <a-card class="filters" :bordered="false">
      <a-space>
        <a-select v-model:value="filterStatus" placeholder="状态" allow-clear style="width: 180px" @change="loadList">
          <a-select-option value="pending">pending 待审批</a-select-option>
          <a-select-option value="approved">approved 已批准 (待应用)</a-select-option>
          <a-select-option value="applied">applied 已应用</a-select-option>
          <a-select-option value="rejected">rejected 已拒绝</a-select-option>
          <a-select-option value="cancelled">cancelled 已取消</a-select-option>
          <a-select-option value="failed">failed 应用失败</a-select-option>
        </a-select>
        <a-select v-model:value="filterTable" placeholder="target_table" allow-clear style="width: 200px" @change="loadList">
          <a-select-option value="feature_flags">feature_flags</a-select-option>
          <a-select-option value="system_config">system_config</a-select-option>
          <a-select-option value="kube_clusters">kube_clusters</a-select-option>
        </a-select>
        <a-button @click="loadList">刷新</a-button>
      </a-space>
    </a-card>

    <a-table
      :columns="columns"
      :data-source="items"
      :loading="loading"
      :pagination="{ pageSize: 20 }"
      row-key="id"
      style="margin-top: 16px"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.dataIndex === 'status'">
          <a-tag :color="statusColor(record.status)">{{ record.status }}</a-tag>
        </template>
        <template v-else-if="column.dataIndex === 'target'">
          <span><b>{{ record.target_table }}</b>.{{ record.target_key }}</span>
          <a-tag v-if="record.approval_required_count >= 2" color="red" style="margin-left: 4px">高敏</a-tag>
        </template>
        <template v-else-if="column.dataIndex === 'progress'">
          {{ record.approved_count }} / {{ record.approval_required_count }}
        </template>
        <template v-else-if="column.dataIndex === 'created_at'">
          {{ formatTime(record.created_at) }}
        </template>
        <template v-else-if="column.dataIndex === 'actions'">
          <a-button type="link" size="small" @click="onView(record)">详情</a-button>
          <template v-if="record.status === 'pending'">
            <a-button type="link" size="small" @click="onApprove(record)">批准</a-button>
            <a-button type="link" size="small" danger @click="onReject(record)">拒绝</a-button>
            <a-button v-if="record.requested_by === currentUser" type="link" size="small" @click="onCancel(record)">取消</a-button>
          </template>
        </template>
      </template>
    </a-table>

    <!-- 提交变更对话框 -->
    <a-modal v-model:open="createVisible" title="提交配置变更" :ok-text="`提交 (需 ${sensitivity} 个审批)`" cancel-text="取消" @ok="onCreateSubmit" width="600px">
      <a-form layout="vertical">
        <a-form-item label="目标表" required>
          <a-select v-model:value="form.target_table">
            <a-select-option value="feature_flags">feature_flags</a-select-option>
            <a-select-option value="system_config">system_config</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="目标 key" required>
          <a-input v-model:value="form.target_key" placeholder="如 mode.global / data_source.alerts" @blur="checkSensitivity" />
        </a-form-item>
        <a-alert v-if="sensitivity >= 2" type="warning" show-icon message="该 key 为高敏配置, 需 2 人审批 (four-eyes)" style="margin-bottom: 12px" />
        <a-form-item label="新值" required>
          <a-textarea v-model:value="form.proposed_value" :rows="2" />
        </a-form-item>
        <a-form-item label="变更原因 (≥10 字符, 审计落库)" required>
          <a-textarea v-model:value="form.reason" :rows="3" placeholder="工单号 / 风险评估 / 验证步骤" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 拒绝对话框 -->
    <a-modal v-model:open="rejectVisible" title="拒绝变更请求" ok-text="确认拒绝" cancel-text="取消" @ok="onRejectSubmit">
      <a-form layout="vertical">
        <a-form-item label="拒绝理由 (≥5 字符)" required>
          <a-textarea v-model:value="rejectReason" :rows="3" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 详情抽屉 -->
    <a-drawer v-model:open="detailVisible" :title="`变更请求 #${detail?.id}`" width="520">
      <a-descriptions v-if="detail" :column="1" bordered size="small">
        <a-descriptions-item label="状态"><a-tag :color="statusColor(detail.status)">{{ detail.status }}</a-tag></a-descriptions-item>
        <a-descriptions-item label="目标">{{ detail.target_table }}.{{ detail.target_key }}</a-descriptions-item>
        <a-descriptions-item label="原值"><pre class="value">{{ detail.old_value || '(空)' }}</pre></a-descriptions-item>
        <a-descriptions-item label="新值"><pre class="value">{{ detail.proposed_value }}</pre></a-descriptions-item>
        <a-descriptions-item label="变更原因">{{ detail.reason }}</a-descriptions-item>
        <a-descriptions-item label="申请人">{{ detail.requested_by }}</a-descriptions-item>
        <a-descriptions-item label="审批进度">{{ detail.approved_count }} / {{ detail.approval_required_count }}</a-descriptions-item>
        <a-descriptions-item label="已审批">{{ detail.approvers || '—' }}</a-descriptions-item>
        <a-descriptions-item v-if="detail.rejected_by" label="拒绝人">{{ detail.rejected_by }}</a-descriptions-item>
        <a-descriptions-item v-if="detail.reject_reason" label="拒绝理由">{{ detail.reject_reason }}</a-descriptions-item>
        <a-descriptions-item label="创建时间">{{ formatTime(detail.created_at) }}</a-descriptions-item>
        <a-descriptions-item v-if="detail.applied_at" label="应用时间">{{ formatTime(detail.applied_at) }}</a-descriptions-item>
      </a-descriptions>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { message, Modal } from 'ant-design-vue'
import { PlusOutlined } from '@ant-design/icons-vue'
import dayjs from 'dayjs'
import { ConfigChangeAPI, type ConfigChangeRequest, type ConfigChangeStatus, type CreateChangeRequest } from '@/api/configChange'

const items = ref<ConfigChangeRequest[]>([])
const loading = ref(false)
const filterStatus = ref<ConfigChangeStatus | undefined>(undefined)
const filterTable = ref<string | undefined>(undefined)
const currentUser = ref<string>(localStorage.getItem('mxcsec_username') || '')

const createVisible = ref(false)
const rejectVisible = ref(false)
const detailVisible = ref(false)
const detail = ref<ConfigChangeRequest | null>(null)
const sensitivity = ref<number>(1)
const rejectingId = ref<number>(0)
const rejectReason = ref('')

const form = reactive<CreateChangeRequest>({
  target_table: 'feature_flags',
  target_key: '',
  proposed_value: '',
  reason: '',
})

const columns = [
  { title: 'ID', dataIndex: 'id', width: 70 },
  { title: '目标', dataIndex: 'target', width: 280 },
  { title: '新值', dataIndex: 'proposed_value', ellipsis: true, width: 200 },
  { title: '状态', dataIndex: 'status', width: 100 },
  { title: '审批进度', dataIndex: 'progress', width: 100 },
  { title: '申请人', dataIndex: 'requested_by', width: 110 },
  { title: '创建时间', dataIndex: 'created_at', width: 150 },
  { title: '操作', dataIndex: 'actions', width: 180, fixed: 'right' },
]

function statusColor(s: ConfigChangeStatus) {
  switch (s) {
    case 'pending': return 'gold'
    case 'approved': return 'blue'
    case 'applied': return 'success'
    case 'rejected': return 'error'
    case 'cancelled': return 'default'
    case 'failed': return 'red'
  }
  return 'default'
}
function formatTime(t?: string) { return t ? dayjs(t).format('YYYY-MM-DD HH:mm') : '—' }

async function loadList() {
  loading.value = true
  try {
    const params: any = {}
    if (filterStatus.value) params.status = filterStatus.value
    if (filterTable.value) params.target_table = filterTable.value
    const res = await ConfigChangeAPI.list(params)
    items.value = res.data?.items || []
  } catch (e: any) {
    message.error('加载失败: ' + (e.message || e))
  } finally {
    loading.value = false
  }
}

function onNewRequest() {
  form.target_table = 'feature_flags'
  form.target_key = ''
  form.proposed_value = ''
  form.reason = ''
  sensitivity.value = 1
  createVisible.value = true
}

async function checkSensitivity() {
  if (!form.target_key) return
  try {
    const res = await ConfigChangeAPI.getSensitivity(form.target_key)
    sensitivity.value = res.data?.required_approval_count || 1
  } catch {
    sensitivity.value = 1
  }
}

async function onCreateSubmit() {
  if (form.reason.length < 10) {
    message.warning('变更原因至少 10 字符')
    return
  }
  try {
    await ConfigChangeAPI.create(form)
    message.success('变更请求已提交, 等待审批')
    createVisible.value = false
    await loadList()
  } catch (e: any) {
    message.error('提交失败: ' + (e.message || e))
  }
}

function onView(r: ConfigChangeRequest) {
  detail.value = r
  detailVisible.value = true
}

function onApprove(r: ConfigChangeRequest) {
  Modal.confirm({
    title: '确认批准?',
    content: `批准 ${r.target_table}.${r.target_key} 改为 "${r.proposed_value}"?`,
    onOk: async () => {
      try {
        await ConfigChangeAPI.approve(r.id)
        message.success('已批准')
        await loadList()
      } catch (e: any) {
        message.error('批准失败: ' + (e.message || e))
      }
    },
  })
}

function onReject(r: ConfigChangeRequest) {
  rejectingId.value = r.id
  rejectReason.value = ''
  rejectVisible.value = true
}

async function onRejectSubmit() {
  if (rejectReason.value.length < 5) {
    message.warning('拒绝理由至少 5 字符')
    return
  }
  try {
    await ConfigChangeAPI.reject(rejectingId.value, rejectReason.value)
    message.success('已拒绝')
    rejectVisible.value = false
    await loadList()
  } catch (e: any) {
    message.error('拒绝失败: ' + (e.message || e))
  }
}

function onCancel(r: ConfigChangeRequest) {
  Modal.confirm({
    title: '取消变更请求?',
    onOk: async () => {
      try {
        await ConfigChangeAPI.cancel(r.id)
        message.success('已取消')
        await loadList()
      } catch (e: any) {
        message.error('取消失败: ' + (e.message || e))
      }
    },
  })
}

onMounted(loadList)
</script>

<style scoped>
.config-change-page {
  padding: 16px;
}
.filters {
  margin-top: 12px;
}
.value {
  margin: 0;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
