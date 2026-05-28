<template>
  <div class="migration-page">
    <div class="page-header">
      <h2>迁移助手</h2>
      <span class="page-header-hint">从 MVP1 (开源版) 迁移核心业务数据到 MVP2</span>
    </div>

    <!-- 向导步骤 -->
    <div class="dashboard-card" style="margin-bottom: 16px">
      <div class="card-body">
        <a-steps :current="currentStep" size="small">
          <a-step title="连接旧平台" description="输入 MVP1 地址和管理员账号" />
          <a-step title="选择迁移范围" description="勾选要迁移的数据表" />
          <a-step title="执行迁移" description="查看进度与详细报告" />
        </a-steps>
      </div>
    </div>

    <!-- Step 1: 连接 -->
    <div v-if="currentStep === 0" class="dashboard-card">
      <div class="card-header">
        <span class="card-title">连接 MVP1</span>
      </div>
      <div class="card-body">
        <a-alert
          type="info"
          show-icon
          style="margin-bottom: 16px"
          message="说明"
          description="请提供 MVP1 开源版的访问地址和管理员账号。本工具通过 HTTP API 读取数据，不会修改旧平台数据。若 MVP1 使用自签名 HTTPS 证书，工具将跳过证书校验。"
        />
        <a-form layout="vertical" :model="connForm" style="max-width: 600px">
          <a-form-item label="MVP1 地址" required>
            <a-input v-model:value="connForm.url" placeholder="http://mvp1.example.com" />
          </a-form-item>
          <a-form-item label="管理员账号" required>
            <a-input v-model:value="connForm.username" placeholder="admin" />
          </a-form-item>
          <a-form-item label="密码" required>
            <a-input-password v-model:value="connForm.password" placeholder="密码不会存储到数据库" />
          </a-form-item>
          <a-button type="primary" :loading="testing" @click="handleTest">测试连接</a-button>
        </a-form>

        <div v-if="connResult" class="conn-result">
          <a-divider />
          <a-descriptions title="连接成功" :column="2" bordered size="small">
            <a-descriptions-item label="MVP1 版本">{{ connResult.version }}</a-descriptions-item>
            <a-descriptions-item label="可迁移数据">
              <span style="color: #52c41a">✓ 连接正常</span>
            </a-descriptions-item>
          </a-descriptions>
          <h4 style="margin-top: 16px">各表记录数预览</h4>
          <a-table
            :columns="previewColumns"
            :data-source="previewRows"
            :pagination="false"
            size="small"
            row-key="name"
          />
          <div style="margin-top: 16px; text-align: right">
            <a-button type="primary" @click="currentStep = 1">下一步：选择迁移范围</a-button>
          </div>
        </div>
      </div>
    </div>

    <!-- Step 2: 选择范围 -->
    <div v-if="currentStep === 1" class="dashboard-card">
      <div class="card-header">
        <span class="card-title">选择迁移范围</span>
      </div>
      <div class="card-body">
        <a-alert
          type="warning"
          show-icon
          style="margin-bottom: 16px"
          message="注意事项"
          description="冲突处理策略：已存在的记录将被跳过。结束后会生成详细报告。用户密码为安全原因不会迁移，迁移后需要管理员重置。"
        />
        <a-form layout="vertical">
          <a-form-item label="选择要迁移的表">
            <a-checkbox-group v-model:value="scope" :options="scopeOptions" />
          </a-form-item>
        </a-form>
        <div style="margin-top: 16px">
          <a-space>
            <a-button @click="currentStep = 0">上一步</a-button>
            <a-popconfirm
              title="确认开始迁移？此过程不可逆，但不会修改 MVP1 数据。"
              @confirm="handleStart"
            >
              <a-button type="primary" :disabled="!scope.length" :loading="starting">
                开始迁移
              </a-button>
            </a-popconfirm>
          </a-space>
        </div>
      </div>
    </div>

    <!-- Step 3: 进度 / 报告 -->
    <div v-if="currentStep === 2" class="dashboard-card">
      <div class="card-header">
        <span class="card-title">迁移进度</span>
        <a-tag :color="statusColor(currentJob?.status)" :bordered="false">
          {{ statusLabel(currentJob?.status) }}
        </a-tag>
      </div>
      <div class="card-body">
        <a-progress
          :percent="currentJob?.progress || 0"
          :status="progressStatus"
          style="margin-bottom: 16px"
        />

        <a-row :gutter="16" style="margin-bottom: 16px">
          <a-col :span="6">
            <a-statistic title="总计处理" :value="currentJob?.total_records || 0" />
          </a-col>
          <a-col :span="6">
            <a-statistic
              title="已创建"
              :value="currentJob?.created_count || 0"
              :value-style="{ color: '#52c41a' }"
            />
          </a-col>
          <a-col :span="6">
            <a-statistic
              title="已跳过"
              :value="currentJob?.skipped_count || 0"
              :value-style="{ color: '#faad14' }"
            />
          </a-col>
          <a-col :span="6">
            <a-statistic
              title="失败"
              :value="currentJob?.failed_count || 0"
              :value-style="{ color: '#ff4d4f' }"
            />
          </a-col>
        </a-row>

        <div v-if="currentJob?.status === 'running' && currentJob?.current_table">
          <a-tag color="blue">当前处理：{{ currentJob.current_table }}</a-tag>
        </div>

        <div v-if="currentJob?.error" style="margin-top: 16px">
          <a-alert type="error" show-icon :message="currentJob.error" />
        </div>

        <!-- 报告表格 -->
        <div v-if="currentJob?.report_data?.length" style="margin-top: 24px">
          <h4>详细报告</h4>
          <a-table
            :columns="reportColumns"
            :data-source="currentJob.report_data"
            :pagination="false"
            size="small"
            row-key="table"
            :expand-row-by-click="true"
          >
            <template #expandedRowRender="{ record }">
              <div v-if="record.skip_reasons?.length">
                <h5 style="color: #faad14">跳过原因 ({{ record.skipped }})</h5>
                <ul class="reason-list">
                  <li v-for="(r, i) in record.skip_reasons" :key="'s' + i">{{ r }}</li>
                </ul>
              </div>
              <div v-if="record.fail_errors?.length" style="margin-top: 12px">
                <h5 style="color: #ff4d4f">失败错误 ({{ record.failed }})</h5>
                <ul class="reason-list">
                  <li v-for="(e, i) in record.fail_errors" :key="'f' + i">{{ e }}</li>
                </ul>
              </div>
              <a-empty v-if="!record.skip_reasons?.length && !record.fail_errors?.length" />
            </template>
          </a-table>
        </div>

        <div style="margin-top: 16px">
          <a-space>
            <a-button
              v-if="currentJob?.status === 'running'"
              danger
              @click="handleCancel"
            >
              取消迁移
            </a-button>
            <a-button v-if="!isJobActive" type="primary" @click="resetWizard">
              再次迁移
            </a-button>
          </a-space>
        </div>
      </div>
    </div>

    <!-- 历史任务 -->
    <div class="dashboard-card" style="margin-top: 16px">
      <div class="card-header">
        <span class="card-title">历史迁移任务</span>
        <a-button type="link" size="small" @click="loadHistory">刷新</a-button>
      </div>
      <div class="card-body">
        <a-table
          :columns="historyColumns"
          :data-source="historyJobs"
          :loading="historyLoading"
          :pagination="{ pageSize: 10 }"
          size="small"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'status'">
              <a-tag :color="statusColor(record.status)" :bordered="false">
                {{ statusLabel(record.status) }}
              </a-tag>
            </template>
            <template v-if="column.key === 'scope'">
              <a-tag v-for="s in record.scope" :key="s">{{ scopeLabels[s] || s }}</a-tag>
            </template>
            <template v-if="column.key === 'counts'">
              <span style="color: #52c41a">✓ {{ record.created_count }}</span>
              <span style="margin: 0 6px; color: #faad14">- {{ record.skipped_count }}</span>
              <span style="color: #ff4d4f">× {{ record.failed_count }}</span>
            </template>
            <template v-if="column.key === 'action'">
              <a-button type="link" size="small" @click="viewJob(record)">查看详情</a-button>
            </template>
          </template>
        </a-table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { message } from 'ant-design-vue'
import { migrationApi, type MigrationJob, type TestConnectionResult } from '@/api/migration'

const currentStep = ref(0)

// Step 1 - 连接
const connForm = ref({ url: '', username: '', password: '' })
const testing = ref(false)
const connResult = ref<TestConnectionResult | null>(null)

// Step 2 - 范围
const scopeLabels: Record<string, string> = {
  users: '用户',
  business_lines: '业务线',
  hosts: '主机',
  policies: '策略',
  rules: '规则',
  scan_tasks: '扫描任务',
  scan_results: '扫描结果',
  notifications: '通知配置',
}

const scopeOptions = [
  { label: '用户 (users)', value: 'users' },
  { label: '业务线 (business_lines)', value: 'business_lines' },
  { label: '主机 (hosts)', value: 'hosts' },
  { label: '策略 (policies)', value: 'policies' },
  { label: '规则 (rules)', value: 'rules' },
  { label: '扫描任务 (scan_tasks)', value: 'scan_tasks' },
  { label: '扫描结果 (scan_results)', value: 'scan_results' },
  { label: '通知配置 (notifications)', value: 'notifications' },
]

const scope = ref<string[]>([
  'users', 'business_lines', 'hosts', 'policies', 'rules', 'notifications',
])

const starting = ref(false)

// Step 3 - 进度
const currentJob = ref<MigrationJob | null>(null)
let pollTimer: ReturnType<typeof setInterval> | null = null

const isJobActive = computed(() => {
  const s = currentJob.value?.status
  return s === 'pending' || s === 'running'
})

const progressStatus = computed(() => {
  const s = currentJob.value?.status
  if (s === 'completed') return 'success'
  if (s === 'failed' || s === 'cancelled') return 'exception'
  return 'active'
})

// 连接测试表格预览
const previewColumns = [
  { title: '数据表', dataIndex: 'label', key: 'label' },
  { title: '记录数', dataIndex: 'count', key: 'count' },
]
const previewRows = computed(() => {
  if (!connResult.value) return []
  return Object.entries(connResult.value.tables).map(([k, v]) => ({
    name: k,
    label: scopeLabels[k] || k,
    count: v < 0 ? '查询失败' : v,
  }))
})

// 报告列
const reportColumns = [
  { title: '数据表', dataIndex: 'table', key: 'table', width: 140 },
  { title: '总计', dataIndex: 'total', key: 'total', width: 80 },
  { title: '已创建', dataIndex: 'created', key: 'created', width: 80 },
  { title: '已跳过', dataIndex: 'skipped', key: 'skipped', width: 80 },
  { title: '失败', dataIndex: 'failed', key: 'failed', width: 80 },
]

// 历史任务
const historyJobs = ref<MigrationJob[]>([])
const historyLoading = ref(false)
const historyColumns = [
  { title: 'ID', dataIndex: 'id', key: 'id', width: 60 },
  { title: '源地址', dataIndex: 'source_url', key: 'source_url', ellipsis: true },
  { title: '范围', key: 'scope' },
  { title: '状态', key: 'status', width: 90 },
  { title: '创建/跳过/失败', key: 'counts', width: 160 },
  { title: '开始时间', dataIndex: 'started_at', key: 'started_at', width: 170 },
  { title: '操作', key: 'action', width: 100 },
]

// --- 方法 ---

const handleTest = async () => {
  if (!connForm.value.url || !connForm.value.username || !connForm.value.password) {
    message.error('请填写完整的连接信息')
    return
  }
  testing.value = true
  try {
    const res = await migrationApi.testConnection(connForm.value)
    connResult.value = res
    message.success('连接成功')
  } catch {
    connResult.value = null
  } finally {
    testing.value = false
  }
}

const handleStart = async () => {
  if (!scope.value.length) {
    message.warning('请至少选择一个数据表')
    return
  }
  starting.value = true
  try {
    const job = await migrationApi.startJob({
      ...connForm.value,
      scope: scope.value,
    })
    currentJob.value = job
    currentStep.value = 2
    message.success('迁移任务已启动')
    startPolling(job.id)
    loadHistory()
  } finally {
    starting.value = false
  }
}

const startPolling = (id: number) => {
  stopPolling()
  pollTimer = setInterval(async () => {
    try {
      const job = await migrationApi.getJob(id)
      currentJob.value = job
      if (!['pending', 'running'].includes(job.status)) {
        stopPolling()
        loadHistory()
      }
    } catch {
      stopPolling()
    }
  }, 2000)
}

const stopPolling = () => {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

const handleCancel = async () => {
  if (!currentJob.value) return
  try {
    await migrationApi.cancelJob(currentJob.value.id)
    message.success('已发送取消请求')
  } catch {
    // 错误已由 apiClient 提示
  }
}

const resetWizard = () => {
  currentStep.value = 0
  connResult.value = null
  currentJob.value = null
  connForm.value.password = ''
}

const loadHistory = async () => {
  historyLoading.value = true
  try {
    const res = await migrationApi.listJobs({ page: 1, page_size: 20 })
    historyJobs.value = res.items || []
  } catch {
    historyJobs.value = []
  } finally {
    historyLoading.value = false
  }
}

const viewJob = async (record: MigrationJob) => {
  try {
    const job = await migrationApi.getJob(record.id)
    currentJob.value = job
    currentStep.value = 2
    if (['pending', 'running'].includes(job.status)) {
      startPolling(job.id)
    }
  } catch {
    // ignore
  }
}

// --- 辅助 ---

const statusLabel = (s?: string) => {
  const map: Record<string, string> = {
    pending: '等待中',
    running: '运行中',
    completed: '已完成',
    failed: '失败',
    cancelled: '已取消',
  }
  return map[s || ''] || '未知'
}

const statusColor = (s?: string) => {
  const map: Record<string, string> = {
    pending: 'default',
    running: 'processing',
    completed: 'success',
    failed: 'error',
    cancelled: 'warning',
  }
  return map[s || ''] || 'default'
}

onMounted(() => {
  loadHistory()
})

onUnmounted(() => {
  stopPolling()
})
</script>

<style scoped>
.migration-page {
  width: 100%;
}
.page-header {
  margin-bottom: 16px;
}
.page-header h2 {
  margin: 0 0 4px 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--mxsec-text-1);
}
.page-header-hint {
  font-size: 13px;
  color: var(--mxsec-text-3);
}
.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
}
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 20px;
  border-bottom: 1px solid var(--mxsec-border-light);
}
.card-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--mxsec-text-1);
}
.card-body {
  padding: 20px;
}
.conn-result {
  margin-top: 16px;
}
.reason-list {
  padding-left: 20px;
  margin: 0;
  max-height: 200px;
  overflow-y: auto;
  font-size: 12px;
  color: var(--mxsec-text-2);
}
.reason-list li {
  margin-bottom: 4px;
}
</style>
