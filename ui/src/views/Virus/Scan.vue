<template>
  <div class="virus-scan-page">
    <div class="page-header">
      <h2>病毒查杀</h2>
      <span class="page-header-hint">管理扫描任务、查看威胁检测结果与处置</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value">{{ statistics.threats.detected }}</div>
          <div class="stat-label">待处置威胁</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value critical">{{ statistics.severity.critical }}</div>
          <div class="stat-label">紧急威胁</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value high">{{ statistics.severity.high }}</div>
          <div class="stat-label">高危威胁</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value primary">{{ statistics.affectedHosts }}</div>
          <div class="stat-label">受影响主机</div>
        </div>
      </a-col>
    </a-row>

    <!-- 病毒库状态 -->
    <div class="db-status-bar section-row">
      <div class="db-status-left">
        <span class="db-status-label">病毒库状态</span>
        <template v-if="virusDBStatus && 'version' in virusDBStatus">
          <a-tag :color="dbStatusColor(virusDBStatus.status)" :bordered="false">
            {{ dbStatusText(virusDBStatus.status) }}
          </a-tag>
          <span v-if="virusDBStatus.version" class="db-status-info">
            版本 {{ virusDBStatus.version }}
          </span>
          <span class="db-status-info">
            {{ formatDateTime(virusDBStatus.startedAt) }}
          </span>
          <span v-if="virusDBStatus.duration" class="db-status-info">
            耗时 {{ virusDBStatus.duration }}s
          </span>
          <a-tooltip v-if="virusDBStatus.status === 'failed' && virusDBStatus.errorMsg" :title="virusDBStatus.errorMsg">
            <span class="db-status-error">{{ virusDBStatus.errorMsg }}</span>
          </a-tooltip>
        </template>
        <span v-else class="db-status-info">尚未执行过同步</span>
      </div>
      <div class="db-status-actions">
        <a-button size="small" @click="showVirusDBHistory">历史记录</a-button>
        <a-button size="small" type="primary" :loading="syncTriggering" @click="handleTriggerSync">
          手动同步
        </a-button>
      </div>
    </div>

    <!-- Tab 切换 -->
    <div class="dashboard-card">
      <div class="card-body">
        <a-tabs v-model:activeKey="activeTab">
          <!-- === 扫描任务 Tab === -->
          <a-tab-pane key="tasks" tab="扫描任务">
            <div class="filter-bar">
              <a-input-search
                v-model:value="taskSearch"
                placeholder="搜索任务名称"
                style="width: 260px"
                allow-clear
                @search="handleTaskFilterChange"
              />
              <a-select
                v-model:value="taskFilterStatus"
                style="width: 140px"
                placeholder="任务状态"
                allow-clear
                @change="handleTaskFilterChange"
              >
                <a-select-option value="pending">待执行</a-select-option>
                <a-select-option value="running">执行中</a-select-option>
                <a-select-option value="completed">已完成</a-select-option>
                <a-select-option value="failed">失败</a-select-option>
                <a-select-option value="cancelled">已取消</a-select-option>
              </a-select>
              <a-select
                v-model:value="taskFilterScanType"
                style="width: 140px"
                placeholder="扫描类型"
                allow-clear
                @change="handleTaskFilterChange"
              >
                <a-select-option value="quick">快速扫描</a-select-option>
                <a-select-option value="full">全盘扫描</a-select-option>
                <a-select-option value="custom">自定义扫描</a-select-option>
              </a-select>
              <div class="filter-actions">
                <a-button @click="handleTaskReset">重置</a-button>
                <a-button type="primary" @click="showCreateTaskModal">新建扫描任务</a-button>
              </div>
            </div>

            <a-table
              :columns="taskColumns"
              :data-source="tasks"
              :loading="taskLoading"
              :pagination="taskPagination"
              size="middle"
              row-key="id"
              @change="handleTaskTableChange"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'name'">
                  <a @click="showTaskDetail(record)">{{ record.name }}</a>
                </template>
                <template v-else-if="column.key === 'scanType'">
                  <a-tag :bordered="false">{{ scanTypeTextMap[record.scanType] || record.scanType }}</a-tag>
                </template>
                <template v-else-if="column.key === 'status'">
                  <a-tag :color="taskStatusColorMap[record.status]" :bordered="false">
                    {{ taskStatusTextMap[record.status] || record.status }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'progress'">
                  <template v-if="record.totalHosts > 0">
                    <a-progress
                      :percent="Math.round((record.scannedHosts / record.totalHosts) * 100)"
                      :status="record.status === 'failed' ? 'exception' : record.status === 'completed' ? 'success' : 'active'"
                      size="small"
                    />
                  </template>
                  <span v-else>-</span>
                </template>
                <template v-else-if="column.key === 'threatCount'">
                  <span :style="{ color: record.threatCount > 0 ? '#EF4444' : '#22C55E', fontWeight: 600 }">
                    {{ record.threatCount }}
                  </span>
                </template>
                <template v-else-if="column.key === 'action'">
                  <a-space>
                    <a @click="showTaskDetail(record)">详情</a>
                    <a
                      v-if="record.status === 'pending' || record.status === 'running'"
                      style="color: #F59E0B"
                      @click="handleCancelTask(record)"
                    >
                      取消
                    </a>
                    <a-popconfirm
                      v-if="record.status !== 'running'"
                      title="确认删除该扫描任务？"
                      @confirm="handleDeleteTask(record.id)"
                    >
                      <a style="color: #ff4d4f">删除</a>
                    </a-popconfirm>
                  </a-space>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <!-- === 扫描结果 Tab === -->
          <a-tab-pane key="results" tab="扫描结果">
            <div class="filter-bar">
              <a-input-search
                v-model:value="resultSearch"
                placeholder="搜索威胁名称、文件路径、主机名或 IP"
                style="width: 320px"
                allow-clear
                @search="handleResultFilterChange"
              />
              <a-select
                v-model:value="resultFilterSeverity"
                style="width: 140px"
                placeholder="严重级别"
                allow-clear
                @change="handleResultFilterChange"
              >
                <a-select-option value="critical">紧急</a-select-option>
                <a-select-option value="high">高危</a-select-option>
                <a-select-option value="medium">中危</a-select-option>
                <a-select-option value="low">低危</a-select-option>
              </a-select>
              <a-select
                v-model:value="resultFilterThreatType"
                style="width: 140px"
                placeholder="威胁类型"
                allow-clear
                @change="handleResultFilterChange"
              >
                <a-select-option value="virus">病毒</a-select-option>
                <a-select-option value="trojan">木马</a-select-option>
                <a-select-option value="worm">蠕虫</a-select-option>
                <a-select-option value="ransomware">勒索</a-select-option>
                <a-select-option value="rootkit">Rootkit</a-select-option>
                <a-select-option value="miner">挖矿</a-select-option>
                <a-select-option value="backdoor">后门</a-select-option>
                <a-select-option value="other">其他</a-select-option>
              </a-select>
              <a-select
                v-model:value="resultFilterAction"
                style="width: 140px"
                placeholder="处置状态"
                allow-clear
                @change="handleResultFilterChange"
              >
                <a-select-option value="detected">待处置</a-select-option>
                <a-select-option value="quarantined">已隔离</a-select-option>
                <a-select-option value="deleted">已删除</a-select-option>
                <a-select-option value="ignored">已忽略</a-select-option>
              </a-select>
              <div class="filter-actions">
                <a-button @click="handleResultReset">重置</a-button>
              </div>
            </div>

            <a-table
              :columns="resultColumns"
              :data-source="results"
              :loading="resultLoading"
              :pagination="resultPagination"
              size="middle"
              row-key="id"
              @change="handleResultTableChange"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'threatName'">
                  <a @click="showResultDetail(record)">{{ record.threatName }}</a>
                </template>
                <template v-else-if="column.key === 'severity'">
                  <a-tag :color="severityColorMap[record.severity]" :bordered="false">
                    {{ severityTextMap[record.severity] || record.severity }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'threatType'">
                  <a-tag :bordered="false">{{ threatTypeTextMap[record.threatType] || record.threatType }}</a-tag>
                </template>
                <template v-else-if="column.key === 'host'">
                  <RouterLink :to="`/hosts/${record.hostId}`">{{ record.hostname || record.hostId }}</RouterLink>
                  <div style="color: #86909C; font-size: 12px">{{ record.ip }}</div>
                </template>
                <template v-else-if="column.key === 'filePath'">
                  <span style="font-family: monospace; font-size: 12px; word-break: break-all">{{ record.filePath }}</span>
                </template>
                <template v-else-if="column.key === 'action'">
                  <a-tag :color="actionColorMap[record.action]" :bordered="false">
                    {{ actionTextMap[record.action] || record.action }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'operate'">
                  <a-space>
                    <a @click="showResultDetail(record)">详情</a>
                    <template v-if="record.action === 'detected'">
                      <a-popconfirm title="确认隔离该威胁文件？" @confirm="handleQuarantine(record.id)">
                        <a style="color: #F59E0B">隔离</a>
                      </a-popconfirm>
                      <a-popconfirm title="确认删除该威胁文件？" @confirm="handleDeleteFile(record.id)">
                        <a style="color: #EF4444">删除</a>
                      </a-popconfirm>
                      <a @click="handleIgnore(record.id)">忽略</a>
                    </template>
                  </a-space>
                </template>
              </template>
            </a-table>
          </a-tab-pane>
        </a-tabs>
      </div>
    </div>

    <!-- 新建扫描任务弹窗 -->
    <a-modal
      v-model:open="createVisible"
      title="新建扫描任务"
      :confirm-loading="createLoading"
      @ok="handleCreateTask"
    >
      <a-form layout="vertical">
        <a-form-item label="任务名称" required>
          <a-input v-model:value="createForm.name" placeholder="请输入任务名称" />
        </a-form-item>
        <a-form-item label="扫描类型" required>
          <a-radio-group v-model:value="createForm.scanType">
            <a-radio value="quick">快速扫描</a-radio>
            <a-radio value="full">全盘扫描</a-radio>
            <a-radio value="custom">自定义路径</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item v-if="createForm.scanType === 'custom'" label="扫描路径" required>
          <a-textarea
            v-model:value="createForm.scanPathsText"
            placeholder="每行一个路径，如：&#10;/usr/bin&#10;/tmp&#10;/var/www"
            :rows="4"
          />
        </a-form-item>
        <a-form-item label="目标主机" required>
          <a-select
            v-model:value="createForm.hostIds"
            mode="multiple"
            placeholder="选择目标主机"
            :loading="hostsLoading"
            show-search
            :filter-option="filterHostOption"
            style="width: 100%"
          >
            <a-select-option v-for="h in availableHosts" :key="h.host_id" :value="h.host_id">
              {{ h.hostname }} ({{ h.ipv4?.[0] || '-' }})
            </a-select-option>
          </a-select>
          <div style="margin-top: 4px">
            <a-button type="link" size="small" @click="selectAllHosts">全选</a-button>
            <a-button type="link" size="small" @click="createForm.hostIds = []">清空</a-button>
          </div>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 任务详情抽屉 -->
    <a-drawer
      v-model:open="taskDetailVisible"
      :title="taskDetail?.name || '任务详情'"
      width="640"
      placement="right"
    >
      <template v-if="taskDetail">
        <a-descriptions :column="2" bordered size="small">
          <a-descriptions-item label="任务名称" :span="2">{{ taskDetail.name }}</a-descriptions-item>
          <a-descriptions-item label="扫描类型">
            {{ scanTypeTextMap[taskDetail.scanType] || taskDetail.scanType }}
          </a-descriptions-item>
          <a-descriptions-item label="状态">
            <a-tag :color="taskStatusColorMap[taskDetail.status]" :bordered="false">
              {{ taskStatusTextMap[taskDetail.status] || taskDetail.status }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="目标主机数">{{ taskDetail.totalHosts }}</a-descriptions-item>
          <a-descriptions-item label="已完成">{{ taskDetail.scannedHosts }}</a-descriptions-item>
          <a-descriptions-item label="发现威胁数">
            <span :style="{ color: taskDetail.threatCount > 0 ? '#EF4444' : '#22C55E', fontWeight: 600 }">
              {{ taskDetail.threatCount }}
            </span>
          </a-descriptions-item>
          <a-descriptions-item label="创建人">{{ taskDetail.createdBy || '-' }}</a-descriptions-item>
          <a-descriptions-item label="创建时间" :span="2">{{ taskDetail.createdAt }}</a-descriptions-item>
          <a-descriptions-item label="开始时间">{{ taskDetail.startedAt || '-' }}</a-descriptions-item>
          <a-descriptions-item label="结束时间">{{ taskDetail.finishedAt || '-' }}</a-descriptions-item>
          <a-descriptions-item v-if="taskDetail.scanPaths?.length" label="扫描路径" :span="2">
            <div v-for="p in taskDetail.scanPaths" :key="p" style="font-family: monospace; font-size: 12px">{{ p }}</div>
          </a-descriptions-item>
        </a-descriptions>

        <a-divider>查看该任务的扫描结果</a-divider>
        <a-button type="primary" @click="viewTaskResults(taskDetail.id)">查看扫描结果</a-button>
      </template>
    </a-drawer>

    <!-- 结果详情抽屉 -->
    <a-drawer
      v-model:open="resultDetailVisible"
      :title="resultDetail?.threatName || '威胁详情'"
      width="640"
      placement="right"
    >
      <template v-if="resultDetail">
        <a-descriptions :column="1" bordered size="small">
          <a-descriptions-item label="威胁名称">{{ resultDetail.threatName }}</a-descriptions-item>
          <a-descriptions-item label="威胁类型">
            <a-tag :bordered="false">{{ threatTypeTextMap[resultDetail.threatType] || resultDetail.threatType }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="严重级别">
            <a-tag :color="severityColorMap[resultDetail.severity]" :bordered="false">
              {{ severityTextMap[resultDetail.severity] || resultDetail.severity }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="处置状态">
            <a-tag :color="actionColorMap[resultDetail.action]" :bordered="false">
              {{ actionTextMap[resultDetail.action] || resultDetail.action }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="文件路径">
            <span style="font-family: monospace; font-size: 12px; word-break: break-all">{{ resultDetail.filePath }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="文件哈希">
            <span style="font-family: monospace; font-size: 12px">{{ resultDetail.fileHash || '-' }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="文件大小">{{ formatFileSize(resultDetail.fileSize) }}</a-descriptions-item>
          <a-descriptions-item label="主机">
            <RouterLink :to="`/hosts/${resultDetail.hostId}`">{{ resultDetail.hostname || resultDetail.hostId }}</RouterLink>
            <span style="color: #86909C; margin-left: 8px">{{ resultDetail.ip }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="检测时间">{{ resultDetail.detectedAt }}</a-descriptions-item>
        </a-descriptions>

        <template v-if="resultDetail.action === 'detected'">
          <a-divider />
          <a-space>
            <a-button type="primary" danger @click="handleQuarantine(resultDetail.id); resultDetailVisible = false">
              隔离文件
            </a-button>
            <a-button danger @click="handleDeleteFile(resultDetail.id); resultDetailVisible = false">
              删除文件
            </a-button>
            <a-button @click="handleIgnore(resultDetail.id); resultDetailVisible = false">
              忽略
            </a-button>
          </a-space>
        </template>
      </template>
    </a-drawer>
    <!-- 病毒库同步历史抽屉 -->
    <a-drawer
      v-model:open="virusDBHistoryVisible"
      title="病毒库同步历史"
      width="1080"
      placement="right"
    >
      <a-table
        :columns="virusDBHistoryColumns"
        :data-source="virusDBHistoryData"
        :loading="virusDBHistoryLoading"
        :pagination="virusDBHistoryPagination"
        size="small"
        row-key="id"
        @change="handleVirusDBHistoryTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'">
            <a-tag :color="dbStatusColor(record.status)" :bordered="false">
              {{ dbStatusText(record.status) }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'fileSize'">
            {{ formatFileSize(record.fileSize) }}
          </template>
          <template v-else-if="column.key === 'errorMsg'">
            <a-tooltip v-if="record.errorMsg" :title="record.errorMsg">
              <span style="color: #EF4444; font-size: 12px; cursor: pointer">{{ record.errorMsg }}</span>
            </a-tooltip>
            <span v-else>-</span>
          </template>
        </template>
      </a-table>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { antivirusApi } from '@/api/antivirus'
import type { AntivirusScanTask, AntivirusScanResult, AntivirusStatistics, SecurityDBSyncRecord } from '@/api/antivirus'
import { hostsApi } from '@/api/hosts'
import type { Host } from '@/api/types'
import { formatDateTime } from '@/utils/date'

const route = useRoute()
const router = useRouter()

// === 统计 ===
const statistics = ref<AntivirusStatistics>({
  tasks: { total: 0, running: 0, completed: 0 },
  threats: { total: 0, detected: 0, quarantined: 0, deleted: 0, ignored: 0 },
  severity: { critical: 0, high: 0, medium: 0, low: 0 },
  affectedHosts: 0,
})

// === Tab ===
const activeTab = ref<string>((route.query.tab as string) || 'tasks')

// === 映射表 ===
const severityColorMap: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityTextMap: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }
const scanTypeTextMap: Record<string, string> = { quick: '快速扫描', full: '全盘扫描', custom: '自定义扫描' }
const taskStatusColorMap: Record<string, string> = { pending: 'default', running: 'processing', completed: 'success', failed: 'error', cancelled: 'warning' }
const taskStatusTextMap: Record<string, string> = { pending: '待执行', running: '执行中', completed: '已完成', failed: '失败', cancelled: '已取消' }
const threatTypeTextMap: Record<string, string> = { virus: '病毒', trojan: '木马', worm: '蠕虫', ransomware: '勒索', rootkit: 'Rootkit', miner: '挖矿', backdoor: '后门', other: '其他' }
const actionColorMap: Record<string, string> = { detected: 'red', quarantined: 'orange', deleted: 'default', ignored: 'default' }
const actionTextMap: Record<string, string> = { detected: '待处置', quarantined: '已隔离', deleted: '已删除', ignored: '已忽略' }

// === 扫描任务 ===
const taskLoading = ref(false)
const tasks = ref<AntivirusScanTask[]>([])
const taskSearch = ref('')
const taskFilterStatus = ref<string>()
const taskFilterScanType = ref<string>()
const taskPagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const taskColumns = [
  { title: '任务名称', key: 'name', ellipsis: true },
  { title: '扫描类型', key: 'scanType', width: 110 },
  { title: '状态', key: 'status', width: 100 },
  { title: '进度', key: 'progress', width: 160 },
  { title: '威胁数', key: 'threatCount', width: 80, align: 'center' as const },
  { title: '创建人', dataIndex: 'createdBy', width: 100 },
  { title: '创建时间', dataIndex: 'createdAt', width: 170 },
  { title: '操作', key: 'action', width: 160, fixed: 'right' as const },
]

// === 扫描结果 ===
const resultLoading = ref(false)
const results = ref<AntivirusScanResult[]>([])
const resultSearch = ref('')
const resultFilterSeverity = ref<string>()
const resultFilterThreatType = ref<string>()
const resultFilterAction = ref<string>()
const resultFilterTaskId = ref<number>()
const resultPagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const resultColumns = [
  { title: '威胁名称', key: 'threatName', width: 180 },
  { title: '严重级别', key: 'severity', width: 90 },
  { title: '威胁类型', key: 'threatType', width: 90 },
  { title: '主机', key: 'host', width: 160 },
  { title: '文件路径', key: 'filePath', ellipsis: true },
  { title: '处置状态', key: 'action', width: 90 },
  { title: '检测时间', dataIndex: 'detectedAt', width: 170 },
  { title: '操作', key: 'operate', width: 180, fixed: 'right' as const },
]

// === 创建任务 ===
const createVisible = ref(false)
const createLoading = ref(false)
const hostsLoading = ref(false)
const availableHosts = ref<Host[]>([])
const createForm = reactive({
  name: '',
  scanType: 'quick',
  scanPathsText: '',
  hostIds: [] as string[],
})

// === 详情 ===
const taskDetailVisible = ref(false)
const taskDetail = ref<AntivirusScanTask>()
const resultDetailVisible = ref(false)
const resultDetail = ref<AntivirusScanResult>()

// === 病毒库状态 ===
const virusDBStatus = ref<SecurityDBSyncRecord | null>(null)
const syncTriggering = ref(false)
const virusDBHistoryVisible = ref(false)
const virusDBHistoryLoading = ref(false)
const virusDBHistoryData = ref<SecurityDBSyncRecord[]>([])
const virusDBHistoryPagination = ref({
  current: 1,
  pageSize: 10,
  total: 0,
  showSizeChanger: false,
  showTotal: (total: number) => `共 ${total} 条`,
})

const virusDBHistoryColumns = [
  { title: '版本', dataIndex: 'version', width: 160 },
  { title: '状态', key: 'status', width: 80 },
  { title: '文件大小', key: 'fileSize', width: 100 },
  { title: '耗时(秒)', dataIndex: 'duration', width: 80 },
  { title: '开始时间', dataIndex: 'startedAt', width: 170, customRender: ({ text }: { text: string }) => formatDateTime(text) },
  { title: '错误信息', key: 'errorMsg', ellipsis: true },
]

const dbStatusColor = (status: string) => {
  if (status === 'success') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'running') return 'processing'
  return 'default'
}

const dbStatusText = (status: string) => {
  const map: Record<string, string> = { success: '成功', failed: '失败', running: '同步中' }
  return map[status] || status
}

const loadVirusDBStatus = async () => {
  try {
    const res = await antivirusApi.getVirusDBStatus()
    if ('version' in res) {
      virusDBStatus.value = res as SecurityDBSyncRecord
    } else {
      virusDBStatus.value = null
    }
  } catch {
    virusDBStatus.value = null
  }
}

const handleTriggerSync = async () => {
  syncTriggering.value = true
  try {
    await antivirusApi.triggerVirusDBSync()
    message.success('同步任务已触发')
    setTimeout(() => loadVirusDBStatus(), 2000)
  } catch {
    // 全局拦截器已处理
  } finally {
    syncTriggering.value = false
  }
}

const showVirusDBHistory = async () => {
  virusDBHistoryVisible.value = true
  await loadVirusDBHistory()
}

const loadVirusDBHistory = async () => {
  virusDBHistoryLoading.value = true
  try {
    const res = await antivirusApi.getVirusDBHistory({
      page: virusDBHistoryPagination.value.current,
      page_size: virusDBHistoryPagination.value.pageSize,
    })
    virusDBHistoryData.value = res.items ?? []
    virusDBHistoryPagination.value.total = res.total ?? 0
  } catch {
    virusDBHistoryData.value = []
  } finally {
    virusDBHistoryLoading.value = false
  }
}

const handleVirusDBHistoryTableChange = (pag: any) => {
  virusDBHistoryPagination.value.current = pag.current
  loadVirusDBHistory()
}

// === 数据加载 ===
const loadStatistics = async () => {
  try {
    statistics.value = await antivirusApi.getStatistics()
  } catch {
    // 静默处理
  }
}

const loadTasks = async () => {
  taskLoading.value = true
  try {
    const res = await antivirusApi.listTasks({
      page: taskPagination.value.current,
      page_size: taskPagination.value.pageSize,
      keyword: taskSearch.value || undefined,
      status: taskFilterStatus.value || undefined,
      scan_type: taskFilterScanType.value || undefined,
    })
    tasks.value = res.items ?? []
    taskPagination.value.total = res.total ?? 0
  } catch {
    tasks.value = []
  } finally {
    taskLoading.value = false
  }
}

const loadResults = async () => {
  resultLoading.value = true
  try {
    const res = await antivirusApi.listResults({
      page: resultPagination.value.current,
      page_size: resultPagination.value.pageSize,
      keyword: resultSearch.value || undefined,
      severity: resultFilterSeverity.value || undefined,
      threat_type: resultFilterThreatType.value || undefined,
      action: resultFilterAction.value || undefined,
      task_id: resultFilterTaskId.value || undefined,
    })
    results.value = res.items ?? []
    resultPagination.value.total = res.total ?? 0
  } catch {
    results.value = []
  } finally {
    resultLoading.value = false
  }
}

// === 任务操作 ===
const handleTaskFilterChange = () => {
  taskPagination.value.current = 1
  loadTasks()
}

const handleTaskTableChange = (pag: any) => {
  taskPagination.value.current = pag.current
  taskPagination.value.pageSize = pag.pageSize
  loadTasks()
}

const handleTaskReset = () => {
  taskSearch.value = ''
  taskFilterStatus.value = undefined
  taskFilterScanType.value = undefined
  taskPagination.value.current = 1
  loadTasks()
}

const showCreateTaskModal = async () => {
  createForm.name = ''
  createForm.scanType = 'quick'
  createForm.scanPathsText = ''
  createForm.hostIds = []
  createVisible.value = true
  hostsLoading.value = true
  try {
    const res = await hostsApi.list({ page: 1, page_size: 1000, status: 'online' })
    availableHosts.value = res.items ?? []
  } catch {
    availableHosts.value = []
  } finally {
    hostsLoading.value = false
  }
}

const filterHostOption = (input: string, option: any) => {
  const label = option.children?.[0]?.children || ''
  return label.toLowerCase().includes(input.toLowerCase())
}

const selectAllHosts = () => {
  createForm.hostIds = availableHosts.value.map((h) => h.host_id)
}

const handleCreateTask = async () => {
  if (!createForm.name.trim()) {
    message.warning('请输入任务名称')
    return
  }
  if (createForm.hostIds.length === 0) {
    message.warning('请选择目标主机')
    return
  }
  if (createForm.scanType === 'custom' && !createForm.scanPathsText.trim()) {
    message.warning('自定义扫描模式必须指定扫描路径')
    return
  }

  createLoading.value = true
  try {
    const scanPaths = createForm.scanType === 'custom'
      ? createForm.scanPathsText.split('\n').map((p) => p.trim()).filter(Boolean)
      : undefined
    await antivirusApi.createTask({
      name: createForm.name.trim(),
      scanType: createForm.scanType,
      scanPaths,
      hostIds: createForm.hostIds,
    })
    message.success('扫描任务创建成功')
    createVisible.value = false
    loadTasks()
    loadStatistics()
  } catch {
    // 全局拦截器已处理
  } finally {
    createLoading.value = false
  }
}

const handleCancelTask = async (task: AntivirusScanTask) => {
  try {
    await antivirusApi.cancelTask(task.id)
    message.success('任务已取消')
    loadTasks()
    loadStatistics()
  } catch {
    // 全局拦截器已处理
  }
}

const handleDeleteTask = async (id: number) => {
  try {
    await antivirusApi.deleteTask(id)
    message.success('任务已删除')
    loadTasks()
    loadStatistics()
  } catch {
    // 全局拦截器已处理
  }
}

const showTaskDetail = async (task: AntivirusScanTask) => {
  try {
    taskDetail.value = await antivirusApi.getTask(task.id)
    taskDetailVisible.value = true
  } catch {
    // 全局拦截器已处理
  }
}

const viewTaskResults = (taskId: number) => {
  taskDetailVisible.value = false
  activeTab.value = 'results'
  resultFilterTaskId.value = taskId
  resultPagination.value.current = 1
  loadResults()
}

// === 结果操作 ===
const handleResultFilterChange = () => {
  resultFilterTaskId.value = undefined
  resultPagination.value.current = 1
  loadResults()
}

const handleResultTableChange = (pag: any) => {
  resultPagination.value.current = pag.current
  resultPagination.value.pageSize = pag.pageSize
  loadResults()
}

const handleResultReset = () => {
  resultSearch.value = ''
  resultFilterSeverity.value = undefined
  resultFilterThreatType.value = undefined
  resultFilterAction.value = undefined
  resultFilterTaskId.value = undefined
  resultPagination.value.current = 1
  loadResults()
}

const showResultDetail = async (record: AntivirusScanResult) => {
  try {
    resultDetail.value = await antivirusApi.getResult(record.id)
    resultDetailVisible.value = true
  } catch {
    // 全局拦截器已处理
  }
}

const handleQuarantine = async (id: number) => {
  try {
    await antivirusApi.quarantineResult(id)
    message.success('威胁已隔离')
    loadResults()
    loadStatistics()
  } catch {
    // 全局拦截器已处理
  }
}

const handleDeleteFile = async (id: number) => {
  try {
    await antivirusApi.deleteFileResult(id)
    message.success('威胁文件已删除')
    loadResults()
    loadStatistics()
  } catch {
    // 全局拦截器已处理
  }
}

const handleIgnore = async (id: number) => {
  try {
    await antivirusApi.ignoreResult(id)
    message.success('威胁已忽略')
    loadResults()
    loadStatistics()
  } catch {
    // 全局拦截器已处理
  }
}

// === 工具函数 ===
const formatFileSize = (bytes: number) => {
  if (!bytes || bytes === 0) return '-'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let size = bytes
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024
    i++
  }
  return `${size.toFixed(1)} ${units[i]}`
}

// === Tab 切换时加载数据 ===
watch(activeTab, (tab) => {
  router.replace({ query: { ...route.query, tab } })
  if (tab === 'tasks') loadTasks()
  else if (tab === 'results') loadResults()
})

// === 初始化 ===
onMounted(() => {
  loadStatistics()
  loadVirusDBStatus()
  if (activeTab.value === 'tasks') {
    loadTasks()
  } else {
    loadResults()
  }
})
</script>

<style scoped>
.virus-scan-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.stat-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: var(--mxsec-text-1);
}
.stat-value.critical { color: #EF4444; }
.stat-value.high { color: #F59E0B; }
.stat-value.primary { color: var(--mxsec-primary); }

.stat-label {
  margin-top: 8px;
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
}

.card-body { padding: 20px; }

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}

.filter-actions {
  display: flex;
  gap: 8px;
  margin-left: auto;
}

.db-status-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 12px 20px;
}

.db-status-left {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.db-status-label {
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.db-status-info {
  color: var(--mxsec-text-3);
  font-size: 13px;
}

.db-status-error {
  color: #EF4444;
  font-size: 13px;
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.db-status-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

@media (max-width: 960px) {
  .filter-actions { margin-left: 0; }
  .db-status-bar { flex-direction: column; gap: 8px; align-items: flex-start; }
}
</style>
