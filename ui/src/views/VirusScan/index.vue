<template>
  <div class="virus-scan-page">
    <div class="page-header">
      <h2>病毒扫描</h2>
      <span class="page-header-hint">管理病毒扫描任务与查看扫描结果</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="6">
        <div class="scan-stat-card">
          <div class="scan-stat-value">{{ stats.totalScans }}</div>
          <div class="scan-stat-label">扫描总次数</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="scan-stat-card">
          <div class="scan-stat-value" style="color: #EF4444">{{ stats.threatsFound }}</div>
          <div class="scan-stat-label">发现威胁</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="scan-stat-card">
          <div class="scan-stat-value" style="color: #22C55E">{{ stats.cleaned }}</div>
          <div class="scan-stat-label">已清理</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="scan-stat-card">
          <div class="scan-stat-value" style="color: #F59E0B">{{ stats.quarantined }}</div>
          <div class="scan-stat-label">已隔离</div>
        </div>
      </a-col>
    </a-row>

    <!-- 扫描任务 -->
    <div class="dashboard-card section-row">
      <div class="card-header">
        <span class="card-title">扫描任务</span>
        <a-button type="primary" size="small" @click="showScanModal = true">新建扫描</a-button>
      </div>
      <div class="card-body">
        <a-table
          :columns="taskColumns"
          :data-source="tasks"
          :loading="taskLoading"
          :pagination="taskPagination"
          @change="handleTaskTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'status'">
              <a-tag :color="taskStatusColor[record.status]" :bordered="false">
                {{ taskStatusText[record.status] }}
              </a-tag>
            </template>
            <template v-if="column.key === 'progress'">
              <a-progress :percent="record.progress" :size="6" :status="record.status === 'failed' ? 'exception' : undefined" />
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="viewResults(record)">查看结果</a-button>
                <a-button type="link" size="small" danger @click="cancelTask(record)" v-if="record.status === 'running'">取消</a-button>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 扫描结果 -->
    <div class="dashboard-card">
      <div class="card-header">
        <span class="card-title">威胁检测记录</span>
      </div>
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search
            v-model:value="searchText"
            placeholder="搜索文件名或路径"
            style="width: 280px"
            allow-clear
            @search="loadResults"
          />
          <a-select v-model:value="filterThreatType" style="width: 140px" placeholder="威胁类型" allow-clear @change="loadResults">
            <a-select-option value="virus">病毒</a-select-option>
            <a-select-option value="trojan">木马</a-select-option>
            <a-select-option value="worm">蠕虫</a-select-option>
            <a-select-option value="ransomware">勒索</a-select-option>
            <a-select-option value="backdoor">后门</a-select-option>
          </a-select>
          <a-select v-model:value="filterAction" style="width: 140px" placeholder="处理状态" allow-clear @change="loadResults">
            <a-select-option value="pending">待处理</a-select-option>
            <a-select-option value="quarantined">已隔离</a-select-option>
            <a-select-option value="cleaned">已清理</a-select-option>
            <a-select-option value="ignored">已忽略</a-select-option>
          </a-select>
        </div>

        <a-table
          :columns="resultColumns"
          :data-source="results"
          :loading="resultLoading"
          :pagination="resultPagination"
          @change="handleResultTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'threatType'">
              <a-tag color="red" :bordered="false">{{ record.threatType }}</a-tag>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="quarantineFile(record)" v-if="record.actionStatus === 'pending'">隔离</a-button>
                <a-button type="link" size="small" @click="ignoreFile(record)" v-if="record.actionStatus === 'pending'">忽略</a-button>
              </a-space>
            </template>
            <template v-if="column.key === 'actionStatus'">
              <a-tag :color="actionStatusColor[record.actionStatus]" :bordered="false">
                {{ actionStatusText[record.actionStatus] }}
              </a-tag>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 新建扫描 Modal -->
    <a-modal
      v-model:open="showScanModal"
      title="新建病毒扫描"
      :confirm-loading="scanSubmitting"
      @ok="handleCreateScan"
    >
      <a-form :model="scanForm" layout="vertical">
        <a-form-item label="扫描范围">
          <a-radio-group v-model:value="scanForm.scope">
            <a-radio value="all">全部主机</a-radio>
            <a-radio value="selected">指定主机</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="选择主机" v-if="scanForm.scope === 'selected'">
          <a-select v-model:value="scanForm.hostIds" mode="multiple" placeholder="选择目标主机" style="width: 100%">
            <a-select-option v-for="h in hostOptions" :key="h.value" :value="h.value">{{ h.label }}</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="扫描路径">
          <a-input v-model:value="scanForm.scanPath" placeholder="默认: / (全盘扫描)" />
        </a-form-item>
        <a-form-item label="扫描深度">
          <a-select v-model:value="scanForm.depth">
            <a-select-option value="quick">快速扫描 (关键路径)</a-select-option>
            <a-select-option value="standard">标准扫描</a-select-option>
            <a-select-option value="deep">深度扫描 (全盘)</a-select-option>
          </a-select>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import apiClient from '@/api/client'

const searchText = ref('')
const filterThreatType = ref<string>()
const filterAction = ref<string>()
const taskLoading = ref(false)
const resultLoading = ref(false)
const tasks = ref<any[]>([])
const results = ref<any[]>([])
const hostOptions = ref<any[]>([])
const stats = ref({ totalScans: 0, threatsFound: 0, cleaned: 0, quarantined: 0 })

const taskPagination = ref({ current: 1, pageSize: 10, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })
const resultPagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const taskStatusColor: Record<string, string> = { pending: 'default', running: 'processing', completed: 'green', failed: 'red' }
const taskStatusText: Record<string, string> = { pending: '等待中', running: '进行中', completed: '已完成', failed: '失败' }
const actionStatusColor: Record<string, string> = { pending: 'orange', quarantined: 'blue', cleaned: 'green', ignored: 'default' }
const actionStatusText: Record<string, string> = { pending: '待处理', quarantined: '已隔离', cleaned: '已清理', ignored: '已忽略' }

const taskColumns = [
  { title: '任务 ID', dataIndex: 'id', key: 'id', width: 100 },
  { title: '扫描范围', dataIndex: 'scope', key: 'scope', width: 140 },
  { title: '目标主机数', dataIndex: 'hostCount', key: 'hostCount', width: 110 },
  { title: '进度', key: 'progress', width: 200 },
  { title: '发现威胁', dataIndex: 'threats', key: 'threats', width: 100 },
  { title: '状态', key: 'status', width: 100 },
  { title: '创建时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
  { title: '操作', key: 'action', width: 160 },
]

const resultColumns = [
  { title: '主机名', dataIndex: 'hostname', key: 'hostname', width: 160 },
  { title: '文件路径', dataIndex: 'filePath', key: 'filePath', ellipsis: true },
  { title: '威胁类型', key: 'threatType', width: 100 },
  { title: '威胁名称', dataIndex: 'threatName', key: 'threatName', width: 200 },
  { title: '处理状态', key: 'actionStatus', width: 100 },
  { title: '检测时间', dataIndex: 'detectedAt', key: 'detectedAt', width: 180 },
  { title: '操作', key: 'action', width: 130 },
]

// 新建扫描
const showScanModal = ref(false)
const scanSubmitting = ref(false)
const scanForm = ref({ scope: 'all', hostIds: [] as string[], scanPath: '', depth: 'quick' })

const loadTasks = async () => {
  taskLoading.value = true
  try {
    const res = await apiClient.get<any>('/virus/scan-tasks', {
      params: { page: taskPagination.value.current, page_size: taskPagination.value.pageSize },
    })
    tasks.value = res.items ?? []
    taskPagination.value.total = res.total ?? 0
    if (res.stats) stats.value = res.stats
  } catch { tasks.value = [] }
  finally { taskLoading.value = false }
}

const loadResults = async () => {
  resultLoading.value = true
  try {
    const res = await apiClient.get<any>('/virus/results', {
      params: {
        page: resultPagination.value.current,
        page_size: resultPagination.value.pageSize,
        search: searchText.value || undefined,
        threat_type: filterThreatType.value || undefined,
        action_status: filterAction.value || undefined,
      },
    })
    results.value = res.items ?? []
    resultPagination.value.total = res.total ?? 0
  } catch { results.value = [] }
  finally { resultLoading.value = false }
}

const handleTaskTableChange = (pag: any) => { taskPagination.value.current = pag.current; taskPagination.value.pageSize = pag.pageSize; loadTasks() }
const handleResultTableChange = (pag: any) => { resultPagination.value.current = pag.current; resultPagination.value.pageSize = pag.pageSize; loadResults() }

const viewResults = (_record: any) => {
  filterAction.value = undefined
  searchText.value = ''
  loadResults()
}

const cancelTask = async (record: any) => {
  try {
    await apiClient.post(`/virus/scan-tasks/${record.id}/cancel`)
    message.success('任务已取消')
    loadTasks()
  } catch (error) { console.error('取消扫描任务失败:', error) }
}

const quarantineFile = async (record: any) => {
  try {
    await apiClient.post(`/virus/results/${record.id}/quarantine`)
    message.success('文件已隔离')
    loadResults()
  } catch (error) { console.error('隔离文件失败:', error) }
}

const ignoreFile = async (record: any) => {
  try {
    await apiClient.post(`/virus/results/${record.id}/ignore`)
    message.success('已忽略')
    loadResults()
  } catch (error) { console.error('忽略文件失败:', error) }
}

const handleCreateScan = async () => {
  scanSubmitting.value = true
  try {
    await apiClient.post('/virus/scan-tasks', scanForm.value)
    message.success('扫描任务已创建')
    showScanModal.value = false
    scanForm.value = { scope: 'all', hostIds: [], scanPath: '', depth: 'quick' }
    loadTasks()
  } catch (error) { console.error('创建扫描任务失败:', error) }
  finally { scanSubmitting.value = false }
}

onMounted(() => { loadTasks(); loadResults() })
</script>

<style scoped>
.virus-scan-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.scan-stat-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}
.scan-stat-value { font-size: 28px; font-weight: 700; color: var(--mxsec-text-1); line-height: 1.2; }
.scan-stat-label { font-size: 13px; color: var(--mxsec-text-3); margin-top: 4px; }

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
.card-title { font-size: 14px; font-weight: 600; color: var(--mxsec-text-1); }
.card-body { padding: 20px; }

.filter-bar {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 16px;
  padding: 12px 16px;
  background: var(--mxsec-fill-1);
  border-radius: 4px;
  border: 1px solid var(--mxsec-border);
}
</style>
