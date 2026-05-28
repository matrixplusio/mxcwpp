<template>
  <div class="kube-baseline-rules-page">
    <div class="page-header">
      <h2>容器基线规则</h2>
      <span class="page-header-hint">Kubernetes CIS 基线检查规则管理</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="6">
        <div class="stat-card">
          <div class="stat-value">{{ stats.totalRules }}</div>
          <div class="stat-label">规则总数</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="stat-card">
          <div class="stat-value" style="color: #22C55E">{{ stats.enabled }}</div>
          <div class="stat-label">已启用</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="stat-card">
          <div class="stat-value" style="color: #86909C">{{ stats.disabled }}</div>
          <div class="stat-label">已禁用</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="stat-card">
          <div class="stat-value" style="color: #3B82F6">{{ stats.builtin }}</div>
          <div class="stat-label">内置规则</div>
        </div>
      </a-col>
    </a-row>

    <!-- 规则列表 -->
    <div class="dashboard-card">
      <div class="card-header">
        <span class="card-title">规则列表</span>
        <a-space>
          <a-button @click="handleExport">导出</a-button>
          <a-upload :before-upload="handleImportFile" :show-upload-list="false" accept=".json">
            <a-button>导入</a-button>
          </a-upload>
          <a-button type="primary" @click="handleAdd">新增规则</a-button>
        </a-space>
      </div>
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search v-model:value="searchText" placeholder="搜索规则" style="width: 220px" allow-clear @search="loadRules" />
          <a-select v-model:value="filterCategory" style="width: 160px" placeholder="分类" allow-clear @change="loadRules">
            <a-select-option value="RBAC">RBAC</a-select-option>
            <a-select-option value="Pod Security">Pod Security</a-select-option>
            <a-select-option value="Network">Network</a-select-option>
            <a-select-option value="Secrets & Config">Secrets & Config</a-select-option>
            <a-select-option value="Workload">Workload</a-select-option>
            <a-select-option value="Node">Node</a-select-option>
            <a-select-option value="Cluster Config">Cluster Config</a-select-option>
            <a-select-option value="Supply Chain">Supply Chain</a-select-option>
            <a-select-option value="Runtime">Runtime</a-select-option>
          </a-select>
          <a-select v-model:value="filterSeverity" style="width: 120px" placeholder="级别" allow-clear @change="loadRules">
            <a-select-option value="critical">紧急</a-select-option>
            <a-select-option value="high">高危</a-select-option>
            <a-select-option value="medium">中危</a-select-option>
            <a-select-option value="low">低危</a-select-option>
          </a-select>
          <a-select v-model:value="filterEnabled" style="width: 120px" placeholder="状态" allow-clear @change="loadRules">
            <a-select-option value="true">已启用</a-select-option>
            <a-select-option value="false">已禁用</a-select-option>
          </a-select>
        </div>

        <a-table
          :columns="columns"
          :data-source="rules"
          :loading="loading"
          :pagination="pagination"
          @change="handleTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'enabled'">
              <a-switch :checked="record.enabled" size="small" @change="handleToggle(record)" />
            </template>
            <template v-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity]" :bordered="false">{{ severityTextMap[record.severity] }}</a-tag>
            </template>
            <template v-if="column.key === 'builtin'">
              <a-tag v-if="record.builtin" color="blue" :bordered="false">内置</a-tag>
              <a-tag v-else color="default" :bordered="false">自定义</a-tag>
            </template>
            <template v-if="column.key === 'checkMethod'">
              <a-tag v-if="record.hasCheckFunc" color="green" :bordered="false">内置函数</a-tag>
              <a-tag v-else-if="record.hasCheckConfig" color="purple" :bordered="false">CEL 表达式</a-tag>
              <a-tag v-else color="default" :bordered="false">仅元数据</a-tag>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="handleEdit(record)">编辑</a-button>
                <a-popconfirm v-if="!record.builtin" title="确定删除此规则？" @confirm="handleDelete(record)">
                  <a-button type="link" size="small" danger>删除</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 编辑弹窗 -->
    <KubeBaselineRuleModal v-model:open="modalVisible" :edit-rule="editingRule" @saved="loadRules" />

    <!-- 导入确认弹窗 -->
    <a-modal v-model:open="importVisible" title="导入规则" @ok="confirmImport" :confirm-loading="importLoading">
      <p>即将导入 <strong>{{ importData.length }}</strong> 条规则。</p>
      <a-radio-group v-model:value="importMode">
        <a-radio value="skip">跳过已存在</a-radio>
        <a-radio value="update">覆盖已存在</a-radio>
      </a-radio-group>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { listRules, toggleRule, deleteRule, exportRules, importRules } from '@/api/kubeBaselineRules'
import type { KubeBaselineRule, KubeBaselineRuleStats } from '@/api/kubeBaselineRules'
import KubeBaselineRuleModal from './components/KubeBaselineRuleModal.vue'

const searchText = ref('')
const filterCategory = ref<string>()
const filterSeverity = ref<string>()
const filterEnabled = ref<string>()
const loading = ref(false)
const rules = ref<KubeBaselineRule[]>([])
const stats = ref<KubeBaselineRuleStats>({ totalRules: 0, enabled: 0, disabled: 0, builtin: 0 })
const modalVisible = ref(false)
const editingRule = ref<KubeBaselineRule | null>(null)

// 导入相关
const importVisible = ref(false)
const importLoading = ref(false)
const importMode = ref<'skip' | 'update'>('skip')
const importData = ref<unknown[]>([])

const pagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const severityColorMap: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityTextMap: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }

const columns = [
  { title: '启用', key: 'enabled', width: 70, align: 'center' as const },
  { title: '编号', dataIndex: 'checkId', key: 'checkId', width: 120 },
  { title: '名称', dataIndex: 'checkName', key: 'checkName', ellipsis: true },
  { title: '分类', dataIndex: 'category', key: 'category', width: 130 },
  { title: '级别', key: 'severity', width: 80 },
  { title: '类型', key: 'builtin', width: 80 },
  { title: '检查方式', key: 'checkMethod', width: 100 },
  { title: '操作', key: 'action', width: 120 },
]

const loadRules = async () => {
  loading.value = true
  try {
    const res = await listRules({
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      keyword: searchText.value || undefined,
      category: filterCategory.value || undefined,
      severity: filterSeverity.value || undefined,
      enabled: filterEnabled.value || undefined,
    })
    rules.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    if (res.stats) stats.value = res.stats
  } catch {
    rules.value = []
  } finally {
    loading.value = false
  }
}

const handleTableChange = (pag: { current?: number; pageSize?: number }) => {
  pagination.value.current = pag.current ?? 1
  pagination.value.pageSize = pag.pageSize ?? 20
  loadRules()
}

const handleAdd = () => {
  editingRule.value = null
  modalVisible.value = true
}

const handleEdit = (record: KubeBaselineRule) => {
  editingRule.value = record
  modalVisible.value = true
}

const handleToggle = async (record: KubeBaselineRule) => {
  try {
    await toggleRule(record.id)
    loadRules()
  } catch { /* handled */ }
}

const handleDelete = async (record: KubeBaselineRule) => {
  try {
    await deleteRule(record.id)
    message.success('规则已删除')
    loadRules()
  } catch { /* handled */ }
}

const handleExport = async () => {
  try {
    const blob = await exportRules()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'kube_baseline_rules.json'
    a.click()
    URL.revokeObjectURL(url)
    message.success('导出成功')
  } catch { /* handled */ }
}

const handleImportFile = (file: File) => {
  const reader = new FileReader()
  reader.onload = (e) => {
    try {
      const data = JSON.parse(e.target?.result as string)
      if (!Array.isArray(data)) {
        message.error('JSON 文件格式错误，需要数组格式')
        return
      }
      importData.value = data
      importMode.value = 'skip'
      importVisible.value = true
    } catch {
      message.error('JSON 文件解析失败')
    }
  }
  reader.readAsText(file)
  return false
}

const confirmImport = async () => {
  importLoading.value = true
  try {
    const result = await importRules(importData.value, importMode.value)
    message.success(`导入完成：新增 ${result.created}，更新 ${result.updated}，跳过 ${result.skipped}`)
    importVisible.value = false
    loadRules()
  } catch { /* handled */ }
  finally { importLoading.value = false }
}

onMounted(() => { loadRules() })
</script>

<style scoped>
.kube-baseline-rules-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.stat-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; padding: 20px; text-align: center; }
.stat-value { font-size: 28px; font-weight: 700; color: var(--mxsec-text-1); line-height: 1.2; }
.stat-label { font-size: 13px; color: var(--mxsec-text-3); margin-top: 4px; }

.dashboard-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; }
.card-header { display: flex; align-items: center; justify-content: space-between; padding: 14px 20px; border-bottom: 1px solid var(--mxsec-border-light); }
.card-title { font-size: 14px; font-weight: 600; color: var(--mxsec-text-1); }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 16px; padding: 12px 16px; background: var(--mxsec-fill-1); border-radius: 4px; border: 1px solid var(--mxsec-border); }
</style>
