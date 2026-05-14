<template>
  <div class="detection-rules-page">
    <!-- 统计卡片 -->
    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="6">
        <a-card>
          <a-statistic title="规则总数" :value="statistics.total" />
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card>
          <a-statistic title="已启用" :value="statistics.enabled" :value-style="{ color: '#3f8600' }" />
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card>
          <a-statistic title="已禁用" :value="statistics.disabled" :value-style="{ color: '#999' }" />
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card>
          <a-statistic title="高危规则" :value="(statistics.severity?.critical || 0) + (statistics.severity?.high || 0)" :value-style="{ color: '#cf1322' }" />
        </a-card>
      </a-col>
    </a-row>

    <!-- 操作栏 -->
    <a-card>
      <div style="display: flex; justify-content: space-between; margin-bottom: 16px">
        <a-space>
          <a-input-search v-model:value="filters.keyword" placeholder="搜索规则名称/描述" style="width: 250px" @search="fetchRules" />
          <a-select v-model:value="filters.severity" placeholder="严重级别" style="width: 120px" allowClear @change="fetchRules">
            <a-select-option value="critical">紧急</a-select-option>
            <a-select-option value="high">高危</a-select-option>
            <a-select-option value="medium">中危</a-select-option>
            <a-select-option value="low">低危</a-select-option>
          </a-select>
          <a-select v-model:value="filters.category" placeholder="分类" style="width: 140px" allowClear @change="fetchRules">
            <a-select-option v-for="cat in categories" :key="cat" :value="cat">{{ cat }}</a-select-option>
          </a-select>
          <a-select v-model:value="filters.enabled" placeholder="状态" style="width: 100px" allowClear @change="fetchRules">
            <a-select-option value="true">启用</a-select-option>
            <a-select-option value="false">禁用</a-select-option>
          </a-select>
        </a-space>
        <a-button type="primary" @click="showCreateModal">新建规则</a-button>
      </div>

      <!-- 规则表格 -->
      <a-table :columns="columns" :data-source="rules" :loading="loading" :pagination="pagination" row-key="id" @change="handleTableChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'severity'">
            <a-tag :color="severityColor(record.severity)">{{ severityLabel(record.severity) }}</a-tag>
          </template>
          <template v-if="column.key === 'enabled'">
            <a-switch :checked="record.enabled" size="small" @change="toggleRule(record)" />
          </template>
          <template v-if="column.key === 'mitreId'">
            <a-tag v-if="record.mitreId" color="blue">{{ record.mitreId }}</a-tag>
            <span v-else>-</span>
          </template>
          <template v-if="column.key === 'action'">
            <a-space>
              <a @click="showEditModal(record)">编辑</a>
              <a-popconfirm title="确定删除该规则？" @confirm="deleteRule(record.id)">
                <a style="color: #ff4d4f">删除</a>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 新建/编辑弹窗 -->
    <a-modal v-model:open="modalVisible" :title="editingRule ? '编辑规则' : '新建规则'" width="700px" @ok="handleSubmit" :confirmLoading="submitting">
      <a-form :model="form" layout="vertical">
        <a-form-item label="规则名称" required>
          <a-input v-model:value="form.name" placeholder="输入规则名称" />
        </a-form-item>
        <a-form-item label="CEL 表达式" required>
          <a-textarea v-model:value="form.expression" placeholder='例如: exe.contains("xmrig") || cmdline.contains("stratum+tcp")' :rows="3" />
        </a-form-item>
        <a-row :gutter="16">
          <a-col :span="8">
            <a-form-item label="严重级别" required>
              <a-select v-model:value="form.severity">
                <a-select-option value="critical">紧急</a-select-option>
                <a-select-option value="high">高危</a-select-option>
                <a-select-option value="medium">中危</a-select-option>
                <a-select-option value="low">低危</a-select-option>
              </a-select>
            </a-form-item>
          </a-col>
          <a-col :span="8">
            <a-form-item label="分类">
              <a-input v-model:value="form.category" placeholder="如：挖矿检测" />
            </a-form-item>
          </a-col>
          <a-col :span="8">
            <a-form-item label="MITRE ATT&CK">
              <a-input v-model:value="form.mitreId" placeholder="如：T1496" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item label="适用数据类型">
          <a-select v-model:value="form.dataTypes" mode="multiple" placeholder="选择适用的事件类型">
            <a-select-option value="3000">进程事件 (3000)</a-select-option>
            <a-select-option value="3001">文件事件 (3001)</a-select-option>
            <a-select-option value="3002">网络事件 (3002)</a-select-option>
            <a-select-option value="6001">FIM 事件 (6001)</a-select-option>
            <a-select-option value="7001">扫描结果 (7001)</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="描述">
          <a-textarea v-model:value="form.description" :rows="2" placeholder="规则说明" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { detectionRulesAPI, type DetectionRule, type DetectionRuleStatistics } from '@/api/detection-rules'

const loading = ref(false)
const submitting = ref(false)
const modalVisible = ref(false)
const editingRule = ref<DetectionRule | null>(null)

const rules = ref<DetectionRule[]>([])
const categories = ref<string[]>([])
const statistics = ref<DetectionRuleStatistics>({ total: 0, enabled: 0, disabled: 0, severity: {} })

const filters = reactive({
  keyword: '',
  severity: undefined as string | undefined,
  category: undefined as string | undefined,
  enabled: undefined as string | undefined,
})

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const form = reactive({
  name: '',
  expression: '',
  severity: 'medium',
  mitreId: '',
  category: '',
  description: '',
  dataTypes: [] as string[],
})

const columns = [
  { title: '规则名称', dataIndex: 'name', key: 'name', ellipsis: true, width: 200 },
  { title: '分类', dataIndex: 'category', key: 'category', width: 120 },
  { title: '严重级别', dataIndex: 'severity', key: 'severity', width: 100 },
  { title: 'MITRE', dataIndex: 'mitreId', key: 'mitreId', width: 100 },
  { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 80 },
  { title: '操作', key: 'action', width: 120 },
]

const severityColor = (s: string) => ({ critical: 'red', high: 'orange', medium: 'blue', low: 'green' }[s] || 'default')
const severityLabel = (s: string) => ({ critical: '紧急', high: '高危', medium: '中危', low: '低危' }[s] || s)

async function fetchRules() {
  loading.value = true
  try {
    const res = await detectionRulesAPI.list({
      page: pagination.current,
      page_size: pagination.pageSize,
      keyword: filters.keyword || undefined,
      severity: filters.severity,
      category: filters.category,
      enabled: filters.enabled,
    })
    rules.value = res.items || []
    pagination.total = res.total
  } catch {
    // handled by client
  } finally {
    loading.value = false
  }
}

async function fetchStatistics() {
  try {
    statistics.value = await detectionRulesAPI.getStatistics()
  } catch {
    // ignore
  }
}

async function fetchCategories() {
  try {
    categories.value = await detectionRulesAPI.getCategories()
  } catch {
    // ignore
  }
}

function handleTableChange(pag: any) {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  fetchRules()
}

function showCreateModal() {
  editingRule.value = null
  Object.assign(form, { name: '', expression: '', severity: 'medium', mitreId: '', category: '', description: '', dataTypes: [] })
  modalVisible.value = true
}

function showEditModal(rule: DetectionRule) {
  editingRule.value = rule
  Object.assign(form, {
    name: rule.name,
    expression: rule.expression,
    severity: rule.severity,
    mitreId: rule.mitreId || '',
    category: rule.category || '',
    description: rule.description || '',
    dataTypes: rule.dataTypes || [],
  })
  modalVisible.value = true
}

async function handleSubmit() {
  if (!form.name || !form.expression || !form.severity) {
    message.warning('请填写必填字段')
    return
  }
  submitting.value = true
  try {
    if (editingRule.value) {
      await detectionRulesAPI.update(editingRule.value.id, form)
      message.success('规则已更新')
    } else {
      await detectionRulesAPI.create(form)
      message.success('规则已创建')
    }
    modalVisible.value = false
    fetchRules()
    fetchStatistics()
  } catch {
    // handled by client
  } finally {
    submitting.value = false
  }
}

async function deleteRule(id: number) {
  try {
    await detectionRulesAPI.delete(id)
    message.success('规则已删除')
    fetchRules()
    fetchStatistics()
  } catch {
    // handled by client
  }
}

async function toggleRule(rule: DetectionRule) {
  try {
    await detectionRulesAPI.toggle(rule.id)
    fetchRules()
    fetchStatistics()
  } catch {
    // handled by client
  }
}

onMounted(() => {
  fetchRules()
  fetchStatistics()
  fetchCategories()
})
</script>
