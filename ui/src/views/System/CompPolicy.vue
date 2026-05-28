<template>
  <div class="comp-policy-page">
    <div class="page-header">
      <h2>组件策略</h2>
      <span class="page-header-hint">管理 Agent 组件版本分发与升级策略</span>
    </div>

    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search
            v-model:value="searchText"
            placeholder="搜索策略名称"
            style="width: 240px"
            allow-clear
            @search="loadPolicies"
          />
          <a-select v-model:value="filterComponent" style="width: 160px" placeholder="组件类型" allow-clear @change="loadPolicies">
            <a-select-option value="agent">Agent</a-select-option>
            <a-select-option value="baseline">Baseline 插件</a-select-option>
            <a-select-option value="collector">Collector 插件</a-select-option>
            <a-select-option value="fim">FIM 插件</a-select-option>
            <a-select-option value="scanner">Scanner 插件</a-select-option>
            <a-select-option value="remediation">Remediation 插件</a-select-option>
          </a-select>
          <a-select v-model:value="filterStatus" style="width: 120px" placeholder="状态" allow-clear @change="loadPolicies">
            <a-select-option value="enabled">启用</a-select-option>
            <a-select-option value="disabled">禁用</a-select-option>
          </a-select>
          <div style="flex: 1"></div>
          <a-button type="primary" @click="showCreateModal = true">新建策略</a-button>
        </div>

        <a-table
          :columns="columns"
          :data-source="policies"
          :loading="loading"
          :pagination="pagination"
          @change="handleTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'component'">
              <a-tag :bordered="false">{{ record.componentName }}</a-tag>
            </template>
            <template v-if="column.key === 'status'">
              <a-switch
                :checked="record.status === 'enabled'"
                checked-children="启用"
                un-checked-children="禁用"
                @change="(checked: boolean) => handleToggle(record, checked)"
              />
            </template>
            <template v-if="column.key === 'scope'">
              <span v-if="record.scope === 'all'">全部主机</span>
              <span v-else>{{ record.hostCount }} 台主机</span>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="handleEdit(record)">编辑</a-button>
                <a-popconfirm title="确定删除该策略?" @confirm="handleDelete(record.id)">
                  <a-button type="link" size="small" danger>删除</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 新建/编辑 Modal -->
    <a-modal
      v-model:open="showCreateModal"
      :title="editingId ? '编辑组件策略' : '新建组件策略'"
      :confirm-loading="submitLoading"
      width="560px"
      @ok="handleSubmit"
      @cancel="resetForm"
    >
      <a-form :model="form" :rules="formRules" ref="formRef" layout="vertical">
        <a-form-item label="策略名称" name="name">
          <a-input v-model:value="form.name" placeholder="输入策略名称" />
        </a-form-item>
        <a-form-item label="组件" name="componentType">
          <a-select v-model:value="form.componentType" placeholder="选择组件">
            <a-select-option value="agent">Agent</a-select-option>
            <a-select-option value="baseline">Baseline 插件</a-select-option>
            <a-select-option value="collector">Collector 插件</a-select-option>
            <a-select-option value="fim">FIM 插件</a-select-option>
            <a-select-option value="scanner">Scanner 插件</a-select-option>
            <a-select-option value="remediation">Remediation 插件</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="目标版本" name="targetVersion">
          <a-input v-model:value="form.targetVersion" placeholder="例: 1.2.0" />
        </a-form-item>
        <a-form-item label="分发范围">
          <a-radio-group v-model:value="form.scope">
            <a-radio value="all">全部主机</a-radio>
            <a-radio value="selected">指定主机</a-radio>
            <a-radio value="business_line">按业务线</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="升级策略">
          <a-radio-group v-model:value="form.strategy">
            <a-radio value="immediate">立即执行</a-radio>
            <a-radio value="rolling">滚动升级 (分批)</a-radio>
            <a-radio value="canary">灰度发布</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="灰度比例" v-if="form.strategy === 'canary'">
          <a-slider v-model:value="form.canaryPercent" :min="1" :max="100" :marks="{ 1: '1%', 25: '25%', 50: '50%', 100: '100%' }" />
        </a-form-item>
        <a-form-item label="备注">
          <a-textarea v-model:value="form.remark" placeholder="备注说明" :rows="2" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import type { FormInstance } from 'ant-design-vue'
import { message } from 'ant-design-vue'
import apiClient from '@/api/client'

const searchText = ref('')
const filterComponent = ref<string>()
const filterStatus = ref<string>()
const loading = ref(false)
const policies = ref<any[]>([])

const pagination = ref({
  current: 1, pageSize: 20, total: 0, showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  { title: '策略名称', dataIndex: 'name', key: 'name', width: 200 },
  { title: '组件', key: 'component', width: 140 },
  { title: '目标版本', dataIndex: 'targetVersion', key: 'targetVersion', width: 120 },
  { title: '升级策略', dataIndex: 'strategyText', key: 'strategyText', width: 120 },
  { title: '范围', key: 'scope', width: 120 },
  { title: '状态', key: 'status', width: 120 },
  { title: '创建时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
  { title: '操作', key: 'action', width: 140 },
]

const showCreateModal = ref(false)
const submitLoading = ref(false)
const editingId = ref<string>()
const formRef = ref<FormInstance>()
const form = ref({
  name: '', componentType: '', targetVersion: '',
  scope: 'all', strategy: 'immediate', canaryPercent: 10, remark: '',
})
const formRules = {
  name: [{ required: true, message: '请输入策略名称', trigger: 'blur' }],
  componentType: [{ required: true, message: '请选择组件', trigger: 'change' }],
  targetVersion: [{ required: true, message: '请输入目标版本', trigger: 'blur' }],
}

const loadPolicies = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/system/comp-policies', {
      params: {
        page: pagination.value.current, page_size: pagination.value.pageSize,
        search: searchText.value || undefined,
        component: filterComponent.value || undefined,
        status: filterStatus.value || undefined,
      },
    })
    policies.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch { policies.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadPolicies() }

const handleToggle = async (record: any, checked: boolean) => {
  try {
    await apiClient.put(`/system/comp-policies/${record.id}`, { status: checked ? 'enabled' : 'disabled' })
    message.success('状态已更新')
    loadPolicies()
  } catch { message.error('操作失败') }
}

const handleEdit = (record: any) => {
  editingId.value = record.id
  form.value = { name: record.name, componentType: record.componentType, targetVersion: record.targetVersion, scope: record.scope, strategy: record.strategy, canaryPercent: record.canaryPercent ?? 10, remark: record.remark ?? '' }
  showCreateModal.value = true
}

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()
    submitLoading.value = true
    if (editingId.value) {
      await apiClient.put(`/system/comp-policies/${editingId.value}`, form.value)
      message.success('策略已更新')
    } else {
      await apiClient.post('/system/comp-policies', form.value)
      message.success('策略已创建')
    }
    showCreateModal.value = false
    resetForm()
    loadPolicies()
  } catch (error: any) {
    if (!error?.errorFields) message.error('操作失败')
  } finally { submitLoading.value = false }
}

const handleDelete = async (id: string) => {
  try { await apiClient.delete(`/system/comp-policies/${id}`); message.success('已删除'); loadPolicies() }
  catch { message.error('删除失败') }
}

const resetForm = () => {
  editingId.value = undefined
  form.value = { name: '', componentType: '', targetVersion: '', scope: 'all', strategy: 'immediate', canaryPercent: 10, remark: '' }
  formRef.value?.resetFields()
}

onMounted(() => { loadPolicies() })
</script>

<style scoped>
.comp-policy-page { width: 100%; }

.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
}
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
