<template>
  <div class="rasp-config-page">
    <div class="page-header">
      <h2>RASP 配置</h2>
      <span class="page-header-hint">管理 RASP 探针的部署配置与防护规则</span>
    </div>

    <!-- 配置列表 -->
    <div class="dashboard-card">
      <div class="card-header">
        <span class="card-title">防护配置</span>
        <a-button type="primary" size="small" @click="showCreateModal = true">新建配置</a-button>
      </div>
      <div class="card-body">
        <a-table :columns="columns" :data-source="configs" :loading="loading" :pagination="pagination" @change="handleTableChange" size="middle" row-key="id">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'mode'">
              <a-tag :color="record.mode === 'block' ? 'red' : record.mode === 'monitor' ? 'blue' : 'default'" :bordered="false">{{ modeTextMap[record.mode] }}</a-tag>
            </template>
            <template v-if="column.key === 'status'">
              <a-switch :checked="record.status === 'enabled'" checked-children="启用" un-checked-children="禁用" @change="(checked: boolean) => handleToggle(record, checked)" />
            </template>
            <template v-if="column.key === 'rules'">
              <span>{{ record.enabledRules }}/{{ record.totalRules }} 条规则</span>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="handleEdit(record)">编辑</a-button>
                <a-popconfirm title="确定删除?" @confirm="handleDelete(record.id)"><a-button type="link" size="small" danger>删除</a-button></a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 防护规则模板 -->
    <div class="dashboard-card" style="margin-top: 16px">
      <div class="card-header">
        <span class="card-title">防护规则</span>
      </div>
      <div class="card-body">
        <a-table :columns="ruleColumns" :data-source="rules" :pagination="false" size="middle" row-key="id">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'category'">
              <a-tag :bordered="false" color="purple">{{ record.category }}</a-tag>
            </template>
            <template v-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity]" :bordered="false">{{ severityTextMap[record.severity] }}</a-tag>
            </template>
            <template v-if="column.key === 'defaultAction'">
              <a-tag :color="record.defaultAction === 'block' ? 'red' : 'blue'" :bordered="false">{{ record.defaultAction === 'block' ? '阻断' : '监控' }}</a-tag>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 新建/编辑 Modal -->
    <a-modal v-model:open="showCreateModal" :title="editingId ? '编辑配置' : '新建 RASP 配置'" :confirm-loading="submitLoading" width="560px" @ok="handleSubmit" @cancel="resetForm">
      <a-form :model="form" :rules="formRules" ref="formRef" layout="vertical">
        <a-form-item label="配置名称" name="name">
          <a-input v-model:value="form.name" placeholder="输入配置名称" />
        </a-form-item>
        <a-form-item label="防护模式" name="mode">
          <a-radio-group v-model:value="form.mode">
            <a-radio value="monitor">监控模式 (仅告警, 不阻断)</a-radio>
            <a-radio value="block">阻断模式 (检测到攻击立即阻断)</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="目标语言">
          <a-select v-model:value="form.languages" mode="multiple" placeholder="选择语言" style="width: 100%">
            <a-select-option value="java">Java</a-select-option>
            <a-select-option value="python">Python</a-select-option>
            <a-select-option value="nodejs">Node.js</a-select-option>
            <a-select-option value="php">PHP</a-select-option>
            <a-select-option value="golang">Go</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="适用主机">
          <a-radio-group v-model:value="form.scope">
            <a-radio value="all">全部主机</a-radio>
            <a-radio value="selected">指定主机</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="备注">
          <a-textarea v-model:value="form.remark" placeholder="配置说明" :rows="2" />
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

const loading = ref(false)
const configs = ref<any[]>([])
const rules = ref<any[]>([])

const pagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const modeTextMap: Record<string, string> = { block: '阻断模式', monitor: '监控模式', off: '已关闭' }
const severityColorMap: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityTextMap: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }

const columns = [
  { title: '配置名称', dataIndex: 'name', key: 'name', width: 200 },
  { title: '防护模式', key: 'mode', width: 120 },
  { title: '目标语言', dataIndex: 'languagesText', key: 'languagesText', width: 200 },
  { title: '防护规则', key: 'rules', width: 140 },
  { title: '关联应用', dataIndex: 'appCount', key: 'appCount', width: 100 },
  { title: '状态', key: 'status', width: 120 },
  { title: '更新时间', dataIndex: 'updatedAt', key: 'updatedAt', width: 180 },
  { title: '操作', key: 'action', width: 140 },
]

const ruleColumns = [
  { title: '规则名称', dataIndex: 'name', key: 'name', width: 200 },
  { title: '分类', key: 'category', width: 120 },
  { title: '级别', key: 'severity', width: 80 },
  { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
  { title: '默认动作', key: 'defaultAction', width: 100 },
]

const showCreateModal = ref(false)
const submitLoading = ref(false)
const editingId = ref<string>()
const formRef = ref<FormInstance>()
const form = ref({ name: '', mode: 'monitor', languages: [] as string[], scope: 'all', remark: '' })
const formRules = { name: [{ required: true, message: '请输入配置名称', trigger: 'blur' }], mode: [{ required: true, message: '请选择防护模式' }] }

const loadConfigs = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/rasp/configs', { params: { page: pagination.value.current, page_size: pagination.value.pageSize } })
    configs.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch { configs.value = [] }
  finally { loading.value = false }
}

const loadRules = async () => {
  try { const res = await apiClient.get<any>('/rasp/rules'); rules.value = res.items ?? [] }
  catch { rules.value = [] }
}

const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadConfigs() }
const handleToggle = async (record: any, checked: boolean) => { try { await apiClient.put(`/rasp/configs/${record.id}`, { status: checked ? 'enabled' : 'disabled' }); message.success('已更新'); loadConfigs() } catch { message.error('操作失败') } }

const handleEdit = (record: any) => {
  editingId.value = record.id
  form.value = { name: record.name, mode: record.mode, languages: record.languages ?? [], scope: record.scope ?? 'all', remark: record.remark ?? '' }
  showCreateModal.value = true
}

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()
    submitLoading.value = true
    if (editingId.value) { await apiClient.put(`/rasp/configs/${editingId.value}`, form.value); message.success('已更新') }
    else { await apiClient.post('/rasp/configs', form.value); message.success('已创建') }
    showCreateModal.value = false; resetForm(); loadConfigs()
  } catch (error: any) { if (!error?.errorFields) message.error('操作失败') }
  finally { submitLoading.value = false }
}

const handleDelete = async (id: string) => { try { await apiClient.delete(`/rasp/configs/${id}`); message.success('已删除'); loadConfigs() } catch { message.error('删除失败') } }
const resetForm = () => { editingId.value = undefined; form.value = { name: '', mode: 'monitor', languages: [], scope: 'all', remark: '' }; formRef.value?.resetFields() }

onMounted(() => { loadConfigs(); loadRules() })
</script>

<style scoped>
.rasp-config-page { width: 100%; }
.dashboard-card { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; }
.card-header { display: flex; align-items: center; justify-content: space-between; padding: 14px 20px; border-bottom: 1px solid #F2F3F5; }
.card-title { font-size: 14px; font-weight: 600; color: #1D2129; }
.card-body { padding: 20px; }
</style>
