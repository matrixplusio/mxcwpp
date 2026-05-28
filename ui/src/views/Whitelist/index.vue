<template>
  <div class="whitelist-page">
    <div class="page-header">
      <h2>告警白名单</h2>
      <span class="page-header-hint">命中白名单的告警将自动跳过，不写入告警记录</span>
    </div>

    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search
            v-model:value="keyword"
            placeholder="搜索名称或原因"
            style="width: 280px"
            allow-clear
            @search="loadList"
          />
          <div style="flex: 1"></div>
          <a-button type="primary" @click="openCreate">新建白名单</a-button>
        </div>

        <a-table
          :columns="columns"
          :data-source="items"
          :loading="loading"
          :pagination="pagination"
          row-key="id"
          @change="handleTableChange"
          size="middle"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'rule_id'">
              <span>{{ record.rule_id || '*' }}</span>
            </template>
            <template v-else-if="column.key === 'host_id'">
              <span>{{ record.host_id || '*' }}</span>
            </template>
            <template v-else-if="column.key === 'category'">
              <span>{{ record.category || '*' }}</span>
            </template>
            <template v-else-if="column.key === 'severity'">
              <a-tag v-if="record.severity" :color="severityColor[record.severity]">
                {{ severityText[record.severity] || record.severity }}
              </a-tag>
              <span v-else>*（全部）</span>
            </template>
            <template v-else-if="column.key === 'actions'">
              <a-space>
                <a-button type="link" size="small" @click="openEdit(record)">编辑</a-button>
                <a-popconfirm title="确定删除该白名单条目?" @confirm="handleDelete(record.id)">
                  <a-button type="link" size="small" danger>删除</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 新建/编辑弹窗 -->
    <a-modal
      v-model:open="modalVisible"
      :title="editingId ? '编辑白名单' : '新建白名单'"
      :confirm-loading="submitLoading"
      width="560px"
      @ok="handleSubmit"
      @cancel="closeModal"
    >
      <a-form :model="form" :rules="formRules" ref="formRef" :label-col="{ span: 5 }" :wrapper-col="{ span: 19 }">
        <a-form-item label="名称" name="name">
          <a-input v-model:value="form.name" placeholder="描述该条白名单的用途" />
        </a-form-item>

        <a-divider orientation="left" style="font-size: 13px; color: #86909C;">匹配条件（空或不填表示匹配所有）</a-divider>

        <a-form-item label="规则ID" name="rule_id">
          <a-input v-model:value="form.rule_id" placeholder="如 SSH_001，空则匹配所有规则" allow-clear />
        </a-form-item>
        <a-form-item label="主机ID" name="host_id">
          <a-input v-model:value="form.host_id" placeholder="主机 Agent ID，空则匹配所有主机" allow-clear />
        </a-form-item>
        <a-form-item label="类别" name="category">
          <a-select v-model:value="form.category" placeholder="空则匹配所有类别" allow-clear>
            <a-select-option value="ssh">SSH</a-select-option>
            <a-select-option value="password">密码策略</a-select-option>
            <a-select-option value="file_permission">文件权限</a-select-option>
            <a-select-option value="sysctl">内核参数</a-select-option>
            <a-select-option value="service">服务状态</a-select-option>
            <a-select-option value="agent_offline">Agent 离线</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="严重级别" name="severity">
          <a-select v-model:value="form.severity" placeholder="空则匹配所有级别" allow-clear>
            <a-select-option value="critical">严重</a-select-option>
            <a-select-option value="high">高危</a-select-option>
            <a-select-option value="medium">中危</a-select-option>
            <a-select-option value="low">低危</a-select-option>
          </a-select>
        </a-form-item>

        <a-divider />

        <a-form-item label="原因" name="reason">
          <a-textarea v-model:value="form.reason" placeholder="加入白名单的原因（可选）" :rows="3" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import type { FormInstance } from 'ant-design-vue'
import { message } from 'ant-design-vue'
import { alertWhitelistApi, type AlertWhitelist } from '@/api/alerts'

const keyword = ref('')
const loading = ref(false)
const items = ref<AlertWhitelist[]>([])
const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const severityColor: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'blue',
}
const severityText: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const columns = [
  { title: '名称', dataIndex: 'name', key: 'name', width: 180 },
  { title: '规则ID', key: 'rule_id', width: 140 },
  { title: '主机ID', key: 'host_id', width: 160, ellipsis: true },
  { title: '类别', key: 'category', width: 120 },
  { title: '级别', key: 'severity', width: 120 },
  { title: '原因', dataIndex: 'reason', key: 'reason', ellipsis: true },
  { title: '操作', key: 'actions', width: 120, fixed: 'right' },
]

const modalVisible = ref(false)
const submitLoading = ref(false)
const editingId = ref<number>()
const formRef = ref<FormInstance>()
const form = ref({
  name: '',
  rule_id: '',
  host_id: '',
  category: undefined as string | undefined,
  severity: undefined as string | undefined,
  reason: '',
})
const formRules = {
  name: [{ required: true, message: '请输入名称', trigger: 'blur' }],
}

const loadList = async () => {
  loading.value = true
  try {
    const res = await alertWhitelistApi.list({
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      keyword: keyword.value || undefined,
    })
    items.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch {
    items.value = []
  } finally {
    loading.value = false
  }
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadList()
}

const openCreate = () => {
  editingId.value = undefined
  form.value = { name: '', rule_id: '', host_id: '', category: undefined, severity: undefined, reason: '' }
  modalVisible.value = true
}

const openEdit = (record: AlertWhitelist) => {
  editingId.value = record.id
  form.value = {
    name: record.name,
    rule_id: record.rule_id || '',
    host_id: record.host_id || '',
    category: record.category || undefined,
    severity: record.severity || undefined,
    reason: record.reason || '',
  }
  modalVisible.value = true
}

const closeModal = () => {
  modalVisible.value = false
  formRef.value?.resetFields()
}

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()
    submitLoading.value = true
    const payload = {
      name: form.value.name,
      rule_id: form.value.rule_id || undefined,
      host_id: form.value.host_id || undefined,
      category: form.value.category || undefined,
      severity: form.value.severity || undefined,
      reason: form.value.reason || undefined,
    }
    if (editingId.value) {
      await alertWhitelistApi.update(editingId.value, payload)
      message.success('白名单已更新')
    } else {
      await alertWhitelistApi.create(payload)
      message.success('白名单已创建')
    }
    closeModal()
    loadList()
  } catch (error: any) {
    if (!error?.errorFields) {
      message.error('操作失败')
    }
  } finally {
    submitLoading.value = false
  }
}

const handleDelete = async (id: number) => {
  try {
    await alertWhitelistApi.delete(id)
    message.success('已删除')
    loadList()
  } catch {
    message.error('删除失败')
  }
}

onMounted(() => { loadList() })
</script>

<style scoped>
.whitelist-page { width: 100%; }

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
}
</style>
