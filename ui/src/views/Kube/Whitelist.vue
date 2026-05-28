<template>
  <div class="kube-whitelist-page">
    <div class="page-header">
      <h2>容器告警白名单</h2>
      <span class="page-header-hint">管理 Kubernetes 集群安全告警白名单规则</span>
    </div>

    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search v-model:value="searchText" placeholder="搜索规则名称" style="width: 240px" allow-clear @search="loadWhitelist" />
          <a-select v-model:value="filterCluster" style="width: 180px" placeholder="集群" allow-clear @change="loadWhitelist">
            <a-select-option v-for="c in clusterOptions" :key="c.value" :value="c.value">{{ c.label }}</a-select-option>
          </a-select>
          <div style="flex: 1"></div>
          <a-button type="primary" @click="showCreateModal = true">新建白名单</a-button>
        </div>

        <a-table :columns="columns" :data-source="whitelist" :loading="loading" :pagination="pagination" @change="handleTableChange" size="middle" row-key="id">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'status'">
              <a-switch :checked="record.status === 'enabled'" checked-children="启用" un-checked-children="禁用" @change="(checked: boolean) => handleToggle(record, checked)" />
            </template>
            <template v-if="column.key === 'scope'">
              <a-tag v-if="record.clusterName" :bordered="false" color="purple">{{ record.clusterName }}</a-tag>
              <span v-else>全部集群</span>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="handleEdit(record)">编辑</a-button>
                <a-popconfirm title="确定删除?" @confirm="handleDelete(record.id)">
                  <a-button type="link" size="small" danger>删除</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 新建/编辑 Modal -->
    <a-modal v-model:open="showCreateModal" :title="editingId ? '编辑白名单' : '新建白名单'" :confirm-loading="submitLoading" width="560px" @ok="handleSubmit" @cancel="resetForm">
      <a-form :model="form" :rules="formRules" ref="formRef" layout="vertical">
        <a-form-item label="规则名称" name="name">
          <a-input v-model:value="form.name" placeholder="输入规则名称" />
        </a-form-item>
        <a-form-item label="适用集群">
          <a-select v-model:value="form.clusterId" style="width: 100%" placeholder="全部集群" allow-clear>
            <a-select-option v-for="c in clusterOptions" :key="c.value" :value="c.value">{{ c.label }}</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="告警类型">
          <a-select v-model:value="form.alarmTypes" mode="multiple" placeholder="选择告警类型" style="width: 100%">
            <a-select-option value="container_escape">容器逃逸</a-select-option>
            <a-select-option value="abnormal_process">异常进程</a-select-option>
            <a-select-option value="abnormal_network">异常网络</a-select-option>
            <a-select-option value="file_tamper">文件篡改</a-select-option>
            <a-select-option value="privilege_escalation">提权行为</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="匹配条件 (Namespace)">
          <a-input v-model:value="form.namespace" placeholder="匹配的 Namespace (支持通配符 *)" />
        </a-form-item>
        <a-form-item label="匹配条件 (Pod 名称)">
          <a-input v-model:value="form.podPattern" placeholder="匹配的 Pod 名称 (支持正则)" />
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
const filterCluster = ref<string>()
const loading = ref(false)
const whitelist = ref<any[]>([])
const clusterOptions = ref<any[]>([])

const pagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const columns = [
  { title: '规则名称', dataIndex: 'name', key: 'name', width: 200 },
  { title: '适用集群', key: 'scope', width: 160 },
  { title: '告警类型', dataIndex: 'alarmTypesText', key: 'alarmTypesText', ellipsis: true },
  { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 140 },
  { title: '匹配次数', dataIndex: 'hitCount', key: 'hitCount', width: 100 },
  { title: '状态', key: 'status', width: 120 },
  { title: '创建时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
  { title: '操作', key: 'action', width: 140 },
]

const showCreateModal = ref(false)
const submitLoading = ref(false)
const editingId = ref<string>()
const formRef = ref<FormInstance>()
const form = ref({ name: '', clusterId: undefined as string | undefined, alarmTypes: [] as string[], namespace: '', podPattern: '', remark: '' })
const formRules = { name: [{ required: true, message: '请输入规则名称', trigger: 'blur' }] }

const loadWhitelist = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/kube/whitelist', {
      params: { page: pagination.value.current, page_size: pagination.value.pageSize, search: searchText.value || undefined, cluster_id: filterCluster.value || undefined },
    })
    whitelist.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch { whitelist.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadWhitelist() }
const handleToggle = async (record: any, checked: boolean) => { try { await apiClient.put(`/kube/whitelist/${record.id}`, { status: checked ? 'enabled' : 'disabled' }); message.success('状态已更新'); loadWhitelist() } catch { message.error('操作失败') } }

const handleEdit = (record: any) => {
  editingId.value = record.id
  form.value = { name: record.name, clusterId: record.clusterId, alarmTypes: record.alarmTypes ?? [], namespace: record.namespace ?? '', podPattern: record.podPattern ?? '', remark: record.remark ?? '' }
  showCreateModal.value = true
}

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()
    submitLoading.value = true
    if (editingId.value) { await apiClient.put(`/kube/whitelist/${editingId.value}`, form.value); message.success('已更新') }
    else { await apiClient.post('/kube/whitelist', form.value); message.success('已创建') }
    showCreateModal.value = false; resetForm(); loadWhitelist()
  } catch (error: any) { if (!error?.errorFields) message.error('操作失败') }
  finally { submitLoading.value = false }
}

const handleDelete = async (id: string) => { try { await apiClient.delete(`/kube/whitelist/${id}`); message.success('已删除'); loadWhitelist() } catch { message.error('删除失败') } }

const resetForm = () => { editingId.value = undefined; form.value = { name: '', clusterId: undefined, alarmTypes: [], namespace: '', podPattern: '', remark: '' }; formRef.value?.resetFields() }

onMounted(() => { loadWhitelist() })
</script>

<style scoped>
.kube-whitelist-page { width: 100%; }
.dashboard-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 16px; padding: 12px 16px; background: var(--mxsec-fill-1); border-radius: 4px; border: 1px solid var(--mxsec-border); }
</style>
