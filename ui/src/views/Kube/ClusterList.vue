<template>
  <div class="kube-cluster-page">
    <div class="page-header">
      <h2>集群管理</h2>
      <span class="page-header-hint">管理和监控 Kubernetes 容器集群</span>
    </div>

    <!-- 概览统计 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="6" v-for="item in overviewStats" :key="item.key">
        <div class="stat-card-item">
          <div class="stat-card-icon" :style="{ background: item.gradient }">
            <component :is="item.icon" />
          </div>
          <div class="stat-card-value">{{ item.value }}</div>
          <div class="stat-card-label">{{ item.label }}</div>
        </div>
      </a-col>
    </a-row>

    <!-- 集群列表 -->
    <div class="dashboard-card">
      <div class="card-header">
        <span class="card-title">集群列表</span>
        <a-button type="primary" size="small" @click="showAddModal = true">接入集群</a-button>
      </div>
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search
            v-model:value="searchText"
            placeholder="搜索集群名称"
            style="width: 240px"
            allow-clear
            @search="loadClusters"
          />
          <a-select v-model:value="filterStatus" style="width: 140px" placeholder="集群状态" allow-clear @change="loadClusters">
            <a-select-option value="running">运行中</a-select-option>
            <a-select-option value="warning">异常</a-select-option>
            <a-select-option value="offline">离线</a-select-option>
          </a-select>
        </div>

        <a-table
          :columns="columns"
          :data-source="clusters"
          :loading="loading"
          :pagination="pagination"
          @change="handleTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'name'">
              <a @click="$router.push(`/kube/clusters/${record.id}`)">{{ record.name }}</a>
            </template>
            <template v-if="column.key === 'status'">
              <span class="status-dot" :class="`dot-${record.status}`"></span>
              {{ statusTextMap[record.status] }}
            </template>
            <template v-if="column.key === 'version'">
              <a-tag :bordered="false">{{ record.version }}</a-tag>
            </template>
            <template v-if="column.key === 'health'">
              <a-progress
                :percent="record.healthScore"
                :size="6"
                :stroke-color="record.healthScore >= 90 ? '#22C55E' : record.healthScore >= 70 ? '#F59E0B' : '#EF4444'"
              />
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="$router.push(`/kube/clusters/${record.id}`)">详情</a-button>
                <a-button type="link" size="small" @click="handleEditCluster(record)">编辑</a-button>
                <a-popconfirm title="确定移除该集群?" @confirm="handleDelete(record.id)">
                  <a-button type="link" size="small" danger>移除</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 接入集群 Modal -->
    <a-modal
      v-model:open="showAddModal"
      :title="editingId ? '编辑集群' : '接入 Kubernetes 集群'"
      :confirm-loading="submitLoading"
      width="640px"
      @ok="handleSubmit"
      @cancel="resetForm"
    >
      <a-form :model="form" :rules="formRules" ref="formRef" layout="vertical">
        <a-form-item label="集群名称" name="name">
          <a-input v-model:value="form.name" placeholder="输入集群显示名称" />
        </a-form-item>
        <a-form-item label="API Server 地址" name="apiServer">
          <a-input v-model:value="form.apiServer" placeholder="https://10.0.0.1:6443" />
        </a-form-item>
        <a-form-item label="KubeConfig" name="kubeConfig">
          <a-textarea v-model:value="form.kubeConfig" placeholder="粘贴 KubeConfig 内容 (YAML)" :rows="8" />
        </a-form-item>
        <a-form-item label="备注">
          <a-input v-model:value="form.remark" placeholder="集群用途说明 (可选)" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 创建成功后展示 Webhook 配置 -->
    <a-modal
      v-model:open="showWebhookModal"
      title="集群接入成功 - Webhook 配置"
      :footer="null"
      width="640px"
      @cancel="showWebhookModal = false"
    >
      <a-alert type="success" message="集群已成功接入，请配置 Audit Webhook 以启用安全告警。" show-icon style="margin-bottom: 16px" />
      <div class="webhook-info-field">
        <span class="webhook-info-label">Webhook URL</span>
        <div class="webhook-info-value">
          <code class="webhook-info-code">{{ createdWebhookURL }}</code>
          <a-button type="link" size="small" @click="copyText(createdWebhookURL, 'Webhook URL')"><CopyOutlined /></a-button>
        </div>
      </div>
      <div class="webhook-info-field">
        <span class="webhook-info-label">Audit Token</span>
        <div class="webhook-info-value">
          <code class="webhook-info-code">{{ createdAuditToken }}</code>
          <a-button type="link" size="small" @click="copyText(createdAuditToken, 'Audit Token')"><CopyOutlined /></a-button>
        </div>
      </div>
      <a-alert type="warning" style="margin-top: 12px">
        <template #message>请妥善保存以上信息。Token 可在集群详情页查看和重新生成。</template>
      </a-alert>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import {
  CloudServerOutlined,
  ClusterOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  CopyOutlined,
} from '@ant-design/icons-vue'
import type { FormInstance } from 'ant-design-vue'
import { message } from 'ant-design-vue'
import apiClient from '@/api/client'

const searchText = ref('')
const filterStatus = ref<string>()
const loading = ref(false)
const clusters = ref<any[]>([])
const showWebhookModal = ref(false)
const createdWebhookURL = ref('')
const createdAuditToken = ref('')

const pagination = ref({
  current: 1, pageSize: 20, total: 0, showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const stats = ref({ total: 0, running: 0, nodes: 0, pods: 0 })

const statusTextMap: Record<string, string> = {
  running: '运行中', warning: '异常', offline: '离线',
}

const overviewStats = computed(() => [
  { key: 'clusters', label: '集群总数', value: stats.value.total, icon: CloudServerOutlined, gradient: 'linear-gradient(135deg, #722ED1, #531DAB)' },
  { key: 'running', label: '运行中', value: stats.value.running, icon: CheckCircleOutlined, gradient: 'linear-gradient(135deg, #22C55E, #009A29)' },
  { key: 'nodes', label: 'Node 节点', value: stats.value.nodes, icon: ClusterOutlined, gradient: 'linear-gradient(135deg, #3B82F6, #2563EB)' },
  { key: 'pods', label: 'Pod 总数', value: stats.value.pods, icon: WarningOutlined, gradient: 'linear-gradient(135deg, #F59E0B, #D25F00)' },
])

const columns = [
  { title: '集群名称', key: 'name', width: 200 },
  { title: '状态', key: 'status', width: 120 },
  { title: 'K8s 版本', key: 'version', width: 120 },
  { title: 'Node 数', dataIndex: 'nodeCount', key: 'nodeCount', width: 100 },
  { title: 'Pod 数', dataIndex: 'podCount', key: 'podCount', width: 100 },
  { title: 'Namespace', dataIndex: 'namespaceCount', key: 'namespaceCount', width: 110 },
  { title: '健康度', key: 'health', width: 160 },
  { title: 'API Server', dataIndex: 'apiServer', key: 'apiServer', ellipsis: true },
  { title: '接入时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
  { title: '操作', key: 'action', width: 180 },
]

// Modal
const showAddModal = ref(false)
const submitLoading = ref(false)
const editingId = ref<string>()
const formRef = ref<FormInstance>()
const form = ref({ name: '', apiServer: '', kubeConfig: '', remark: '' })
const formRules = {
  name: [{ required: true, message: '请输入集群名称', trigger: 'blur' }],
  apiServer: [{ required: true, message: '请输入 API Server 地址', trigger: 'blur' }],
  kubeConfig: [{ required: true, message: '请粘贴 KubeConfig', trigger: 'blur' }],
}

const loadClusters = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/kube/clusters', {
      params: {
        page: pagination.value.current, page_size: pagination.value.pageSize,
        search: searchText.value || undefined,
        status: filterStatus.value || undefined,
      },
    })
    clusters.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    if (res.stats) stats.value = res.stats
  } catch { clusters.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadClusters() }

const handleEditCluster = (record: any) => {
  editingId.value = record.id
  form.value = { name: record.name, apiServer: record.apiServer, kubeConfig: '', remark: record.remark || '' }
  showAddModal.value = true
}

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()
    submitLoading.value = true
    if (editingId.value) {
      await apiClient.put(`/kube/clusters/${editingId.value}`, form.value)
      message.success('集群已更新')
    } else {
      const res = await apiClient.post<any>('/kube/clusters', form.value)
      message.success('集群接入成功')
      // 展示 webhook 配置信息
      if (res?.auditToken) {
        createdAuditToken.value = res.auditToken
        createdWebhookURL.value = res.webhookURL || ''
        showWebhookModal.value = true
      }
    }
    showAddModal.value = false
    resetForm()
    loadClusters()
  } catch (error: any) {
    if (!error?.errorFields) message.error('操作失败')
  } finally { submitLoading.value = false }
}

const handleDelete = async (id: string) => {
  try { await apiClient.delete(`/kube/clusters/${id}`); message.success('集群已移除'); loadClusters() }
  catch { message.error('移除失败') }
}

const resetForm = () => {
  editingId.value = undefined
  form.value = { name: '', apiServer: '', kubeConfig: '', remark: '' }
  formRef.value?.resetFields()
}

const copyText = async (text: string, label: string) => {
  try {
    await navigator.clipboard.writeText(text)
    message.success(`${label} 已复制到剪贴板`)
  } catch {
    const textArea = document.createElement('textarea')
    textArea.value = text
    textArea.style.position = 'fixed'
    textArea.style.opacity = '0'
    document.body.appendChild(textArea)
    textArea.select()
    try { document.execCommand('copy'); message.success(`${label} 已复制到剪贴板`) }
    catch { message.error('复制失败，请手动复制') }
    document.body.removeChild(textArea)
  }
}

onMounted(() => { loadClusters() })
</script>

<style scoped>
.kube-cluster-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.stat-card-item {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.2s;
}
.stat-card-item:hover { border-color: var(--mxsec-primary); }
.stat-card-icon {
  width: 40px; height: 40px; border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  color: var(--mxsec-card-bg); font-size: 18px; margin: 0 auto 12px;
}
.stat-card-value { font-size: 28px; font-weight: 700; color: var(--mxsec-text-1); line-height: 1.2; }
.stat-card-label { font-size: 13px; color: var(--mxsec-text-3); margin-top: 4px; }

.dashboard-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; }
.card-header { display: flex; align-items: center; justify-content: space-between; padding: 14px 20px; border-bottom: 1px solid var(--mxsec-border-light); }
.card-title { font-size: 14px; font-weight: 600; color: var(--mxsec-text-1); }
.card-body { padding: 20px; }

.filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 16px; padding: 12px 16px; background: var(--mxsec-fill-1); border-radius: 4px; border: 1px solid var(--mxsec-border); }

.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.dot-running { background: #22C55E; box-shadow: 0 0 0 3px rgba(0,180,42,0.15); }
.dot-warning { background: #F59E0B; box-shadow: 0 0 0 3px rgba(255,125,0,0.15); }
.dot-offline { background: #EF4444; box-shadow: 0 0 0 3px rgba(245,63,63,0.15); }

.webhook-info-field { margin-bottom: 12px; }
.webhook-info-label { display: block; font-size: 12px; color: var(--mxsec-text-3); margin-bottom: 4px; }
.webhook-info-value { display: flex; align-items: center; gap: 4px; }
.webhook-info-code { background: var(--mxsec-fill-1); border: 1px solid var(--mxsec-border); border-radius: 4px; padding: 6px 10px; font-size: 12px; color: var(--mxsec-text-1); word-break: break-all; flex: 1; }
</style>
