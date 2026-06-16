<template>
  <div class="kube-detail-page">
    <div class="page-header" style="gap: 16px">
      <h2 style="white-space: nowrap">
        <a-button type="text" @click="$router.push('/kube/clusters')" style="margin-right: 8px; padding: 0">
          <LeftOutlined />
        </a-button>
        {{ cluster.name || '集群详情' }}
      </h2>
      <div style="display: flex; align-items: center; gap: 12px; flex-shrink: 0">
        <span class="status-dot" :class="`dot-${cluster.status}`"></span>
        <a-tag :color="statusColorMap[cluster.status]" :bordered="false">{{ statusTextMap[cluster.status] }}</a-tag>
        <span class="page-header-hint">K8s {{ cluster.version }}</span>
      </div>
    </div>

    <!-- 概览卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="4" v-for="item in summaryStats" :key="item.key">
        <div class="summary-card">
          <div class="summary-value" :style="{ color: item.color }">{{ item.value }}</div>
          <div class="summary-label">{{ item.label }}</div>
        </div>
      </a-col>
    </a-row>

    <!-- Tab 内容区 -->
    <div class="dashboard-card">
      <a-tabs v-model:activeKey="activeTab">
        <!-- 概览 -->
        <a-tab-pane key="overview" tab="集群概览">
          <a-descriptions :column="3" bordered size="small">
            <a-descriptions-item label="集群名称">{{ cluster.name }}</a-descriptions-item>
            <a-descriptions-item label="API Server">{{ cluster.apiServer }}</a-descriptions-item>
            <a-descriptions-item label="K8s 版本">{{ cluster.version }}</a-descriptions-item>
            <a-descriptions-item label="运行时间">{{ cluster.uptime }}</a-descriptions-item>
            <a-descriptions-item label="接入时间">{{ cluster.createdAt }}</a-descriptions-item>
            <a-descriptions-item label="最后心跳">{{ cluster.lastHeartbeat }}</a-descriptions-item>
            <a-descriptions-item label="备注" :span="3">{{ cluster.remark || '--' }}</a-descriptions-item>
          </a-descriptions>

          <!-- 审计日志接入说明 -->
          <div class="webhook-hint" style="margin-top: 20px; padding: 10px 14px; background: var(--mxsec-fill-1); border: 1px solid var(--mxsec-border); border-radius: 6px; line-height: 1.8">
            审计日志接入支持两种方式，根据集群类型选择：<br>
            <b>自建集群</b>（kubeadm / k3s / RKE）→ 使用下方「Audit Webhook 配置」，在 apiserver 中配置 Webhook 直接推送<br>
            <b>GKE 集群</b>（托管 apiserver）→ 使用下方「GCP Pub/Sub 配置」，通过 Cloud Logging → Pub/Sub 间接接入
          </div>

          <!-- Audit Webhook 配置 -->
          <div class="webhook-section">
            <div class="webhook-section-title">Audit Webhook 配置（自建集群）</div>
            <div class="webhook-hint">适用于可自行配置 apiserver 启动参数的集群。将 Webhook URL 配置到 apiserver 的 Audit Webhook Backend，即可接收审计事件并生成安全告警。</div>

            <template v-if="cluster.auditToken">
              <div class="webhook-field">
                <span class="webhook-field-label">Webhook URL</span>
                <div class="webhook-field-value">
                  <code class="webhook-code">{{ cluster.webhookURL }}</code>
                  <a-button type="link" size="small" @click="copyToClipboard(cluster.webhookURL, 'Webhook URL')">
                    <CopyOutlined />
                  </a-button>
                </div>
              </div>

              <div class="webhook-field">
                <span class="webhook-field-label">Audit Token</span>
                <div class="webhook-field-value">
                  <code class="webhook-code">{{ showToken ? cluster.auditToken : maskToken(cluster.auditToken) }}</code>
                  <a-button type="link" size="small" @click="showToken = !showToken">
                    <EyeOutlined v-if="!showToken" />
                    <EyeInvisibleOutlined v-else />
                  </a-button>
                  <a-button type="link" size="small" @click="copyToClipboard(cluster.auditToken, 'Audit Token')">
                    <CopyOutlined />
                  </a-button>
                  <a-popconfirm title="重新生成后旧 Token 将立即失效，已配置的 Webhook 需要同步更新。确定继续？" @confirm="regenerateToken">
                    <a-button type="link" size="small" danger>重新生成</a-button>
                  </a-popconfirm>
                </div>
              </div>

              <a-collapse :bordered="false" style="margin-top: 12px; background: transparent">
                <a-collapse-panel key="guide" header="K8s Apiserver 审计策略配置示例">
                  <div class="webhook-code-block">
                    <div class="webhook-code-block-header">
                      <span>audit-webhook-config.yaml</span>
                      <a-button type="link" size="small" @click="copyToClipboard(auditWebhookYaml, '配置')">
                        <CopyOutlined /> 复制
                      </a-button>
                    </div>
                    <pre class="webhook-pre">{{ auditWebhookYaml }}</pre>
                  </div>
                  <div class="webhook-hint" style="margin-top: 8px">
                    将上述内容保存为文件后，在 kube-apiserver 启动参数中添加：<br>
                    <code>--audit-webhook-config-file=/etc/kubernetes/audit-webhook-config.yaml</code><br>
                    <code>--audit-webhook-batch-max-wait=5s</code>
                  </div>
                </a-collapse-panel>
              </a-collapse>
            </template>

            <div v-else style="padding: 8px 0">
              <span style="color: #86909C; font-size: 13px">该集群尚未生成 Audit Token。</span>
              <a-button type="primary" size="small" style="margin-left: 12px" @click="regenerateToken">生成 Token</a-button>
            </div>
          </div>

          <!-- GCP Pub/Sub 配置 -->
          <div class="webhook-section" style="margin-top: 16px">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px">
              <div class="webhook-section-title">GCP Pub/Sub 配置（GKE 审计日志接入）</div>
              <a-switch
                v-model:checked="gcpForm.enabled"
                checked-children="已启用"
                un-checked-children="未启用"
                :loading="gcpSaving"
              />
            </div>
            <div class="webhook-hint">GKE 集群的审计日志通过 Cloud Logging → Pub/Sub 链路接入。配置后平台将自动消费审计事件并生成安全告警。</div>

            <div v-if="gcpForm.enabled || cluster.gcpEnabled">
              <a-form layout="vertical" style="max-width: 560px">
                <a-form-item label="GCP Project ID" required>
                  <a-input v-model:value="gcpForm.projectId" placeholder="your-gcp-project-id" />
                </a-form-item>
                <a-form-item label="Pub/Sub Subscription" required>
                  <a-input v-model:value="gcpForm.subscription" placeholder="mxsec-k8s-audit-sub" />
                </a-form-item>
                <a-form-item>
                  <template #label>
                    <span>SA JSON Key</span>
                    <span style="font-weight: 400; color: #86909C; margin-left: 8px">
                      {{ cluster.gcpHasCredentials ? '（已配置，留空保持不变）' : '（GCE ADC / Workload Identity 可留空）' }}
                    </span>
                  </template>
                  <a-textarea
                    v-model:value="gcpForm.credentialsJson"
                    placeholder="粘贴 Service Account JSON Key 内容，GCE 实例或 Workload Identity 环境下可留空"
                    :rows="4"
                    style="font-family: monospace; font-size: 12px"
                  />
                </a-form-item>
                <a-form-item>
                  <a-space>
                    <a-button type="primary" :loading="gcpSaving" @click="saveGCPConfig">保存配置</a-button>
                    <a-popconfirm
                      v-if="cluster.gcpEnabled"
                      title="清除后将停止接收该集群的 GKE 审计日志，确定继续？"
                      @confirm="deleteGCPConfig"
                    >
                      <a-button danger :loading="gcpSaving">清除配置</a-button>
                    </a-popconfirm>
                  </a-space>
                </a-form-item>
              </a-form>
            </div>
          </div>
        </a-tab-pane>

        <!-- Node 列表 -->
        <a-tab-pane key="nodes" tab="Node 节点">
          <a-table :columns="nodeColumns" :data-source="nodes" :loading="loadingNodes" :pagination="false" size="middle" row-key="name" :scroll="{ x: 1400 }">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <a-tag :color="record.status === 'Ready' ? 'green' : 'red'" :bordered="false">{{ record.status }}</a-tag>
              </template>
              <template v-if="column.key === 'cpu'">
                <a-progress :percent="record.cpuPercent" :size="6" :stroke-color="record.cpuPercent > 80 ? '#EF4444' : '#3B82F6'" />
              </template>
              <template v-if="column.key === 'memory'">
                <a-progress :percent="record.memoryPercent" :size="6" :stroke-color="record.memoryPercent > 80 ? '#EF4444' : '#22C55E'" />
              </template>
            </template>
          </a-table>
        </a-tab-pane>

        <!-- Pod 列表 -->
        <a-tab-pane key="pods" tab="Pod">
          <div class="filter-bar" style="margin-bottom: 16px">
            <a-input-search v-model:value="podSearch" placeholder="搜索 Pod 名称" style="width: 240px" allow-clear @search="loadPods" />
            <a-select v-model:value="podNamespace" style="width: 180px" placeholder="Namespace" allow-clear show-search @change="loadPods">
              <a-select-option v-for="ns in namespaces" :key="ns" :value="ns">{{ ns }}</a-select-option>
            </a-select>
            <a-select v-model:value="podStatus" style="width: 140px" placeholder="状态" allow-clear @change="loadPods">
              <a-select-option value="Running">Running</a-select-option>
              <a-select-option value="Pending">Pending</a-select-option>
              <a-select-option value="Failed">Failed</a-select-option>
              <a-select-option value="Succeeded">Succeeded</a-select-option>
            </a-select>
          </div>
          <a-table :columns="podColumns" :data-source="pods" :loading="loadingPods" :pagination="podPagination" @change="handlePodTableChange" size="middle" row-key="name">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <a-tag :color="podStatusColor[record.status]" :bordered="false">{{ record.status }}</a-tag>
              </template>
              <template v-if="column.key === 'containers'">
                <span>{{ record.readyContainers }}/{{ record.totalContainers }}</span>
              </template>
              <template v-if="column.key === 'restarts'">
                <span :style="{ color: record.restarts > 5 ? '#EF4444' : 'var(--mxsec-text-1)' }">{{ record.restarts }}</span>
              </template>
            </template>
          </a-table>
        </a-tab-pane>

        <!-- Workload -->
        <a-tab-pane key="workloads" tab="Workload">
          <a-table :columns="workloadColumns" :data-source="workloads" :loading="loadingWorkloads" :pagination="false" size="middle" row-key="name">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'type'">
                <a-tag :bordered="false">{{ record.type }}</a-tag>
              </template>
              <template v-if="column.key === 'replicas'">
                <span :style="{ color: record.readyReplicas < record.desiredReplicas ? '#F59E0B' : '#22C55E' }">
                  {{ record.readyReplicas }}/{{ record.desiredReplicas }}
                </span>
              </template>
            </template>
          </a-table>
        </a-tab-pane>

        <!-- 安全风险 -->
        <a-tab-pane key="risks" tab="安全风险">
          <a-row :gutter="[16, 16]" style="margin-bottom: 16px">
            <a-col :span="8">
              <div class="risk-card">
                <div class="risk-value" style="color: #EF4444">{{ riskStats.alarms }}</div>
                <div class="risk-label">安全告警</div>
              </div>
            </a-col>
            <a-col :span="8">
              <div class="risk-card">
                <div class="risk-value" style="color: #F59E0B">{{ riskStats.events }}</div>
                <div class="risk-label">安全事件</div>
              </div>
            </a-col>
            <a-col :span="8">
              <div class="risk-card">
                <div class="risk-value" style="color: #3B82F6">{{ riskStats.baseline }}</div>
                <div class="risk-label">基线问题</div>
              </div>
            </a-col>
          </a-row>
          <a-table :columns="riskColumns" :data-source="risks" :loading="loadingRisks" size="middle" row-key="id">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'severity'">
                <a-tag :color="severityColorMap[record.severity]" :bordered="false">{{ severityTextMap[record.severity] }}</a-tag>
              </template>
              <template v-if="column.key === 'type'">
                <a-tag :bordered="false">{{ record.type }}</a-tag>
              </template>
            </template>
          </a-table>
        </a-tab-pane>
      </a-tabs>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { LeftOutlined, CopyOutlined, EyeOutlined, EyeInvisibleOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import apiClient from '@/api/client'

const route = useRoute()
const clusterId = route.params.id as string
const activeTab = ref('overview')

const cluster = ref<any>({ name: '', status: 'running', version: '', apiServer: '', auditToken: '', webhookURL: '', gcpEnabled: false, gcpProjectId: '', gcpSubscription: '', gcpHasCredentials: false })
const showToken = ref(false)
const gcpSaving = ref(false)
const gcpForm = ref({ enabled: false, projectId: '', subscription: '', credentialsJson: '' })
const nodes = ref<any[]>([])
const pods = ref<any[]>([])
const workloads = ref<any[]>([])
const risks = ref<any[]>([])
const namespaces = ref<string[]>([])
const loadingNodes = ref(false)
const loadingPods = ref(false)
const loadingWorkloads = ref(false)
const loadingRisks = ref(false)

const podSearch = ref('')
const podNamespace = ref<string>()
const podStatus = ref<string>()
const podPagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const summaryStats = ref([
  { key: 'nodes', label: 'Node', value: 0, color: '#3B82F6' },
  { key: 'pods', label: 'Pod', value: 0, color: '#22C55E' },
  { key: 'namespaces', label: 'Namespace', value: 0, color: '#722ED1' },
  { key: 'deployments', label: 'Deployment', value: 0, color: '#F59E0B' },
  { key: 'services', label: 'Service', value: 0, color: '#3B82F6' },
  { key: 'alarms', label: '安全告警', value: 0, color: '#EF4444' },
])

const riskStats = ref({ alarms: 0, events: 0, baseline: 0 })

const statusColorMap: Record<string, string> = { running: 'green', warning: 'orange', offline: 'red' }
const statusTextMap: Record<string, string> = { running: '运行中', warning: '异常', offline: '离线' }
const podStatusColor: Record<string, string> = { Running: 'green', Pending: 'orange', Failed: 'red', Succeeded: 'blue' }
const severityColorMap: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityTextMap: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }

const nodeColumns = [
  { title: '节点名称', dataIndex: 'name', key: 'name', width: 200 },
  { title: '状态', key: 'status', width: 100 },
  { title: '角色', dataIndex: 'roles', key: 'roles', width: 120 },
  { title: 'IP', dataIndex: 'ip', key: 'ip', width: 140 },
  { title: 'OS', dataIndex: 'os', key: 'os', width: 160 },
  { title: 'CPU 使用', key: 'cpu', width: 200 },
  { title: '内存使用', key: 'memory', width: 200 },
  { title: 'Pod 数', dataIndex: 'podCount', key: 'podCount', width: 80, align: 'center' as const },
  { title: '版本', dataIndex: 'kubeletVersion', key: 'kubeletVersion', width: 120 },
]

const podColumns = [
  { title: 'Pod 名称', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 140 },
  { title: '状态', key: 'status', width: 100 },
  { title: '容器', key: 'containers', width: 80 },
  { title: '重启次数', key: 'restarts', width: 100 },
  { title: '节点', dataIndex: 'nodeName', key: 'nodeName', width: 160 },
  { title: 'IP', dataIndex: 'podIp', key: 'podIp', width: 130 },
  { title: '运行时间', dataIndex: 'age', key: 'age', width: 120 },
]

const workloadColumns = [
  { title: '名称', dataIndex: 'name', key: 'name', width: 200 },
  { title: '类型', key: 'type', width: 120 },
  { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 140 },
  { title: '副本', key: 'replicas', width: 100 },
  { title: '镜像', dataIndex: 'images', key: 'images', ellipsis: true },
  { title: '创建时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
]

const riskColumns = [
  { title: '风险类型', key: 'type', width: 120 },
  { title: '严重级别', key: 'severity', width: 100 },
  { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
  { title: '影响对象', dataIndex: 'target', key: 'target', width: 200 },
  { title: '发现时间', dataIndex: 'discoveredAt', key: 'discoveredAt', width: 180 },
]

const loadCluster = async () => {
  try {
    const res = await apiClient.get<any>(`/kube/clusters/${clusterId}`)
    cluster.value = res
    if (res.summary) {
      summaryStats.value = [
        { key: 'nodes', label: 'Node', value: res.summary.nodes ?? 0, color: '#3B82F6' },
        { key: 'pods', label: 'Pod', value: res.summary.pods ?? 0, color: '#22C55E' },
        { key: 'namespaces', label: 'Namespace', value: res.summary.namespaces ?? 0, color: '#722ED1' },
        { key: 'deployments', label: 'Deployment', value: res.summary.deployments ?? 0, color: '#F59E0B' },
        { key: 'services', label: 'Service', value: res.summary.services ?? 0, color: '#3B82F6' },
        { key: 'alarms', label: '安全告警', value: res.summary.alarms ?? 0, color: '#EF4444' },
      ]
    }
    if (res.namespaces) namespaces.value = res.namespaces
    if (res.risks) riskStats.value = res.risks
    // 同步 GCP 表单
    gcpForm.value.enabled = res.gcpEnabled ?? false
    gcpForm.value.projectId = res.gcpProjectId ?? ''
    gcpForm.value.subscription = res.gcpSubscription ?? ''
    gcpForm.value.credentialsJson = ''
  } catch { /* API 未就绪 */ }
}

const loadNodes = async () => {
  loadingNodes.value = true
  try { const res = await apiClient.get<any>(`/kube/clusters/${clusterId}/nodes`); nodes.value = res.items ?? [] }
  catch { nodes.value = [] }
  finally { loadingNodes.value = false }
}

const loadPods = async () => {
  loadingPods.value = true
  try {
    const res = await apiClient.get<any>(`/kube/clusters/${clusterId}/pods`, {
      params: { page: podPagination.value.current, page_size: podPagination.value.pageSize, search: podSearch.value || undefined, namespace: podNamespace.value || undefined, status: podStatus.value || undefined },
    })
    pods.value = res.items ?? []
    podPagination.value.total = res.total ?? 0
  } catch { pods.value = [] }
  finally { loadingPods.value = false }
}

const loadWorkloads = async () => {
  loadingWorkloads.value = true
  try { const res = await apiClient.get<any>(`/kube/clusters/${clusterId}/workloads`); workloads.value = res.items ?? [] }
  catch { workloads.value = [] }
  finally { loadingWorkloads.value = false }
}

const handlePodTableChange = (pag: any) => { podPagination.value.current = pag.current; podPagination.value.pageSize = pag.pageSize; loadPods() }

// Audit Webhook 相关
const maskToken = (token: string) => {
  if (!token || token.length <= 8) return token
  return token.slice(0, 4) + '*'.repeat(token.length - 8) + token.slice(-4)
}

const auditWebhookYaml = computed(() => {
  const url = cluster.value.webhookURL || 'https://YOUR_DOMAIN/api/v1/kube/audit-webhook/YOUR_TOKEN'
  return `apiVersion: v1
kind: Config
clusters:
- name: mxsec-audit
  cluster:
    server: "${url}"
contexts:
- name: mxsec-audit
  context:
    cluster: mxsec-audit
current-context: mxsec-audit`
})

const copyToClipboard = async (text: string, label: string) => {
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

const regenerateToken = async () => {
  try {
    const res = await apiClient.post<any>(`/kube/clusters/${clusterId}/regenerate-token`)
    cluster.value.auditToken = res.auditToken
    cluster.value.webhookURL = res.webhookURL
    message.success('Audit Token 已重新生成')
  } catch (error) {
    console.error('重新生成 Token 失败:', error)
  }
}

const saveGCPConfig = async () => {
  if (!gcpForm.value.projectId || !gcpForm.value.subscription) {
    message.warning('请填写 GCP Project ID 和 Pub/Sub Subscription')
    return
  }
  gcpSaving.value = true
  try {
    const res = await apiClient.put<any>(`/kube/clusters/${clusterId}/gcp-config`, {
      projectId: gcpForm.value.projectId,
      subscription: gcpForm.value.subscription,
      credentialsJson: gcpForm.value.credentialsJson || undefined,
    })
    cluster.value.gcpEnabled = res.gcpEnabled
    cluster.value.gcpProjectId = res.gcpProjectId
    cluster.value.gcpSubscription = res.gcpSubscription
    cluster.value.gcpHasCredentials = res.gcpHasCredentials
    gcpForm.value.credentialsJson = ''
    message.success('GCP Pub/Sub 配置已保存')
  } catch (error) {
    console.error('保存 GCP 配置失败:', error)
  } finally {
    gcpSaving.value = false
  }
}

const deleteGCPConfig = async () => {
  gcpSaving.value = true
  try {
    await apiClient.delete(`/kube/clusters/${clusterId}/gcp-config`)
    cluster.value.gcpEnabled = false
    cluster.value.gcpProjectId = ''
    cluster.value.gcpSubscription = ''
    cluster.value.gcpHasCredentials = false
    gcpForm.value = { enabled: false, projectId: '', subscription: '', credentialsJson: '' }
    message.success('GCP Pub/Sub 配置已清除')
  } catch (error) {
    console.error('清除 GCP 配置失败:', error)
  } finally {
    gcpSaving.value = false
  }
}

onMounted(() => { loadCluster(); loadNodes(); loadPods(); loadWorkloads() })
</script>

<style scoped>
.kube-detail-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.summary-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; padding: 16px; text-align: center; }
.summary-value { font-size: 24px; font-weight: 700; line-height: 1.2; }
.summary-label { font-size: 12px; color: var(--mxsec-text-3); margin-top: 4px; }

.risk-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; padding: 20px; text-align: center; }
.risk-value { font-size: 28px; font-weight: 700; line-height: 1.2; }
.risk-label { font-size: 13px; color: var(--mxsec-text-3); margin-top: 4px; }

.dashboard-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; padding: 0 20px 20px; }

.filter-bar { display: flex; gap: 8px; align-items: center; padding: 12px 16px; background: var(--mxsec-fill-1); border-radius: 4px; border: 1px solid var(--mxsec-border); }

.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }
.dot-running { background: #22C55E; box-shadow: 0 0 0 3px rgba(0,180,42,0.15); }
.dot-warning { background: #F59E0B; box-shadow: 0 0 0 3px rgba(255,125,0,0.15); }
.dot-offline { background: #EF4444; box-shadow: 0 0 0 3px rgba(245,63,63,0.15); }

.webhook-section { margin-top: 20px; padding: 16px; background: var(--mxsec-fill-1); border: 1px solid var(--mxsec-border); border-radius: 8px; }
.webhook-section-title { font-size: 14px; font-weight: 600; color: var(--mxsec-text-1); margin-bottom: 4px; }
.webhook-hint { font-size: 12px; color: var(--mxsec-text-3); margin-bottom: 12px; line-height: 1.6; }
.webhook-field { margin-bottom: 10px; }
.webhook-field-label { display: block; font-size: 12px; color: var(--mxsec-text-3); margin-bottom: 4px; }
.webhook-field-value { display: flex; align-items: center; gap: 4px; }
.webhook-code { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 4px; padding: 4px 8px; font-size: 12px; color: var(--mxsec-text-1); word-break: break-all; flex: 1; }
.webhook-code-block { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 4px; overflow: hidden; }
.webhook-code-block-header { display: flex; justify-content: space-between; align-items: center; padding: 6px 12px; background: var(--mxsec-fill-2); border-bottom: 1px solid var(--mxsec-border); font-size: 12px; color: var(--mxsec-text-3); }
.webhook-pre { margin: 0; padding: 12px; font-size: 12px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; color: var(--mxsec-text-1); }
</style>
