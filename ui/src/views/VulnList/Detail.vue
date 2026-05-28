<template>
  <div class="vuln-detail-page">
    <div class="page-header">
      <a-button type="link" @click="router.back()" style="padding: 0; margin-right: 8px">
        <template #icon><ArrowLeftOutlined /></template>
        返回
      </a-button>
      <h2>{{ vuln?.cveId || '漏洞详情' }}</h2>
      <a-tag v-if="vuln" :color="severityColorMap[vuln.severity]" :bordered="false" style="margin-left: 12px">
        {{ severityTextMap[vuln.severity] }}
      </a-tag>
    </div>

    <a-spin :spinning="loading">
      <template v-if="vuln">
        <a-tabs v-model:activeKey="activeTab">
          <a-tab-pane key="info" tab="基本信息">
            <div class="detail-card">
              <a-descriptions :column="2" bordered size="small">
                <a-descriptions-item label="漏洞编号">{{ vuln.cveId }}</a-descriptions-item>
                <a-descriptions-item v-if="vuln.osvId" label="OSV ID">{{ vuln.osvId }}</a-descriptions-item>
                <a-descriptions-item label="CVSS 评分">
                  <span :class="cvssClass(vuln.cvssScore)">{{ vuln.cvssScore }}</span>
                </a-descriptions-item>
                <a-descriptions-item label="严重级别">
                  <a-tag :color="severityColorMap[vuln.severity]" :bordered="false">
                    {{ severityTextMap[vuln.severity] }}
                  </a-tag>
                </a-descriptions-item>
                <a-descriptions-item label="影响组件">
                  <a-tag color="blue">{{ vuln.component || '-' }}</a-tag>
                </a-descriptions-item>
                <a-descriptions-item label="当前版本">{{ vuln.currentVersion || '-' }}</a-descriptions-item>
                <a-descriptions-item label="修复版本">{{ vuln.fixedVersion || '暂无' }}</a-descriptions-item>
                <a-descriptions-item label="状态">
                  <a-tag :color="statusColor(vuln.status)" :bordered="false">
                    {{ statusTextMap[vuln.status] || vuln.status }}
                  </a-tag>
                </a-descriptions-item>
                <a-descriptions-item label="发现时间" :span="2">{{ vuln.discoveredAt || '-' }}</a-descriptions-item>
                <a-descriptions-item label="描述" :span="2">{{ vuln.description || '-' }}</a-descriptions-item>
              </a-descriptions>

              <!-- 参考链接 -->
              <div v-if="vuln.referenceUrl || vuln.cveId" class="reference-section">
                <h4>参考链接</h4>
                <ul>
                  <li v-if="vuln.cveId?.startsWith('CVE-')">
                    <a :href="`https://nvd.nist.gov/vuln/detail/${vuln.cveId}`" target="_blank" rel="noopener">
                      NVD - {{ vuln.cveId }}
                    </a>
                  </li>
                  <li v-if="vuln.osvId">
                    <a :href="`https://osv.dev/vulnerability/${vuln.osvId}`" target="_blank" rel="noopener">
                      OSV - {{ vuln.osvId }}
                    </a>
                  </li>
                  <li v-if="vuln.referenceUrl">
                    <a :href="vuln.referenceUrl" target="_blank" rel="noopener">{{ vuln.referenceUrl }}</a>
                  </li>
                </ul>
              </div>
            </div>

            <div class="detail-card" style="margin-top: 16px">
              <h4>受影响主机 ({{ vuln.hosts?.length ?? 0 }})</h4>
              <a-table
                :columns="hostColumns"
                :data-source="vuln.hosts ?? []"
                :pagination="false"
                size="small"
                row-key="id"
              >
                <template #bodyCell="{ column, record: hostRecord }">
                  <template v-if="column.key === 'host'">
                    <RouterLink :to="`/hosts/${hostRecord.hostId}?tab=vulnerabilities`">
                      {{ hostRecord.hostname || hostRecord.hostId }}
                    </RouterLink>
                  </template>
                  <template v-else-if="column.key === 'status'">
                    <a-tag :color="statusColor(hostRecord.status)" :bordered="false">
                      {{ statusTextMap[hostRecord.status] || hostRecord.status }}
                    </a-tag>
                  </template>
                </template>
              </a-table>
            </div>
          </a-tab-pane>

          <a-tab-pane key="advice" tab="修复建议">
            <div class="detail-card">
              <a-spin :spinning="adviceLoading">
                <template v-if="adviceData">
                  <a-alert
                    v-if="!adviceData.fixedVersion"
                    type="warning"
                    show-icon
                    message="暂无官方修复版本"
                    description="建议关注供应商安全公告，或通过网络层限制访问以降低风险。"
                    style="margin-bottom: 16px"
                  />

                  <div v-if="adviceData.commands.length > 0" class="advice-section">
                    <h4>升级命令</h4>
                    <div v-for="(cmd, idx) in adviceData.commands" :key="idx" class="advice-command">
                      <div class="advice-command-header">
                        <a-tag color="blue" :bordered="false">{{ cmd.packageType.toUpperCase() }}</a-tag>
                        <span class="advice-command-desc">{{ cmd.description }}</span>
                      </div>
                      <div class="advice-command-code">
                        <code>{{ cmd.command }}</code>
                        <a-button type="link" size="small" @click="copyCommand(cmd.command)">复制</a-button>
                      </div>
                    </div>
                  </div>

                  <div v-if="adviceData.references.length > 0" class="advice-section">
                    <h4>参考链接</h4>
                    <ul>
                      <li v-for="(ref, idx) in adviceData.references" :key="idx">
                        <a :href="ref" target="_blank" rel="noopener">{{ ref }}</a>
                      </li>
                    </ul>
                  </div>

                  <div v-if="adviceData.workaround" class="advice-section">
                    <h4>临时缓解措施</h4>
                    <a-alert type="info" :message="adviceData.workaround" show-icon />
                  </div>

                  <a-divider />
                  <a-space v-if="vuln.status === 'unpatched'">
                    <a-button type="primary" :loading="createTaskLoading" @click="handleCreateTask">
                      创建修复任务（全部主机）
                    </a-button>
                    <a-button @click="handlePatch">标记为已修复</a-button>
                  </a-space>
                </template>
              </a-spin>
            </div>
          </a-tab-pane>
        </a-tabs>
      </template>
    </a-spin>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useRoute, useRouter, RouterLink } from 'vue-router'
import { message } from 'ant-design-vue'
import { ArrowLeftOutlined } from '@ant-design/icons-vue'
import { vulnerabilitiesApi } from '@/api/vulnerabilities'
import type { RemediationAdvice } from '@/api/vulnerabilities'
import { remediationTasksApi } from '@/api/remediation-tasks'
import type { Vulnerability } from '@/api/types'

const route = useRoute()
const router = useRouter()

const loading = ref(false)
const vuln = ref<Vulnerability | null>(null)
const activeTab = ref('info')
const adviceLoading = ref(false)
const adviceData = ref<RemediationAdvice | null>(null)
const createTaskLoading = ref(false)

const severityColorMap: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'blue',
}

const severityTextMap: Record<string, string> = {
  critical: '紧急',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const statusTextMap: Record<string, string> = {
  unpatched: '未修复',
  patched: '已修复',
  ignored: '已忽略',
}

const hostColumns = [
  { title: '主机', key: 'host', width: 180 },
  { title: 'IP', dataIndex: 'ip', key: 'ip', width: 140 },
  { title: '当前版本', dataIndex: 'currentVersion', key: 'currentVersion', width: 140 },
  { title: '状态', key: 'status', width: 100 },
]

const statusColor = (status: string) => {
  if (status === 'patched') return 'green'
  if (status === 'ignored') return 'default'
  return 'red'
}

const cvssClass = (score: number) => {
  if (score >= 9) return 'score-critical'
  if (score >= 7) return 'score-high'
  return 'score-normal'
}

const loadVuln = async () => {
  const id = Number(route.params.id)
  if (!id) return
  loading.value = true
  try {
    vuln.value = await vulnerabilitiesApi.get(id)
  } catch {
    message.error('获取漏洞详情失败')
  } finally {
    loading.value = false
  }
}

const loadAdvice = async () => {
  if (!vuln.value) return
  adviceLoading.value = true
  try {
    adviceData.value = await vulnerabilitiesApi.getAdvice(vuln.value.id)
  } catch {
    message.error('获取修复建议失败')
    adviceData.value = null
  } finally {
    adviceLoading.value = false
  }
}

const handlePatch = async () => {
  if (!vuln.value) return
  try {
    await vulnerabilitiesApi.patch(vuln.value.id)
    message.success('已标记为修复')
    loadVuln()
  } catch {
    message.error('操作失败')
  }
}

const handleCreateTask = async () => {
  if (!vuln.value) return
  const hosts = vuln.value.hosts?.filter(h => h.status === 'unpatched') ?? []
  if (hosts.length === 0) {
    message.warning('该漏洞无未修复的主机')
    return
  }
  createTaskLoading.value = true
  try {
    const hostIds = hosts.map(h => h.hostId)
    const res = await remediationTasksApi.create(vuln.value.id, hostIds)
    message.success(`已为 ${res.created} 台主机创建修复任务，请前往修复任务页面确认执行`)
  } catch {
    message.error('创建修复任务失败')
  } finally {
    createTaskLoading.value = false
  }
}

const copyCommand = (cmd: string) => {
  navigator.clipboard.writeText(cmd)
  message.success('已复制到剪贴板')
}

watch(activeTab, (tab) => {
  if (tab === 'advice' && vuln.value && !adviceData.value) {
    loadAdvice()
  }
})

onMounted(() => {
  loadVuln()
})
</script>

<style scoped>
.vuln-detail-page { width: 100%; }

.page-header {
  display: flex;
  align-items: center;
  margin-bottom: 20px;
}

.page-header h2 {
  margin: 0;
}

.detail-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
}

.detail-card h4 {
  margin-bottom: 12px;
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.reference-section {
  margin-top: 20px;
}

.reference-section ul {
  padding-left: 20px;
}

.reference-section li {
  margin-bottom: 6px;
}

.score-critical { color: #EF4444; font-weight: 700; }
.score-high { color: #F59E0B; font-weight: 700; }
.score-normal { color: var(--mxsec-text-1); font-weight: 600; }

.advice-section { margin-bottom: 20px; }
.advice-section h4 { margin-bottom: 12px; font-weight: 600; color: var(--mxsec-text-1); }

.advice-command {
  margin-bottom: 12px;
  border: 1px solid var(--mxsec-border);
  border-radius: 6px;
  padding: 12px;
}

.advice-command-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.advice-command-desc { font-size: 13px; color: var(--mxsec-text-2); }

.advice-command-code {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--mxsec-fill-1);
  border-radius: 4px;
  padding: 8px 12px;
}

.advice-command-code code {
  font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
  font-size: 13px;
  color: var(--mxsec-text-1);
  word-break: break-all;
}
</style>
