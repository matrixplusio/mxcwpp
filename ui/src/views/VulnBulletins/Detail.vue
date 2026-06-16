<template>
  <div class="bulletin-detail-page">
    <div class="page-header">
      <a-button type="link" @click="router.back()" style="padding: 0; margin-right: 8px">
        <template #icon><ArrowLeftOutlined /></template>
        返回
      </a-button>
      <h2>{{ bulletin?.bulletinNo || '通报详情' }}</h2>
      <a-tag
        v-if="bulletin"
        :color="priorityColorMap[bulletin.priority]"
        :bordered="false"
        style="margin-left: 12px"
      >
        {{ priorityTextMap[bulletin.priority] }}
      </a-tag>
      <a-tag
        v-if="bulletin?.slaBreached"
        color="red"
        :bordered="false"
        style="margin-left: 4px"
      >
        SLA 超时
      </a-tag>
    </div>

    <a-spin :spinning="loading">
      <template v-if="bulletin">
        <!-- 操作按钮 -->
        <div class="action-bar section-row">
          <a-space>
            <a-button
              v-if="bulletin.status === 'pending' || bulletin.status === 'notified'"
              type="primary"
              @click="handleAcknowledge"
            >
              确认通报
            </a-button>
            <a-button
              v-if="bulletin.status === 'acknowledged'"
              type="primary"
              @click="showResolveModal"
            >
              标记修复
            </a-button>
            <a-button
              v-if="bulletin.status !== 'ignored' && bulletin.status !== 'resolved'"
              @click="showIgnoreModal"
            >
              忽略通报
            </a-button>
            <a-button
              v-if="bulletin.status === 'resolved' || bulletin.status === 'ignored'"
              @click="handleReopen"
            >
              重新打开
            </a-button>
          </a-space>
          <div class="action-bar-right">
            <span class="status-badge">
              状态：
              <a-tag :color="statusColorMap[bulletin.status]" :bordered="false">
                {{ statusTextMap[bulletin.status] }}
              </a-tag>
            </span>
          </div>
        </div>

        <a-tabs v-model:activeKey="activeTab">
          <!-- 基本信息 -->
          <a-tab-pane key="info" tab="通报信息">
            <div class="detail-card">
              <a-descriptions :column="2" bordered size="small">
                <a-descriptions-item label="通报编号">{{ bulletin.bulletinNo }}</a-descriptions-item>
                <a-descriptions-item label="CVE 编号">
                  <RouterLink :to="`/vuln-list/${bulletin.vulnId}`">{{ bulletin.cveId }}</RouterLink>
                </a-descriptions-item>
                <a-descriptions-item label="优先级">
                  <a-tag :color="priorityColorMap[bulletin.priority]" :bordered="false">
                    {{ priorityTextMap[bulletin.priority] }}
                  </a-tag>
                </a-descriptions-item>
                <a-descriptions-item label="严重级别">
                  <a-tag :color="severityColorMap[bulletin.severity]" :bordered="false">
                    {{ severityTextMap[bulletin.severity] }}
                  </a-tag>
                </a-descriptions-item>
                <a-descriptions-item label="CVSS 评分">
                  <span :class="cvssClass(bulletin.cvssScore)">{{ bulletin.cvssScore }}</span>
                  <span v-if="bulletin.cvssVector" style="margin-left: 8px; color: #86909C; font-size: 12px">
                    {{ bulletin.cvssVector }}
                  </span>
                </a-descriptions-item>
                <a-descriptions-item label="EPSS 评分">
                  {{ bulletin.epssScore > 0 ? (bulletin.epssScore * 100).toFixed(2) + '%' : '-' }}
                </a-descriptions-item>
                <a-descriptions-item label="影响组件">
                  <a-tag color="blue">{{ bulletin.component || '-' }}</a-tag>
                </a-descriptions-item>
                <a-descriptions-item label="攻击向量">
                  {{ attackVectorText[bulletin.attackVector] || bulletin.attackVector || '-' }}
                </a-descriptions-item>
                <a-descriptions-item label="漏洞类型">
                  {{ vulnTypeText[bulletin.vulnType] || bulletin.vulnType || '-' }}
                </a-descriptions-item>
                <a-descriptions-item label="漏洞来源">{{ bulletin.source || '-' }}</a-descriptions-item>
                <a-descriptions-item label="受影响资产">
                  <span style="font-weight: 600; color: #EF4444">{{ bulletin.affectedAssets }}</span> 台主机
                </a-descriptions-item>
                <a-descriptions-item label="补丁状态">
                  <a-tag v-if="bulletin.patchAvailable" color="green" :bordered="false">补丁可用</a-tag>
                  <a-tag v-else color="red" :bordered="false">暂无补丁</a-tag>
                </a-descriptions-item>
                <a-descriptions-item label="影响版本" :span="2">
                  {{ bulletin.affectedVersions || '-' }}
                </a-descriptions-item>
                <a-descriptions-item label="描述" :span="2">
                  {{ bulletin.description || '-' }}
                </a-descriptions-item>
              </a-descriptions>
            </div>

            <!-- 威胁情报 -->
            <div class="detail-card" style="margin-top: 16px">
              <h4>威胁情报</h4>
              <a-descriptions :column="2" bordered size="small">
                <a-descriptions-item label="在野利用 (KEV)">
                  <a-tag v-if="bulletin.inKev" color="red" :bordered="false">是</a-tag>
                  <span v-else>否</span>
                </a-descriptions-item>
                <a-descriptions-item label="Exploit 可用">
                  <a-tag v-if="bulletin.hasExploit" color="orange" :bordered="false">是</a-tag>
                  <span v-else>否</span>
                </a-descriptions-item>
                <a-descriptions-item v-if="bulletin.exploitRef" label="Exploit 参考" :span="2">
                  {{ bulletin.exploitRef }}
                </a-descriptions-item>
              </a-descriptions>
            </div>

            <!-- 修复建议 -->
            <div class="detail-card" style="margin-top: 16px">
              <h4>修复建议</h4>
              <a-descriptions :column="1" bordered size="small">
                <a-descriptions-item label="修复版本">
                  {{ bulletin.fixedVersion || '暂无' }}
                </a-descriptions-item>
                <a-descriptions-item label="修复建议">
                  {{ bulletin.fixSuggestion || '-' }}
                </a-descriptions-item>
                <a-descriptions-item label="临时缓解措施">
                  {{ bulletin.workaround || '-' }}
                </a-descriptions-item>
              </a-descriptions>
            </div>

            <!-- 优先级评估因子 -->
            <div v-if="bulletin.priorityFactors" class="detail-card" style="margin-top: 16px">
              <h4>优先级评估因子</h4>
              <a-descriptions :column="2" bordered size="small">
                <a-descriptions-item label="CVSS">{{ bulletin.priorityFactors.cvss_score }}</a-descriptions-item>
                <a-descriptions-item label="攻击向量">
                  {{ attackVectorText[bulletin.priorityFactors.attack_vector] || bulletin.priorityFactors.attack_vector }}
                </a-descriptions-item>
                <a-descriptions-item label="漏洞类型">
                  {{ vulnTypeText[bulletin.priorityFactors.vuln_type] || bulletin.priorityFactors.vuln_type }}
                </a-descriptions-item>
                <a-descriptions-item label="Exploit">
                  {{ bulletin.priorityFactors.has_exploit ? '有' : '无' }}
                </a-descriptions-item>
                <a-descriptions-item label="KEV 在野利用">
                  {{ bulletin.priorityFactors.in_kev ? '是' : '否' }}
                </a-descriptions-item>
                <a-descriptions-item label="补丁可用">
                  {{ bulletin.priorityFactors.patch_available ? '是' : '否' }}
                </a-descriptions-item>
                <a-descriptions-item label="判定依据" :span="2">
                  {{ bulletin.priorityFactors.reason }}
                </a-descriptions-item>
              </a-descriptions>
            </div>
          </a-tab-pane>

          <!-- SLA 跟踪 -->
          <a-tab-pane key="sla" tab="SLA 跟踪">
            <div class="detail-card">
              <a-descriptions :column="2" bordered size="small">
                <a-descriptions-item label="创建时间">{{ formatDateTime(bulletin.createdAt) }}</a-descriptions-item>
                <a-descriptions-item label="通知时间">{{ formatDateTime(bulletin.notifiedAt) || '-' }}</a-descriptions-item>
                <a-descriptions-item label="确认截止">
                  <span :class="{ 'sla-overdue': isSlaOverdue(bulletin.slaAckDeadline, bulletin.acknowledgedAt) }">
                    {{ formatDateTime(bulletin.slaAckDeadline) || '-' }}
                  </span>
                </a-descriptions-item>
                <a-descriptions-item label="确认时间">
                  {{ formatDateTime(bulletin.acknowledgedAt) || '-' }}
                  <span v-if="bulletin.acknowledgedBy" style="color: #86909C; margin-left: 4px">
                    ({{ bulletin.acknowledgedBy }})
                  </span>
                </a-descriptions-item>
                <a-descriptions-item label="修复截止">
                  <span :class="{ 'sla-overdue': isSlaOverdue(bulletin.slaResolveDeadline, bulletin.resolvedAt) }">
                    {{ formatDateTime(bulletin.slaResolveDeadline) || '-' }}
                  </span>
                </a-descriptions-item>
                <a-descriptions-item label="修复时间">
                  {{ formatDateTime(bulletin.resolvedAt) || '-' }}
                  <span v-if="bulletin.resolvedBy" style="color: #86909C; margin-left: 4px">
                    ({{ bulletin.resolvedBy }})
                  </span>
                </a-descriptions-item>
                <a-descriptions-item label="SLA 状态" :span="2">
                  <a-tag v-if="bulletin.slaBreached" color="red" :bordered="false">已超时</a-tag>
                  <a-tag v-else color="green" :bordered="false">正常</a-tag>
                </a-descriptions-item>
                <a-descriptions-item v-if="bulletin.resolveComment" label="修复备注" :span="2">
                  {{ bulletin.resolveComment }}
                </a-descriptions-item>
                <a-descriptions-item v-if="bulletin.ignoredAt" label="忽略时间">
                  {{ formatDateTime(bulletin.ignoredAt) }}
                  <span v-if="bulletin.ignoredBy" style="color: #86909C; margin-left: 4px">
                    ({{ bulletin.ignoredBy }})
                  </span>
                </a-descriptions-item>
                <a-descriptions-item v-if="bulletin.ignoreReason" label="忽略原因">
                  {{ bulletin.ignoreReason }}
                </a-descriptions-item>
                <a-descriptions-item label="通知次数">{{ bulletin.notifyCount }}</a-descriptions-item>
                <a-descriptions-item label="最后通知">{{ formatDateTime(bulletin.lastNotifiedAt) || '-' }}</a-descriptions-item>
              </a-descriptions>
            </div>
          </a-tab-pane>

          <!-- 受影响主机 -->
          <a-tab-pane key="hosts" tab="受影响主机">
            <div class="detail-card">
              <h4>受影响主机 ({{ affectedHosts.length }})</h4>
              <a-table
                :columns="hostColumns"
                :data-source="affectedHosts"
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
                    <a-tag :color="hostStatusColor(hostRecord.status)" :bordered="false">
                      {{ hostStatusText[hostRecord.status] || hostRecord.status }}
                    </a-tag>
                  </template>
                </template>
              </a-table>
            </div>
          </a-tab-pane>
        </a-tabs>
      </template>
    </a-spin>

    <!-- 修复确认弹窗 -->
    <a-modal
      v-model:open="resolveModalVisible"
      title="标记修复"
      @ok="handleResolve"
      :confirmLoading="actionLoading"
    >
      <a-form-item label="修复备注">
        <a-textarea v-model:value="resolveComment" :rows="3" placeholder="请输入修复说明（可选）" />
      </a-form-item>
    </a-modal>

    <!-- 忽略确认弹窗 -->
    <a-modal
      v-model:open="ignoreModalVisible"
      title="忽略通报"
      @ok="handleIgnore"
      :confirmLoading="actionLoading"
    >
      <a-form-item label="忽略原因">
        <a-textarea v-model:value="ignoreReason" :rows="3" placeholder="请输入忽略原因（可选）" />
      </a-form-item>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter, RouterLink } from 'vue-router'
import { message } from 'ant-design-vue'
import { ArrowLeftOutlined } from '@ant-design/icons-vue'
import { vulnBulletinsApi } from '@/api/vuln-bulletins'
import type { VulnBulletin } from '@/api/vuln-bulletins'
import { formatDateTime } from '@/utils/date'

const route = useRoute()
const router = useRouter()

const loading = ref(false)
const bulletin = ref<VulnBulletin | null>(null)
const affectedHosts = ref<any[]>([])
const activeTab = ref('info')
const actionLoading = ref(false)

// 修复/忽略弹窗
const resolveModalVisible = ref(false)
const resolveComment = ref('')
const ignoreModalVisible = ref(false)
const ignoreReason = ref('')

const priorityColorMap: Record<string, string> = {
  P0: 'red',
  P1: 'orange',
  P2: 'blue',
  P3: 'default',
}

const priorityTextMap: Record<string, string> = {
  P0: 'P0 紧急',
  P1: 'P1 高危',
  P2: 'P2 中危',
  P3: 'P3 低危',
}

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

const statusColorMap: Record<string, string> = {
  pending: 'default',
  notified: 'processing',
  acknowledged: 'blue',
  resolved: 'success',
  ignored: 'default',
}

const statusTextMap: Record<string, string> = {
  pending: '待处理',
  notified: '已通知',
  acknowledged: '已确认',
  resolved: '已修复',
  ignored: '已忽略',
}

const attackVectorText: Record<string, string> = {
  network: '网络',
  adjacent: '相邻网络',
  local: '本地',
  physical: '物理',
}

const vulnTypeText: Record<string, string> = {
  rce: '远程代码执行',
  lpe: '本地提权',
  dos: '拒绝服务',
  info_disclosure: '信息泄露',
  auth_bypass: '认证绕过',
  xss: '跨站脚本',
  sqli: 'SQL 注入',
  ssrf: '服务端请求伪造',
  other: '其他',
}

const hostStatusText: Record<string, string> = {
  unpatched: '未修复',
  patched: '已修复',
  ignored: '已忽略',
}

const hostColumns = [
  { title: '主机', key: 'host', width: 200 },
  { title: 'IP', dataIndex: 'ip', key: 'ip', width: 140 },
  { title: '当前版本', dataIndex: 'currentVersion', key: 'currentVersion', width: 160 },
  { title: '状态', key: 'status', width: 100 },
]

const cvssClass = (score: number) => {
  if (score >= 9) return 'score-critical'
  if (score >= 7) return 'score-high'
  return 'score-normal'
}

const hostStatusColor = (status: string) => {
  if (status === 'patched') return 'green'
  if (status === 'ignored') return 'default'
  return 'red'
}

const isSlaOverdue = (deadline?: string, completedAt?: string) => {
  if (!deadline) return false
  if (completedAt) return new Date(completedAt) > new Date(deadline)
  return new Date() > new Date(deadline)
}

// === 数据加载 ===

const loadBulletin = async () => {
  const id = Number(route.params.id)
  if (!id) return
  loading.value = true
  try {
    const res = await vulnBulletinsApi.get(id)
    bulletin.value = res.bulletin
    affectedHosts.value = res.affected_hosts ?? []
  } catch (error) {
    console.error('获取通报详情失败:', error)
  } finally {
    loading.value = false
  }
}

// === 操作 ===

const handleAcknowledge = async () => {
  if (!bulletin.value) return
  actionLoading.value = true
  try {
    await vulnBulletinsApi.acknowledge(bulletin.value.id)
    message.success('通报已确认')
    loadBulletin()
  } catch (error) {
    console.error('确认通报失败:', error)
  } finally {
    actionLoading.value = false
  }
}

const showResolveModal = () => {
  resolveComment.value = ''
  resolveModalVisible.value = true
}

const handleResolve = async () => {
  if (!bulletin.value) return
  actionLoading.value = true
  try {
    await vulnBulletinsApi.resolve(bulletin.value.id, resolveComment.value || undefined)
    message.success('通报已标记为修复')
    resolveModalVisible.value = false
    loadBulletin()
  } catch (error) {
    console.error('标记修复失败:', error)
  } finally {
    actionLoading.value = false
  }
}

const showIgnoreModal = () => {
  ignoreReason.value = ''
  ignoreModalVisible.value = true
}

const handleIgnore = async () => {
  if (!bulletin.value) return
  actionLoading.value = true
  try {
    await vulnBulletinsApi.ignore(bulletin.value.id, ignoreReason.value || undefined)
    message.success('通报已忽略')
    ignoreModalVisible.value = false
    loadBulletin()
  } catch (error) {
    console.error('忽略通报失败:', error)
  } finally {
    actionLoading.value = false
  }
}

const handleReopen = async () => {
  if (!bulletin.value) return
  actionLoading.value = true
  try {
    await vulnBulletinsApi.reopen(bulletin.value.id)
    message.success('通报已重新打开')
    loadBulletin()
  } catch (error) {
    console.error('重新打开通报失败:', error)
  } finally {
    actionLoading.value = false
  }
}

onMounted(() => {
  loadBulletin()
})
</script>

<style scoped>
.bulletin-detail-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.page-header {
  display: flex;
  align-items: center;
  margin-bottom: 20px;
}

.page-header h2 {
  margin: 0;
}

.action-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 12px 20px;
}

.action-bar-right {
  display: flex;
  align-items: center;
  gap: 16px;
}

.status-badge {
  font-size: 13px;
  color: var(--mxsec-text-2);
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

.score-critical { color: #EF4444; font-weight: 700; }
.score-high { color: #F59E0B; font-weight: 700; }
.score-normal { color: var(--mxsec-text-1); font-weight: 600; }

.sla-overdue {
  color: #EF4444;
  font-weight: 600;
}
</style>
