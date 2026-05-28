<template>
  <div class="execution-detail-page">
    <div class="page-header">
      <a-button type="link" @click="router.back()" style="padding: 0; margin-right: 8px">
        <template #icon><ArrowLeftOutlined /></template>
        返回
      </a-button>
      <h2>执行详情 #{{ execId }}</h2>
      <a-tag
        v-if="detail"
        :color="statusColor(detail.execution.status)"
        :bordered="false"
        style="margin-left: 12px"
      >
        {{ statusText(detail.execution.status) }}
      </a-tag>
    </div>

    <a-spin :spinning="loading">
      <div v-if="detail">
        <!-- 摘要卡片 -->
        <div class="dashboard-card section-row">
          <div class="card-body">
            <a-descriptions :column="3" bordered size="small">
              <a-descriptions-item label="所属计划">{{ detail.scheduleName }}</a-descriptions-item>
              <a-descriptions-item label="扫描类型">
                <a-tag :color="scanTypeColor(detail.execution.scanType)">
                  {{ scanTypeText(detail.execution.scanType) }}
                </a-tag>
              </a-descriptions-item>
              <a-descriptions-item label="状态">
                <a-tag :color="statusColor(detail.execution.status)" :bordered="false">
                  {{ statusText(detail.execution.status) }}
                </a-tag>
              </a-descriptions-item>
              <a-descriptions-item label="开始时间">{{ formatDate(detail.execution.startedAt) }}</a-descriptions-item>
              <a-descriptions-item label="结束时间">{{ formatDate(detail.execution.finishedAt) }}</a-descriptions-item>
              <a-descriptions-item label="耗时">{{ detail.execution.duration ? detail.execution.duration + 's' : '-' }}</a-descriptions-item>
              <a-descriptions-item label="数据源状态" :span="3" v-if="sourceResults.length > 0">
                <a-tag
                  v-for="src in sourceResults"
                  :key="src.name"
                  :color="src.status === 'success' ? 'green' : src.status === 'skipped' ? 'default' : 'red'"
                  :bordered="false"
                  style="margin-right: 6px"
                >
                  <a-tooltip v-if="src.error" :title="src.error">
                    {{ src.name }}: {{ src.status === 'success' ? '成功' : src.status === 'skipped' ? '跳过' : '失败' }}
                  </a-tooltip>
                  <template v-else>
                    {{ src.name }}: {{ src.status === 'success' ? '成功' : src.status === 'skipped' ? '跳过' : '失败' }}
                  </template>
                </a-tag>
              </a-descriptions-item>
              <a-descriptions-item
                v-if="detail.execution.errorMsg && sourceResults.length === 0"
                label="执行结果"
                :span="3"
              >
                <span :style="{ color: detail.execution.status === 'failed' ? '#EF4444' : 'var(--mxsec-text-1)' }">
                  {{ detail.execution.errorMsg }}
                </span>
              </a-descriptions-item>
            </a-descriptions>
          </div>
        </div>

        <!-- 统计条 -->
        <a-row :gutter="[16, 16]" class="section-row">
          <a-col :span="8">
            <div class="stat-card">
              <div class="stat-value">{{ detail.vulns.total }}</div>
              <div class="stat-label">新增漏洞</div>
            </div>
          </a-col>
          <a-col :span="8">
            <div class="stat-card">
              <div class="stat-value">{{ (detail.affectedHosts || []).length }}</div>
              <div class="stat-label">受影响主机</div>
            </div>
          </a-col>
          <a-col :span="8">
            <div class="stat-card">
              <div class="stat-value">{{ detail.execution.duration || 0 }}s</div>
              <div class="stat-label">执行耗时</div>
            </div>
          </a-col>
        </a-row>

        <!-- 新增漏洞表 -->
        <div class="dashboard-card section-row">
          <div class="card-header">
            <h3>新增漏洞</h3>
          </div>
          <div class="card-body">
            <a-table
              :columns="vulnColumns"
              :data-source="detail.vulns.items || []"
              :loading="vulnLoading"
              size="small"
              row-key="id"
              :pagination="{
                current: vulnPage,
                pageSize: vulnPageSize,
                total: detail.vulns.total,
                showSizeChanger: false,
                showTotal: (t: number) => '共 ' + t + ' 条',
              }"
              @change="handleVulnPageChange"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'cveId'">
                  <router-link :to="{ name: 'VulnDetail', params: { id: record.id } }">
                    {{ record.cveId }}
                  </router-link>
                </template>
                <template v-else-if="column.key === 'severity'">
                  <a-tag :color="severityColor(record.severity)" :bordered="false">
                    {{ severityText(record.severity) }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'cvssScore'">
                  <span :class="cvssClass(record.cvssScore)">{{ record.cvssScore }}</span>
                </template>
              </template>
            </a-table>
          </div>
        </div>

        <!-- 受影响主机 -->
        <div class="dashboard-card section-row">
          <div class="card-header">
            <h3>受影响主机</h3>
          </div>
          <div class="card-body">
            <a-table
              :columns="hostColumns"
              :data-source="detail.affectedHosts || []"
              size="small"
              row-key="hostId"
              :pagination="false"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'hostname'">
                  <router-link :to="{ name: 'HostDetail', params: { hostId: record.hostId } }">
                    {{ record.hostname || record.hostId }}
                  </router-link>
                </template>
              </template>
            </a-table>
          </div>
        </div>
      </div>

      <a-empty v-else-if="!loading" description="执行记录不存在" />
    </a-spin>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeftOutlined } from '@ant-design/icons-vue'
import { scanSchedulesApi } from '@/api/scan-schedules'
import type { ExecutionDetail } from '@/api/scan-schedules'

const route = useRoute()
const router = useRouter()

const execId = Number(route.params.id)
const loading = ref(false)
const vulnLoading = ref(false)
const detail = ref<ExecutionDetail | null>(null)
const vulnPage = ref(1)
const vulnPageSize = 20

// 解析数据源 JSON
const sourceResults = computed(() => {
  const msg = detail.value?.execution.errorMsg
  if (!msg || !msg.startsWith('[')) return []
  try {
    return JSON.parse(msg) as { name: string; status: string; error?: string }[]
  } catch {
    return []
  }
})

const statusColor = (s: string) => ({ success: 'green', failed: 'red', running: 'blue' }[s] || 'default')
const statusText = (s: string) => ({ success: '成功', failed: '失败', running: '执行中' }[s] || s)

const scanTypeColor = (t: string) => ({ full_scan: 'blue', incremental_scan: 'cyan', sync_only: 'green' }[t] || 'default')
const scanTypeText = (t: string) => ({ full_scan: '全量扫描', incremental_scan: '增量扫描', sync_only: '仅同步' }[t] || t)

const severityColor = (s: string) => {
  const m: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
  return m[s] || 'default'
}
const severityText = (s: string) => {
  const m: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }
  return m[s] || s
}
const cvssClass = (score: number) => {
  if (score >= 9) return 'score-critical'
  if (score >= 7) return 'score-high'
  return 'score-normal'
}

const formatDate = (d?: string) => {
  if (!d) return '-'
  return d.replace('T', ' ').substring(0, 19)
}

const vulnColumns = [
  { title: 'CVE ID', dataIndex: 'cveId', key: 'cveId', width: 180 },
  { title: '严重级别', dataIndex: 'severity', key: 'severity', width: 100 },
  { title: 'CVSS', dataIndex: 'cvssScore', key: 'cvssScore', width: 80 },
  { title: '影响组件', dataIndex: 'component', width: 200, ellipsis: true },
  { title: '受影响主机', dataIndex: 'affectedHosts', width: 100 },
  { title: '描述', dataIndex: 'description', ellipsis: true },
]

const hostColumns = [
  { title: '主机名', dataIndex: 'hostname', key: 'hostname', width: 200 },
  { title: 'IP', dataIndex: 'ip', width: 160 },
  { title: '新增漏洞数', dataIndex: 'vulnCount', width: 120 },
]

const loadDetail = async (page = 1) => {
  loading.value = page === 1
  vulnLoading.value = page > 1
  try {
    const data = await scanSchedulesApi.getExecution(execId, page, vulnPageSize)
    detail.value = data ?? null
    vulnPage.value = page
  } catch {
    detail.value = null
  } finally {
    loading.value = false
    vulnLoading.value = false
  }
}

const handleVulnPageChange = (pag: any) => {
  loadDetail(pag.current)
}

onMounted(() => loadDetail())
</script>

<style scoped>
.execution-detail-page { width: 100%; }

.page-header {
  display: flex;
  align-items: center;
  margin-bottom: 24px;
}
.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.section-row { margin-bottom: 16px; }

.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
}
.card-header {
  padding: 16px 20px 0;
}
.card-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}
.card-body { padding: 16px 20px 20px; }

.stat-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 16px 20px;
  text-align: center;
}
.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: var(--mxsec-text-1);
}
.stat-label {
  font-size: 13px;
  color: var(--mxsec-text-3);
  margin-top: 4px;
}

.score-critical { color: #DC2626; font-weight: 700; }
.score-high { color: #D46B08; font-weight: 600; }
.score-normal { color: var(--mxsec-text-1); }
</style>
