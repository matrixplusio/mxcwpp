<template>
  <div class="rasp-vulns-page">
    <div class="page-header">
      <h2>运行时漏洞</h2>
      <span class="page-header-hint">RASP 运行时检测到的应用依赖漏洞 (IAST)</span>
    </div>

    <!-- 统计 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value">{{ stats.total }}</div>
          <div class="vuln-stat-label">漏洞总数</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value" style="color: #F53F3F">{{ stats.critical }}</div>
          <div class="vuln-stat-label">紧急</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value" style="color: #FF7D00">{{ stats.high }}</div>
          <div class="vuln-stat-label">高危</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value" style="color: #00B42A">{{ stats.patched }}</div>
          <div class="vuln-stat-label">已修复</div>
        </div>
      </a-col>
    </a-row>

    <!-- 漏洞列表 -->
    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search v-model:value="searchText" placeholder="搜索 CVE 或组件名" style="width: 240px" allow-clear @search="loadVulns" />
          <a-select v-model:value="filterSeverity" style="width: 120px" placeholder="级别" allow-clear @change="loadVulns">
            <a-select-option value="critical">紧急</a-select-option>
            <a-select-option value="high">高危</a-select-option>
            <a-select-option value="medium">中危</a-select-option>
            <a-select-option value="low">低危</a-select-option>
          </a-select>
          <a-select v-model:value="filterLanguage" style="width: 140px" placeholder="语言" allow-clear @change="loadVulns">
            <a-select-option value="java">Java</a-select-option>
            <a-select-option value="python">Python</a-select-option>
            <a-select-option value="nodejs">Node.js</a-select-option>
            <a-select-option value="php">PHP</a-select-option>
          </a-select>
          <a-select v-model:value="filterStatus" style="width: 120px" placeholder="状态" allow-clear @change="loadVulns">
            <a-select-option value="active">活跃</a-select-option>
            <a-select-option value="patched">已修复</a-select-option>
            <a-select-option value="ignored">已忽略</a-select-option>
          </a-select>
          <div style="flex: 1"></div>
          <a-button type="primary" @click="handleHotFix" :disabled="!selectedRowKeys.length">热修复</a-button>
        </div>

        <a-table
          :columns="columns"
          :data-source="vulns"
          :loading="loading"
          :pagination="pagination"
          :row-selection="{ selectedRowKeys, onChange: onSelectChange }"
          @change="handleTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'cve'">
              <a :href="`https://nvd.nist.gov/vuln/detail/${record.cveId}`" target="_blank" rel="noopener">{{ record.cveId }}</a>
            </template>
            <template v-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity]" :bordered="false">{{ severityTextMap[record.severity] }}</a-tag>
            </template>
            <template v-if="column.key === 'status'">
              <a-tag :color="record.status === 'patched' ? 'green' : record.status === 'ignored' ? 'default' : 'red'" :bordered="false">
                {{ statusTextMap[record.status] }}
              </a-tag>
            </template>
            <template v-if="column.key === 'hotfix'">
              <a-tag v-if="record.hotfixAvailable" color="green" :bordered="false">可热修复</a-tag>
              <span v-else style="color: #86909C">--</span>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="showVulnDetail(record)">详情</a-button>
                <a-button type="link" size="small" v-if="record.hotfixAvailable && record.status === 'active'" @click="applyHotFix(record)">热修复</a-button>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 详情 Drawer -->
    <a-drawer v-model:open="showDetail" :title="detailRecord?.cveId" width="640">
      <template v-if="detailRecord">
        <a-descriptions :column="1" bordered size="small">
          <a-descriptions-item label="CVE 编号">{{ detailRecord.cveId }}</a-descriptions-item>
          <a-descriptions-item label="CVSS 评分"><span :style="{ fontWeight: 600, color: detailRecord.cvssScore >= 9 ? '#F53F3F' : detailRecord.cvssScore >= 7 ? '#FF7D00' : '#1D2129' }">{{ detailRecord.cvssScore }}</span></a-descriptions-item>
          <a-descriptions-item label="影响组件">{{ detailRecord.component }} {{ detailRecord.currentVersion }}</a-descriptions-item>
          <a-descriptions-item label="修复版本">{{ detailRecord.fixedVersion || '暂无' }}</a-descriptions-item>
          <a-descriptions-item label="语言">{{ detailRecord.language }}</a-descriptions-item>
          <a-descriptions-item label="影响应用数">{{ detailRecord.affectedApps }}</a-descriptions-item>
          <a-descriptions-item label="描述">{{ detailRecord.description }}</a-descriptions-item>
          <a-descriptions-item label="调用方法">
            <pre class="method-info">{{ detailRecord.methodInfo }}</pre>
          </a-descriptions-item>
        </a-descriptions>
      </template>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import apiClient from '@/api/client'

const searchText = ref('')
const filterSeverity = ref<string>()
const filterLanguage = ref<string>()
const filterStatus = ref<string>()
const loading = ref(false)
const vulns = ref<any[]>([])
const selectedRowKeys = ref<string[]>([])
const showDetail = ref(false)
const detailRecord = ref<any>(null)
const stats = ref({ total: 0, critical: 0, high: 0, patched: 0 })

const pagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const severityColorMap: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityTextMap: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }
const statusTextMap: Record<string, string> = { active: '活跃', patched: '已修复', ignored: '已忽略' }

const columns = [
  { title: 'CVE', key: 'cve', width: 160 },
  { title: '级别', key: 'severity', width: 80 },
  { title: '组件', dataIndex: 'component', key: 'component', width: 180 },
  { title: '当前版本', dataIndex: 'currentVersion', key: 'currentVersion', width: 120 },
  { title: '修复版本', dataIndex: 'fixedVersion', key: 'fixedVersion', width: 120 },
  { title: '语言', dataIndex: 'language', key: 'language', width: 80 },
  { title: '影响应用', dataIndex: 'affectedApps', key: 'affectedApps', width: 90 },
  { title: '热修复', key: 'hotfix', width: 100 },
  { title: '状态', key: 'status', width: 90 },
  { title: '发现时间', dataIndex: 'discoveredAt', key: 'discoveredAt', width: 180 },
  { title: '操作', key: 'action', width: 130 },
]

const onSelectChange = (keys: string[]) => { selectedRowKeys.value = keys }

const loadVulns = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/rasp/vulns', {
      params: { page: pagination.value.current, page_size: pagination.value.pageSize, search: searchText.value || undefined, severity: filterSeverity.value || undefined, language: filterLanguage.value || undefined, status: filterStatus.value || undefined },
    })
    vulns.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    if (res.stats) stats.value = res.stats
  } catch { vulns.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadVulns() }
const showVulnDetail = (record: any) => { detailRecord.value = record; showDetail.value = true }

const applyHotFix = async (record: any) => {
  try { await apiClient.post(`/rasp/vulns/${record.id}/hotfix`); message.success('热修复已应用'); loadVulns() }
  catch { message.error('热修复失败') }
}

const handleHotFix = async () => {
  try { await apiClient.post('/rasp/vulns/batch-hotfix', { ids: selectedRowKeys.value }); message.success('批量热修复已应用'); selectedRowKeys.value = []; loadVulns() }
  catch { message.error('批量热修复失败') }
}

onMounted(() => { loadVulns() })
</script>

<style scoped>
.rasp-vulns-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.vuln-stat-card { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; padding: 20px; text-align: center; }
.vuln-stat-value { font-size: 28px; font-weight: 700; color: #1D2129; line-height: 1.2; }
.vuln-stat-label { font-size: 13px; color: #86909C; margin-top: 4px; }

.dashboard-card { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 16px; padding: 12px 16px; background: #F7F8FA; border-radius: 4px; border: 1px solid #E5E8EF; flex-wrap: wrap; }

.method-info { background: #F7F8FA; padding: 8px; border-radius: 4px; font-size: 11px; font-family: 'SF Mono', 'Consolas', monospace; white-space: pre-wrap; margin: 0; color: #1D2129; }
</style>
