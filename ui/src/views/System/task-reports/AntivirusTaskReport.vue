<template>
  <div>
    <!-- 任务列表 -->
    <div v-if="!report">
      <a-tabs v-model:activeKey="activeSubTab">
        <a-tab-pane key="tasks" tab="扫描任务">
          <a-table
            :columns="taskColumns"
            :data-source="completedTasks"
            :loading="loadingTasks"
            row-key="id"
            :pagination="{ pageSize: 15, showSizeChanger: true, showTotal: (total: number) => `共 ${total} 条` }"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'name'">
                <span class="task-name">{{ record.name }}</span>
              </template>
              <template v-else-if="column.key === 'scanType'">
                <a-tag color="blue">{{ getScanTypeLabel(record.scanType) }}</a-tag>
              </template>
              <template v-else-if="column.key === 'hostCount'">
                {{ record.totalHosts || 0 }} 台
              </template>
              <template v-else-if="column.key === 'threatCount'">
                <span :style="{ color: record.threatCount > 0 ? '#F53F3F' : '#00B42A' }">{{ record.threatCount || 0 }}</span>
              </template>
              <template v-else-if="column.key === 'finishedAt'">
                {{ formatDateTime(record.finishedAt) }}
              </template>
              <template v-else-if="column.key === 'actions'">
                <a-button type="primary" size="small" @click="handleViewReport(record)">
                  <template #icon><FileTextOutlined /></template>
                  查看报告
                </a-button>
              </template>
            </template>
            <template #emptyText>
              <a-empty description="暂无已完成的扫描任务" />
            </template>
          </a-table>
        </a-tab-pane>
        <a-tab-pane key="saved" :tab="`已保存报告 (${savedReports.length})`">
          <a-table
            :columns="reportColumns"
            :data-source="savedReports"
            :loading="loadingSaved"
            row-key="id"
            :pagination="{ pageSize: 10, showTotal: (total: number) => `共 ${total} 条` }"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'created_at'">
                {{ record.created_at }}
              </template>
              <template v-else-if="column.key === 'actions'">
                <a-space>
                  <a-button type="primary" size="small" @click="handleViewSaved(record)">
                    <template #icon><FileTextOutlined /></template>
                    查看
                  </a-button>
                  <a-popconfirm title="确定删除此报告？" @confirm="handleDeleteSaved(record.id)">
                    <a-button size="small" danger>删除</a-button>
                  </a-popconfirm>
                </a-space>
              </template>
            </template>
            <template #emptyText>
              <a-empty description="暂无已保存的报告" />
            </template>
          </a-table>
        </a-tab-pane>
      </a-tabs>
    </div>

    <!-- 报告详情 -->
    <div v-if="report" class="report-detail-wrapper">
      <div class="report-header">
        <a-button @click="handleBackToList">
          <template #icon><ArrowLeftOutlined /></template>
          返回列表
        </a-button>
        <a-button type="primary" @click="exportPDF" :loading="exportingPDF" ghost>
          <template #icon><FilePdfOutlined /></template>
          导出 PDF
        </a-button>
      </div>

      <div ref="reportContent" class="report-container">
        <!-- 1. 封面页 -->
        <div class="report-page cover-page">
          <div class="cover-content">
            <div class="cover-logo">
              <img src="/logo.png" alt="Logo" style="width: 80px; height: 80px; object-fit: contain;" />
            </div>
            <h1 class="cover-title">{{ report.meta.reportTitle }}</h1>
            <div class="cover-subtitle">Antivirus Scan Report</div>
            <div class="cover-info">
              <div class="cover-info-item">
                <span class="label">扫描类型：</span>
                <span class="value">{{ report.meta.scanType }}</span>
              </div>
              <div class="cover-info-item">
                <span class="label">检查对象：</span>
                <span class="value">{{ report.meta.checkTarget }}</span>
              </div>
              <div class="cover-info-item">
                <span class="label">报告编号：</span>
                <span class="value">{{ report.meta.reportId }}</span>
              </div>
              <div class="cover-info-item">
                <span class="label">生成时间：</span>
                <span class="value">{{ report.meta.generatedAt }}</span>
              </div>
            </div>
            <div class="cover-company">{{ report.meta.companyName }}</div>
          </div>
        </div>

        <!-- 2. 报告摘要 -->
        <div class="report-page">
          <div class="section-header">
            <div class="section-number">1</div>
            <div class="section-title">报告摘要</div>
            <div class="section-subtitle">Executive Summary</div>
          </div>
          <div class="executive-summary">
            <div class="conclusion-banner" :class="getConclusionClass()">
              <div class="conclusion-icon">
                <CheckCircleOutlined v-if="!report.summary.hasCriticalThreat && !report.summary.hasHighThreat && report.statistics.totalThreats === 0" />
                <ExclamationCircleOutlined v-else />
              </div>
              <div class="conclusion-text">{{ report.summary.overallConclusion }}</div>
            </div>
            <div class="summary-content">
              <p class="summary-paragraph">{{ report.summary.threatOverview }}</p>
              <div class="summary-stats">
                <div class="stat-item">
                  <div class="stat-value">{{ report.taskInfo.hostCount }}</div>
                  <div class="stat-label">扫描主机</div>
                </div>
                <div class="stat-item">
                  <div class="stat-value" style="color: #F53F3F">{{ report.statistics.totalThreats }}</div>
                  <div class="stat-label">发现威胁</div>
                </div>
                <div class="stat-item">
                  <div class="stat-value" style="color: #FF7D00">{{ report.statistics.quarantinedThreats + report.statistics.deletedThreats }}</div>
                  <div class="stat-label">已处置</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 3. 扫描信息 -->
        <div class="report-page">
          <div class="section-header">
            <div class="section-number">2</div>
            <div class="section-title">扫描信息</div>
            <div class="section-subtitle">Scan Information</div>
          </div>
          <table class="info-table">
            <tbody>
              <tr>
                <td class="label-cell">任务名称</td>
                <td class="value-cell">{{ report.taskInfo.taskName }}</td>
                <td class="label-cell">扫描类型</td>
                <td class="value-cell">{{ getScanTypeLabel(report.taskInfo.scanType) }}</td>
              </tr>
              <tr>
                <td class="label-cell">扫描主机数</td>
                <td class="value-cell">{{ report.taskInfo.scannedHosts }} / {{ report.taskInfo.hostCount }} 台</td>
                <td class="label-cell">发现威胁</td>
                <td class="value-cell">{{ report.taskInfo.threatCount }} 个</td>
              </tr>
              <tr>
                <td class="label-cell">开始时间</td>
                <td class="value-cell">{{ report.taskInfo.startedAt || '-' }}</td>
                <td class="label-cell">结束时间</td>
                <td class="value-cell">{{ report.taskInfo.finishedAt || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 4. 威胁统计 -->
        <div class="report-page">
          <div class="section-header">
            <div class="section-number">3</div>
            <div class="section-title">威胁统计</div>
            <div class="section-subtitle">Threat Statistics</div>
          </div>
          <div class="stats-grid">
            <div class="stats-card" style="border-left: 4px solid #F53F3F">
              <div class="stats-info">
                <div class="stats-value" style="color: #F53F3F">{{ report.statistics.detectedThreats }}</div>
                <div class="stats-label">已检测</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #FF7D00">
              <div class="stats-info">
                <div class="stats-value" style="color: #FF7D00">{{ report.statistics.quarantinedThreats }}</div>
                <div class="stats-label">已隔离</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #165DFF">
              <div class="stats-info">
                <div class="stats-value" style="color: #165DFF">{{ report.statistics.deletedThreats }}</div>
                <div class="stats-label">已删除</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #86909C">
              <div class="stats-info">
                <div class="stats-value" style="color: #86909C">{{ report.statistics.ignoredThreats }}</div>
                <div class="stats-label">已忽略</div>
              </div>
            </div>
          </div>

          <!-- 严重级别分布 -->
          <div class="severity-distribution" v-if="report.statistics.totalThreats > 0">
            <h4>按严重级别分布</h4>
            <div class="severity-bars">
              <div class="severity-bar-item" v-for="(count, severity) in report.statistics.bySeverity" :key="severity">
                <div class="severity-label">
                  <span class="severity-tag" :class="severity">{{ getSeverityLabel(severity as string) }}</span>
                </div>
                <div class="severity-bar-container">
                  <div class="severity-bar" :class="severity" :style="{ width: `${(count / report.statistics.totalThreats) * 100}%` }"></div>
                </div>
                <div class="severity-count">{{ count }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- 5. 威胁类型分布 -->
        <div class="report-page" v-if="Object.keys(report.statistics.byThreatType).length > 0">
          <div class="section-header">
            <div class="section-number">4</div>
            <div class="section-title">威胁类型分布</div>
            <div class="section-subtitle">Threat Type Distribution</div>
          </div>
          <div class="severity-distribution">
            <div class="severity-bars">
              <div class="severity-bar-item" v-for="(count, threatType) in report.statistics.byThreatType" :key="threatType">
                <div class="severity-label">
                  <span class="severity-tag medium">{{ getThreatTypeLabel(threatType as string) }}</span>
                </div>
                <div class="severity-bar-container">
                  <div class="severity-bar medium" :style="{ width: `${(count / report.statistics.totalThreats) * 100}%` }"></div>
                </div>
                <div class="severity-count">{{ count }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- 6. 主机扫描明细 -->
        <div class="report-page" v-if="report.hostDetails.length > 0">
          <div class="section-header">
            <div class="section-number">{{ Object.keys(report.statistics.byThreatType).length > 0 ? '5' : '4' }}</div>
            <div class="section-title">主机扫描明细</div>
            <div class="section-subtitle">Host Scan Details</div>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th>主机名</th>
                <th>IP</th>
                <th>威胁数</th>
                <th>严重</th>
                <th>高危</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="host in report.hostDetails" :key="host.hostId">
                <td>{{ host.hostname || host.hostId }}</td>
                <td>{{ host.ip || '-' }}</td>
                <td><span style="color: #F53F3F">{{ host.threatCount }}</span></td>
                <td><span v-if="host.criticalCount > 0" style="color: #F53F3F; font-weight: 600">{{ host.criticalCount }}</span><span v-else>0</span></td>
                <td><span v-if="host.highCount > 0" style="color: #FF7D00; font-weight: 600">{{ host.highCount }}</span><span v-else>0</span></td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 7. Top 威胁列表 -->
        <div class="report-page" v-if="report.topThreats.length > 0">
          <div class="section-header">
            <div class="section-number">{{ getNextSection() }}</div>
            <div class="section-title">Top 威胁列表</div>
            <div class="section-subtitle">Top Threats</div>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th>威胁名称</th>
                <th>级别</th>
                <th>数量</th>
                <th>影响主机</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="threat in report.topThreats" :key="threat.threatName">
                <td>{{ threat.threatName }}</td>
                <td><span class="severity-tag" :class="threat.severity">{{ getSeverityLabel(threat.severity) }}</span></td>
                <td>{{ threat.count }}</td>
                <td>{{ threat.affectedHosts }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 8. 结论与建议 -->
        <div class="report-page">
          <div class="section-header">
            <div class="section-number">{{ getLastSection() }}</div>
            <div class="section-title">结论与建议</div>
            <div class="section-subtitle">Conclusion & Recommendations</div>
          </div>
          <div class="recommendation-section">
            <div class="overall-assessment">
              <h4>总体评估</h4>
              <p>{{ report.recommendation.overallAssessment }}</p>
            </div>
            <div class="action-suggestions">
              <h4>行动建议</h4>
              <ul>
                <li v-for="(s, i) in report.recommendation.actionSuggestions" :key="i">{{ s }}</li>
              </ul>
            </div>
          </div>
        </div>

        <!-- 附录 -->
        <div class="report-page appendix">
          <div class="section-header">
            <div class="section-number">附录</div>
            <div class="section-title">声明与说明</div>
            <div class="section-subtitle">Appendix</div>
          </div>
          <div class="appendix-content">
            <div class="disclaimer">
              <h4>报告声明</h4>
              <p>{{ report.recommendation.disclaimer }}</p>
            </div>
            <div class="report-info">
              <p><strong>报告生成系统：</strong>矩阵云安全平台 (MxSec Platform)</p>
              <p><strong>报告生成时间：</strong>{{ report.meta.generatedAt }}</p>
              <p><strong>报告编号：</strong>{{ report.meta.reportId }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import {
  FileTextOutlined,
  FilePdfOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  ArrowLeftOutlined,
} from '@ant-design/icons-vue'
import { reportsApi, type AntivirusExecutiveReport, type GeneratedReportItem } from '@/api/reports'
import { antivirusApi } from '@/api/antivirus'
import html2pdf from 'html2pdf.js'

const loading = ref(false)
const loadingTasks = ref(false)
const exportingPDF = ref(false)
const loadingSaved = ref(false)
const activeSubTab = ref('tasks')
const completedTasks = ref<any[]>([])
const report = ref<AntivirusExecutiveReport | null>(null)
const reportContent = ref<HTMLElement | null>(null)
const savedReports = ref<GeneratedReportItem[]>([])

const taskColumns = [
  { title: '任务名称', key: 'name', dataIndex: 'name', ellipsis: true },
  { title: '扫描类型', key: 'scanType', width: 120 },
  { title: '主机数', key: 'hostCount', width: 100 },
  { title: '威胁数', key: 'threatCount', width: 100 },
  { title: '完成时间', key: 'finishedAt', width: 180 },
  { title: '操作', key: 'actions', width: 120, fixed: 'right' as const },
]

const loadCompletedTasks = async () => {
  loadingTasks.value = true
  try {
    const res = await antivirusApi.listTasks({ status: 'completed', page_size: 100 }) as any
    completedTasks.value = res.items || []
  } catch (error: any) {
    message.error(error.message || '加载任务列表失败')
  } finally {
    loadingTasks.value = false
  }
}

const reportColumns = [
  { title: '报告标题', dataIndex: 'title', key: 'title' },
  { title: '报告编号', dataIndex: 'report_id', key: 'report_id', width: 200 },
  { title: '生成时间', key: 'created_at', width: 180 },
  { title: '操作', key: 'actions', width: 160, fixed: 'right' as const },
]

const loadSavedReports = async () => {
  loadingSaved.value = true
  try {
    const res = await reportsApi.listGeneratedReports('antivirus')
    savedReports.value = res.items || []
  } catch { /* ignore */ } finally {
    loadingSaved.value = false
  }
}

const handleViewSaved = async (record: GeneratedReportItem) => {
  loading.value = true
  try {
    report.value = await reportsApi.getGeneratedReport(record.id)
  } catch (error: any) {
    message.error(error.message || '加载报告失败')
  } finally {
    loading.value = false
  }
}

const handleDeleteSaved = async (id: number) => {
  try {
    await reportsApi.deleteGeneratedReport(id)
    message.success('删除成功')
    await loadSavedReports()
  } catch (error: any) {
    message.error(error.message || '删除失败')
  }
}

const handleViewReport = async (task: any) => {
  try {
    report.value = await reportsApi.getAntivirusExecutiveReport(task.id)
  } catch (error: any) {
    message.error(error.message || '生成报告失败')
  }
}

const handleBackToList = () => {
  report.value = null
  loadSavedReports()
}

const exportPDF = async () => {
  if (!report.value || !reportContent.value) return
  exportingPDF.value = true
  try {
    const taskName = report.value.taskInfo.taskName.replace(/[\/\\:*?"<>|]/g, '_')
    const dateStr = new Date().toISOString().split('T')[0]
    const filename = `病毒查杀报告-${taskName}_${dateStr}.pdf`

    reportContent.value.classList.add('pdf-exporting')
    const options = {
      margin: [10, 10, 10, 10] as [number, number, number, number],
      filename,
      image: { type: 'jpeg' as const, quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true, logging: false, letterRendering: true, width: 820, windowWidth: 820, scrollX: 0, scrollY: 0 },
      jsPDF: { unit: 'mm' as const, format: 'a4' as const, orientation: 'portrait' as const },
      pagebreak: { mode: ['css', 'legacy'], avoid: ['tr', 'p', 'li', '.stats-card', '.severity-bar-item', '.conclusion-banner', '.info-table', '.risk-item', '.appendix'] },
    }
    await html2pdf().set(options).from(reportContent.value).save()
    message.success('PDF 导出成功')
  } catch (error: any) {
    message.error('PDF 导出失败: ' + (error.message || '未知错误'))
  } finally {
    reportContent.value?.classList.remove('pdf-exporting')
    exportingPDF.value = false
  }
}

const formatDateTime = (dateStr: string | null): string => {
  if (!dateStr) return '-'
  return dateStr.replace('T', ' ').substring(0, 19)
}

const getScanTypeLabel = (type: string): string => {
  const labels: Record<string, string> = { quick: '快速扫描', full: '全盘扫描', custom: '自定义扫描' }
  return labels[type] || type
}

const getSeverityLabel = (severity: string): string => {
  const labels: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
  return labels[severity] || severity
}

const getThreatTypeLabel = (type: string): string => {
  const labels: Record<string, string> = {
    virus: '病毒', trojan: '木马', worm: '蠕虫', ransomware: '勒索软件',
    rootkit: 'Rootkit', miner: '挖矿程序', backdoor: '后门', other: '其他',
  }
  return labels[type] || type
}

const getConclusionClass = (): string => {
  if (!report.value) return ''
  if (report.value.summary.hasCriticalThreat) return 'critical'
  if (report.value.summary.hasHighThreat) return 'high'
  if (report.value.statistics.totalThreats > 0) return 'warning'
  return 'success'
}

const getNextSection = (): string => {
  if (!report.value) return '6'
  const base = Object.keys(report.value.statistics.byThreatType).length > 0 ? 6 : 5
  return String(base)
}

const getLastSection = (): string => {
  if (!report.value) return '7'
  let n = 4
  if (Object.keys(report.value.statistics.byThreatType).length > 0) n++
  if (report.value.hostDetails.length > 0) n++
  if (report.value.topThreats.length > 0) n++
  return String(n)
}

onMounted(() => {
  loadCompletedTasks()
  loadSavedReports()
})
</script>
