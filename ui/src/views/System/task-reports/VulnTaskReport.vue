<template>
  <div>
    <!-- 时间范围选择 + 历史列表 -->
    <div v-if="!report">
      <div class="time-range-selector">
        <a-space>
          <a-range-picker v-model:value="dateRange" :format="'YYYY-MM-DD'" />
          <a-button type="primary" @click="generateReport" :loading="loading">
            生成报告
          </a-button>
        </a-space>
      </div>
      <a-table
        v-if="savedReports.length > 0"
        :columns="reportColumns"
        :data-source="savedReports"
        :loading="loadingSaved"
        row-key="id"
        :pagination="{ pageSize: 10, showTotal: (total: number) => `共 ${total} 条` }"
        style="margin-top: 16px"
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
      </a-table>
    </div>

    <!-- 报告详情 -->
    <div v-if="report" class="report-detail-wrapper">
      <div class="report-header">
        <a-button @click="handleBackToList">
          <template #icon><ArrowLeftOutlined /></template>
          返回
        </a-button>
        <a-button type="primary" @click="exportPDF" :loading="exportingPDF" ghost>
          <template #icon><FilePdfOutlined /></template>
          导出 PDF
        </a-button>
      </div>

      <div ref="reportContent" class="report-container">
        <!-- 1. 封面 -->
        <div class="report-page cover-page">
          <div class="cover-content">
            <div class="cover-logo">
              <img src="/logo.png" alt="Logo" style="width: 80px; height: 80px; object-fit: contain;" />
            </div>
            <h1 class="cover-title">{{ report.meta.reportTitle }}</h1>
            <div class="cover-subtitle">Vulnerability Management Report</div>
            <div class="cover-info">
              <div class="cover-info-item">
                <span class="label">报告周期：</span>
                <span class="value">{{ report.meta.reportPeriod }}</span>
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
            <div class="conclusion-banner" :class="report.summary.hasCriticalVuln ? 'critical' : report.summary.hasHighVuln ? 'high' : report.statistics.totalVulns > 0 ? 'warning' : 'success'">
              <div class="conclusion-icon">
                <CheckCircleOutlined v-if="report.statistics.totalVulns === 0" />
                <ExclamationCircleOutlined v-else />
              </div>
              <div class="conclusion-text">{{ report.summary.overallConclusion }}</div>
            </div>
            <div class="summary-content">
              <p class="summary-paragraph">{{ report.summary.vulnOverview }}</p>
              <div class="summary-stats">
                <div class="stat-item">
                  <div class="stat-value" style="color: #F53F3F">{{ report.statistics.totalVulns }}</div>
                  <div class="stat-label">总漏洞数</div>
                </div>
                <div class="stat-item">
                  <div class="stat-value" style="color: #FF7D00">{{ report.statistics.unpatchedVulns }}</div>
                  <div class="stat-label">未修复</div>
                </div>
                <div class="stat-item">
                  <div class="stat-value">{{ report.statistics.affectedHosts }}</div>
                  <div class="stat-label">影响主机</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 3. 报告周期 -->
        <div class="report-page">
          <div class="section-header">
            <div class="section-number">2</div>
            <div class="section-title">报告周期</div>
            <div class="section-subtitle">Report Period</div>
          </div>
          <table class="info-table">
            <tbody>
              <tr>
                <td class="label-cell">报告周期</td>
                <td class="value-cell">{{ report.meta.reportPeriod }}</td>
                <td class="label-cell">影响主机</td>
                <td class="value-cell">{{ report.statistics.affectedHosts }} 台</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 4. 漏洞统计 -->
        <div class="report-page">
          <div class="section-header">
            <div class="section-number">3</div>
            <div class="section-title">漏洞统计</div>
            <div class="section-subtitle">Vulnerability Statistics</div>
          </div>
          <div class="stats-grid">
            <div class="stats-card" style="border-left: 4px solid #F53F3F">
              <div class="stats-info">
                <div class="stats-value" style="color: #F53F3F">{{ report.statistics.unpatchedVulns }}</div>
                <div class="stats-label">未修复</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #00B42A">
              <div class="stats-info">
                <div class="stats-value" style="color: #00B42A">{{ report.statistics.fixedVulns }}</div>
                <div class="stats-label">已修复</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #86909C">
              <div class="stats-info">
                <div class="stats-value" style="color: #86909C">{{ report.statistics.ignoredVulns }}</div>
                <div class="stats-label">已忽略</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #165DFF">
              <div class="stats-info">
                <div class="stats-value" style="color: #165DFF">{{ report.statistics.affectedHosts }}</div>
                <div class="stats-label">影响主机</div>
              </div>
            </div>
          </div>
          <div class="severity-distribution" v-if="report.statistics.totalVulns > 0">
            <h4>按严重级别分布</h4>
            <div class="severity-bars">
              <div class="severity-bar-item" v-for="(count, severity) in report.statistics.bySeverity" :key="severity">
                <div class="severity-label">
                  <span class="severity-tag" :class="severity">{{ getSeverityLabel(severity as string) }}</span>
                </div>
                <div class="severity-bar-container">
                  <div class="severity-bar" :class="severity" :style="{ width: `${(count / report.statistics.totalVulns) * 100}%` }"></div>
                </div>
                <div class="severity-count">{{ count }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- 5. 组件分布 -->
        <div class="report-page" v-if="report.statistics.byComponent.length > 0">
          <div class="section-header">
            <div class="section-number">4</div>
            <div class="section-title">组件漏洞分布</div>
            <div class="section-subtitle">Component Distribution</div>
          </div>
          <div class="severity-distribution">
            <div class="severity-bars">
              <div class="severity-bar-item" v-for="item in report.statistics.byComponent" :key="item.component">
                <div class="severity-label">
                  <span class="severity-tag medium">{{ item.component }}</span>
                </div>
                <div class="severity-bar-container">
                  <div class="severity-bar medium" :style="{ width: `${(item.count / report.statistics.totalVulns) * 100}%` }"></div>
                </div>
                <div class="severity-count">{{ item.count }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- 6. 主机明细 -->
        <div class="report-page" v-if="report.hostDetails.length > 0">
          <div class="section-header">
            <div class="section-number">{{ report.statistics.byComponent.length > 0 ? '5' : '4' }}</div>
            <div class="section-title">主机漏洞明细</div>
            <div class="section-subtitle">Host Vulnerability Details</div>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th>主机名</th>
                <th>IP</th>
                <th>漏洞数</th>
                <th>严重</th>
                <th>高危</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="host in report.hostDetails" :key="host.hostId">
                <td>{{ host.hostname || host.hostId }}</td>
                <td>{{ host.ip || '-' }}</td>
                <td><span style="color: #F53F3F">{{ host.vulnCount }}</span></td>
                <td><span v-if="host.criticalCount > 0" style="color: #F53F3F; font-weight: 600">{{ host.criticalCount }}</span><span v-else>0</span></td>
                <td><span v-if="host.highCount > 0" style="color: #FF7D00; font-weight: 600">{{ host.highCount }}</span><span v-else>0</span></td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 7. Top 高危漏洞 -->
        <div class="report-page" v-if="report.topVulns.length > 0">
          <div class="section-header">
            <div class="section-number">{{ getTopVulnSection() }}</div>
            <div class="section-title">Top 高危漏洞</div>
            <div class="section-subtitle">Top Vulnerabilities</div>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>级别</th>
                <th>CVSS</th>
                <th>组件</th>
                <th>影响主机</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="vuln in report.topVulns" :key="vuln.cveId">
                <td>{{ vuln.cveId }}</td>
                <td><span class="severity-tag" :class="vuln.severity">{{ getSeverityLabel(vuln.severity) }}</span></td>
                <td>{{ vuln.cvssScore }}</td>
                <td>{{ vuln.component || '-' }}</td>
                <td>{{ vuln.affectedHosts }}</td>
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
import type { Dayjs } from 'dayjs'
import dayjs from 'dayjs'
import {
  FilePdfOutlined,
  FileTextOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  ArrowLeftOutlined,
} from '@ant-design/icons-vue'
import { reportsApi, type VulnerabilityExecutiveReport, type GeneratedReportItem } from '@/api/reports'
import html2pdf from 'html2pdf.js'

const loading = ref(false)
const exportingPDF = ref(false)
const loadingSaved = ref(false)
const dateRange = ref<[Dayjs, Dayjs]>([dayjs().subtract(7, 'day'), dayjs()])
const report = ref<VulnerabilityExecutiveReport | null>(null)
const reportContent = ref<HTMLElement | null>(null)
const savedReports = ref<GeneratedReportItem[]>([])

const reportColumns = [
  { title: '报告标题', dataIndex: 'title', key: 'title' },
  { title: '报告编号', dataIndex: 'report_id', key: 'report_id', width: 200 },
  { title: '报告周期', dataIndex: 'period', key: 'period', width: 200 },
  { title: '生成时间', key: 'created_at', width: 180 },
  { title: '操作', key: 'actions', width: 160, fixed: 'right' as const },
]

const loadSavedReports = async () => {
  loadingSaved.value = true
  try {
    const res = await reportsApi.listGeneratedReports('vulnerability')
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

const generateReport = async () => {
  if (!dateRange.value || dateRange.value.length !== 2) {
    message.warning('请选择日期范围')
    return
  }
  loading.value = true
  try {
    report.value = await reportsApi.getVulnerabilityExecutiveReport({
      start_time: dateRange.value[0].format('YYYY-MM-DD'),
      end_time: dateRange.value[1].format('YYYY-MM-DD'),
    })
  } catch (error: any) {
    message.error(error.message || '生成报告失败')
  } finally {
    loading.value = false
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
    const period = report.value.meta.reportPeriod.replace(/\s/g, '')
    const dateStr = new Date().toISOString().split('T')[0]
    const filename = `漏洞管理报告-${period}_${dateStr}.pdf`
    reportContent.value.classList.add('pdf-exporting')
    const options = {
      margin: [10, 10, 10, 10] as [number, number, number, number],
      filename,
      image: { type: 'jpeg' as const, quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true, logging: false, letterRendering: true, width: 820, windowWidth: 820, scrollX: 0, scrollY: 0 },
      jsPDF: { unit: 'mm' as const, format: 'a4' as const, orientation: 'portrait' as const },
      pagebreak: { mode: ['css', 'legacy'], avoid: ['tr', 'p', 'li', '.stats-card', '.severity-bar-item', '.conclusion-banner', '.info-table', '.appendix'] },
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

const getSeverityLabel = (severity: string): string => {
  const labels: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
  return labels[severity] || severity
}

const getTopVulnSection = (): string => {
  if (!report.value) return '6'
  let n = 4
  if (report.value.statistics.byComponent.length > 0) n++
  if (report.value.hostDetails.length > 0) n++
  return String(n)
}

const getLastSection = (): string => {
  if (!report.value) return '7'
  let n = 4
  if (report.value.statistics.byComponent.length > 0) n++
  if (report.value.hostDetails.length > 0) n++
  if (report.value.topVulns.length > 0) n++
  return String(n)
}

onMounted(() => { loadSavedReports() })
</script>

<style lang="less" scoped>
.time-range-selector {
  padding: 24px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
}
</style>
