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
            <div class="cover-subtitle">Container Security Assessment Report</div>
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
            <div class="conclusion-banner" :class="report.summary.hasCriticalAlarm ? 'critical' : report.alarmStatistics.totalAlarms > 0 ? 'warning' : 'success'">
              <div class="conclusion-icon">
                <CheckCircleOutlined v-if="report.alarmStatistics.totalAlarms === 0 && report.baselineStatistics.failed === 0" />
                <ExclamationCircleOutlined v-else />
              </div>
              <div class="conclusion-text">{{ report.summary.overallConclusion }}</div>
            </div>
            <div class="summary-content">
              <p class="summary-paragraph">{{ report.summary.alarmOverview }}</p>
              <p class="summary-paragraph">{{ report.summary.baselineOverview }}</p>
              <div class="summary-stats">
                <div class="stat-item">
                  <div class="stat-value" style="color: #F53F3F">{{ report.alarmStatistics.totalAlarms }}</div>
                  <div class="stat-label">容器告警</div>
                </div>
                <div class="stat-item">
                  <div class="stat-value" style="color: #FF7D00">{{ report.alarmStatistics.pendingAlarms }}</div>
                  <div class="stat-label">待处理</div>
                </div>
                <div class="stat-item">
                  <div class="stat-value">{{ report.baselineStatistics.totalChecks }}</div>
                  <div class="stat-label">基线检查项</div>
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
                <td class="label-cell">集群数量</td>
                <td class="value-cell">{{ report.meta.checkTarget }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 4. 告警统计 -->
        <div class="report-page">
          <div class="section-header">
            <div class="section-number">3</div>
            <div class="section-title">告警统计</div>
            <div class="section-subtitle">Alarm Statistics</div>
          </div>
          <div class="stats-grid">
            <div class="stats-card" style="border-left: 4px solid #F53F3F">
              <div class="stats-info">
                <div class="stats-value" style="color: #F53F3F">{{ report.alarmStatistics.totalAlarms }}</div>
                <div class="stats-label">总告警</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #FF7D00">
              <div class="stats-info">
                <div class="stats-value" style="color: #FF7D00">{{ report.alarmStatistics.pendingAlarms }}</div>
                <div class="stats-label">待处理</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #00B42A">
              <div class="stats-info">
                <div class="stats-value" style="color: #00B42A">{{ report.alarmStatistics.processedAlarms }}</div>
                <div class="stats-label">已处理</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #86909C">
              <div class="stats-info">
                <div class="stats-value" style="color: #86909C">{{ report.alarmStatistics.ignoredAlarms }}</div>
                <div class="stats-label">已忽略</div>
              </div>
            </div>
          </div>
          <div class="severity-distribution" v-if="report.alarmStatistics.totalAlarms > 0">
            <h4>按严重级别分布</h4>
            <div class="severity-bars">
              <div class="severity-bar-item" v-for="(count, severity) in report.alarmStatistics.bySeverity" :key="severity">
                <div class="severity-label">
                  <span class="severity-tag" :class="severity">{{ getSeverityLabel(severity as string) }}</span>
                </div>
                <div class="severity-bar-container">
                  <div class="severity-bar" :class="severity" :style="{ width: `${(count / report.alarmStatistics.totalAlarms) * 100}%` }"></div>
                </div>
                <div class="severity-count">{{ count }}</div>
              </div>
            </div>
          </div>
          <div class="severity-distribution" v-if="Object.keys(report.alarmStatistics.byAlarmType).length > 0" style="margin-top: 20px">
            <h4>按告警类型分布</h4>
            <div class="severity-bars">
              <div class="severity-bar-item" v-for="(count, alarmType) in report.alarmStatistics.byAlarmType" :key="alarmType">
                <div class="severity-label">
                  <span class="severity-tag medium">{{ getAlarmTypeLabel(alarmType as string) }}</span>
                </div>
                <div class="severity-bar-container">
                  <div class="severity-bar medium" :style="{ width: `${(count / report.alarmStatistics.totalAlarms) * 100}%` }"></div>
                </div>
                <div class="severity-count">{{ count }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- 5. CIS 基线检查结果 -->
        <div class="report-page" v-if="report.baselineStatistics.totalChecks > 0">
          <div class="section-header">
            <div class="section-number">4</div>
            <div class="section-title">CIS 基线检查结果</div>
            <div class="section-subtitle">CIS Baseline Results</div>
          </div>
          <div class="stats-grid">
            <div class="stats-card" style="border-left: 4px solid #00B42A">
              <div class="stats-info">
                <div class="stats-value" style="color: #00B42A">{{ report.baselineStatistics.passed }}</div>
                <div class="stats-label">通过</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #F53F3F">
              <div class="stats-info">
                <div class="stats-value" style="color: #F53F3F">{{ report.baselineStatistics.failed }}</div>
                <div class="stats-label">失败</div>
              </div>
            </div>
            <div class="stats-card" style="border-left: 4px solid #FF7D00">
              <div class="stats-info">
                <div class="stats-value" style="color: #FF7D00">{{ report.baselineStatistics.warning }}</div>
                <div class="stats-label">警告</div>
              </div>
            </div>
          </div>

          <!-- 高危风险项 -->
          <div v-if="report.baselineRiskItems && report.baselineRiskItems.length > 0" class="risk-items-section" style="margin-top: 24px">
            <h4 style="margin-bottom: 12px; color: #1D2129; font-size: 15px">高风险基线违规项</h4>
            <div class="risk-item" v-for="(item, i) in report.baselineRiskItems" :key="i">
              <div class="risk-item-header">
                <span class="severity-tag" :class="item.severity">{{ item.severityLabel }}</span>
                <span class="risk-item-id">{{ item.checkId }}</span>
                <span class="risk-item-title">{{ item.description }}</span>
              </div>
              <div class="risk-item-meta">
                <span>分类：{{ getCategoryLabel(item.category) }}</span>
                <span v-if="item.clusterName">集群：{{ item.clusterName }}</span>
              </div>
              <div class="risk-item-remediation" v-if="item.remediation">
                <strong>修复建议：</strong>{{ item.remediation }}
              </div>
            </div>
          </div>

          <!-- 失败检查项明细表 -->
          <div v-if="report.failedCheckDetails && report.failedCheckDetails.length > 0" style="margin-top: 24px">
            <h4 style="margin-bottom: 12px; color: #1D2129; font-size: 15px">不合规检查项明细</h4>
            <table class="data-table">
              <thead>
                <tr>
                  <th style="width: 120px">检查ID</th>
                  <th>检查名称</th>
                  <th style="width: 100px">分类</th>
                  <th style="width: 70px">级别</th>
                  <th style="width: 120px">集群</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(item, i) in report.failedCheckDetails" :key="i">
                  <td>{{ item.checkId }}</td>
                  <td>{{ item.checkName }}</td>
                  <td>{{ getCategoryLabel(item.category) }}</td>
                  <td><span class="severity-tag" :class="item.severity">{{ item.severityLabel }}</span></td>
                  <td>{{ item.clusterName || '-' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- 6. 集群概览 -->
        <div class="report-page" v-if="report.clusterDetails.length > 0">
          <div class="section-header">
            <div class="section-number">{{ report.baselineStatistics.totalChecks > 0 ? '5' : '4' }}</div>
            <div class="section-title">集群概览</div>
            <div class="section-subtitle">Cluster Overview</div>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th>集群名称</th>
                <th>告警数</th>
                <th>基线通过率</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="cluster in report.clusterDetails" :key="cluster.clusterName">
                <td>{{ cluster.clusterName }}</td>
                <td><span style="color: #F53F3F">{{ cluster.alarmCount }}</span></td>
                <td><span :style="{ color: cluster.baselinePassRate >= 80 ? '#00B42A' : cluster.baselinePassRate >= 60 ? '#FF7D00' : '#F53F3F' }">{{ cluster.baselinePassRate.toFixed(1) }}%</span></td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 7. Top 告警 -->
        <div class="report-page" v-if="report.topAlarms.length > 0">
          <div class="section-header">
            <div class="section-number">{{ getTopAlarmSection() }}</div>
            <div class="section-title">Top 告警</div>
            <div class="section-subtitle">Top Alarms</div>
          </div>
          <table class="data-table">
            <thead>
              <tr>
                <th>Namespace</th>
                <th>目标</th>
                <th>类型</th>
                <th>数量</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(alarm, i) in report.topAlarms" :key="i">
                <td>{{ alarm.namespace || '-' }}</td>
                <td>{{ alarm.target || '-' }}</td>
                <td>{{ getAlarmTypeLabel(alarm.alarmType) }}</td>
                <td>{{ alarm.count }}</td>
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
import { reportsApi, type KubeExecutiveReport, type GeneratedReportItem } from '@/api/reports'
import html2pdf from 'html2pdf.js'

const loading = ref(false)
const exportingPDF = ref(false)
const loadingSaved = ref(false)
const dateRange = ref<[Dayjs, Dayjs]>([dayjs().subtract(7, 'day'), dayjs()])
const report = ref<KubeExecutiveReport | null>(null)
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
    const res = await reportsApi.listGeneratedReports('kube')
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
    report.value = await reportsApi.getKubeExecutiveReport({
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
    const filename = `容器安全报告-${period}_${dateStr}.pdf`
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

const getCategoryLabel = (category: string): string => {
  const labels: Record<string, string> = {
    'RBAC': 'RBAC 安全', 'Pod Security': 'Pod 安全', 'Network': '网络安全',
    'Secrets & Config': '密钥与配置', 'Workload': '工作负载', 'Node': '节点安全',
    'Cluster': '集群配置', 'Supply Chain': '供应链与运行时',
  }
  return labels[category] || category
}

const getAlarmTypeLabel = (type: string): string => {
  const labels: Record<string, string> = {
    container_escape: '容器逃逸', abnormal_process: '异常进程', abnormal_network: '异常网络',
    file_tamper: '文件篡改', privilege_escalation: '权限提升', reverse_shell: '反弹Shell', crypto_mining: '挖矿行为',
  }
  return labels[type] || type
}

const getTopAlarmSection = (): string => {
  if (!report.value) return '6'
  let n = 4
  if (report.value.baselineStatistics.totalChecks > 0) n++
  if (report.value.clusterDetails.length > 0) n++
  return String(n)
}

const getLastSection = (): string => {
  if (!report.value) return '7'
  let n = 4
  if (report.value.baselineStatistics.totalChecks > 0) n++
  if (report.value.clusterDetails.length > 0) n++
  if (report.value.topAlarms.length > 0) n++
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

.risk-item {
  padding: 14px 16px;
  margin-bottom: 10px;
  background: #FFF7F0;
  border-left: 3px solid #FF7D00;
  border-radius: 4px;

  .risk-item-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
  }
  .risk-item-id {
    font-size: 12px;
    color: #86909C;
    font-family: 'SF Mono', 'Consolas', monospace;
  }
  .risk-item-title {
    font-size: 14px;
    font-weight: 500;
    color: #1D2129;
  }
  .risk-item-meta {
    display: flex;
    gap: 16px;
    font-size: 12px;
    color: #86909C;
    margin-bottom: 6px;
  }
  .risk-item-remediation {
    font-size: 13px;
    color: #4E5969;
    line-height: 1.6;
    white-space: pre-line;
  }
}

.severity-tag {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
  &.critical { background: #FFECE8; color: #F53F3F; }
  &.high { background: #FFF3E8; color: #FF7D00; }
  &.medium { background: #FFF7E6; color: #F7BA1E; }
  &.low { background: #E8F3FF; color: #165DFF; }
}
</style>
