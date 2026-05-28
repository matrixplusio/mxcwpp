<template>
  <div class="task-report-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <h2>任务报告</h2>
      <div class="header-actions">
        <a-button v-if="activeTab === 'baseline'" @click="loadCompletedTasks" :loading="loadingTasks">
          <template #icon><ReloadOutlined /></template>
          刷新
        </a-button>
      </div>
    </div>

    <!-- Tab 切换 -->
    <a-tabs v-model:activeKey="activeTab" style="margin-bottom: 16px">
      <a-tab-pane key="baseline" tab="基线检查" />
      <a-tab-pane key="antivirus" tab="病毒查杀" />
      <a-tab-pane key="vulnerability" tab="漏洞管理" />
      <a-tab-pane key="remediation" tab="漏洞修复" />
      <a-tab-pane key="kube" tab="容器安全" />
    </a-tabs>

    <!-- 基线检查 Tab（现有全部内容） -->
    <template v-if="activeTab === 'baseline'">

    <!-- 任务列表 -->
    <div v-if="!report">
      <a-table
        :columns="taskColumns"
        :data-source="completedTasks"
        :loading="loadingTasks"
        row-key="task_id"
        :pagination="{ pageSize: 15, showSizeChanger: true, showTotal: (total: number) => `共 ${total} 条` }"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'name'">
            <span class="task-name">{{ record.name }}</span>
          </template>
          <template v-else-if="column.key === 'policy_name'">
            <a-tag color="blue">{{ getPolicyName(record) }}</a-tag>
          </template>
          <template v-else-if="column.key === 'host_count'">
            {{ record.matched_host_count || 0 }} 台
          </template>
          <template v-else-if="column.key === 'completed_at'">
            {{ formatDateTime(record.completed_at) }}
          </template>
          <template v-else-if="column.key === 'status'">
            <a-tag color="green">已完成</a-tag>
          </template>
          <template v-else-if="column.key === 'actions'">
            <a-space>
              <a-button type="primary" size="small" @click="handleViewReport(record)">
                <template #icon><FileTextOutlined /></template>
                查看报告
              </a-button>
            </a-space>
          </template>
        </template>
        <template #emptyText>
          <a-empty description="暂无已完成的任务" />
        </template>
      </a-table>
    </div>

    <!-- 报告详情 -->
    <div v-if="report" class="report-detail-wrapper">
      <!-- 返回按钮 -->
      <div class="report-header">
        <a-button @click="handleBackToList">
          <template #icon><ArrowLeftOutlined /></template>
          返回列表
        </a-button>
        <a-button
          type="primary"
          @click="exportPDF"
          :loading="exportingPDF"
          ghost
        >
          <template #icon><FilePdfOutlined /></template>
          导出 PDF
        </a-button>
      </div>

      <!-- 报告内容（用于 PDF 导出） -->
      <div ref="reportContent" class="report-container">
      <!-- 1. 封面页 -->
      <div class="report-page cover-page">
        <div class="cover-content">
          <div class="cover-logo">
            <img src="/logo.png" alt="Logo" style="width: 80px; height: 80px; object-fit: contain;" />
          </div>
          <h1 class="cover-title">{{ report.meta.report_title }}</h1>
          <div class="cover-subtitle">Security Baseline Assessment Report</div>
          <div class="cover-info">
            <div class="cover-info-item">
              <span class="label">检查对象：</span>
              <span class="value">{{ report.meta.check_target }}</span>
            </div>
            <div class="cover-info-item">
              <span class="label">基线类型：</span>
              <span class="value">{{ report.meta.baseline_type }}</span>
            </div>
            <div class="cover-info-item">
              <span class="label">报告编号：</span>
              <span class="value">{{ report.meta.report_id }}</span>
            </div>
            <div class="cover-info-item">
              <span class="label">生成时间：</span>
              <span class="value">{{ report.meta.generated_at }}</span>
            </div>
          </div>
          <div class="cover-company">{{ report.meta.company_name }}</div>
        </div>
      </div>

      <!-- 2. 报告摘要（Executive Summary） -->
      <div class="report-page">
        <div class="section-header">
          <div class="section-number">1</div>
          <div class="section-title">报告摘要</div>
          <div class="section-subtitle">Executive Summary</div>
        </div>

        <div class="executive-summary">
          <!-- 总体结论标签 -->
          <div class="conclusion-banner" :class="getConclusionClass(report.summary)">
            <div class="conclusion-icon">
              <CheckCircleOutlined v-if="!report.summary.has_critical_risk && !report.summary.has_high_risk && report.statistics.failed_checks === 0" />
              <ExclamationCircleOutlined v-else-if="report.summary.has_critical_risk || report.summary.has_high_risk" />
              <InfoCircleOutlined v-else />
            </div>
            <div class="conclusion-text">{{ report.summary.overall_conclusion }}</div>
          </div>

          <!-- 摘要内容 -->
          <div class="summary-content">
            <p class="summary-paragraph">{{ report.summary.check_scope }}</p>
            <p class="summary-paragraph">{{ report.summary.conclusion_statement }}</p>

            <div class="summary-stats">
              <div class="stat-item">
                <div class="stat-value">{{ report.task_info.host_count }}</div>
                <div class="stat-label">检查主机</div>
              </div>
              <div class="stat-item">
                <div class="stat-value">{{ report.task_info.rule_count }}</div>
                <div class="stat-label">检查规则</div>
              </div>
              <div class="stat-item">
                <div class="stat-value" :style="{ color: getComplianceColor(report.summary.compliance_rate) }">
                  {{ report.summary.compliance_rate.toFixed(1) }}%
                </div>
                <div class="stat-label">合规率</div>
              </div>
            </div>

            <!-- 策略领域覆盖统计 -->
            <div class="category-coverage" v-if="report.category_stats && report.category_stats.length > 0">
              <h4>策略领域检查概览</h4>
              <div class="category-stats-grid">
                <div class="category-stat-item" v-for="cat in report.category_stats" :key="cat.category">
                  <div class="category-name">{{ cat.category_name }}</div>
                  <div class="category-progress">
                    <div class="progress-bar" :style="{ width: cat.pass_rate + '%', backgroundColor: getComplianceColor(cat.pass_rate) }"></div>
                  </div>
                  <div class="category-detail">
                    <span class="pass-rate" :style="{ color: getComplianceColor(cat.pass_rate) }">{{ cat.pass_rate.toFixed(0) }}%</span>
                    <span class="check-count">{{ cat.passed_checks }}/{{ cat.total_checks }}</span>
                  </div>
                </div>
              </div>
            </div>

            <div class="coverage-note">
              <InfoCircleOutlined style="color: #3B82F6; margin-right: 8px" />
              {{ report.summary.coverage_note }}
            </div>
          </div>
        </div>
      </div>

      <!-- 3. 检查信息 -->
      <div class="report-page">
        <div class="section-header">
          <div class="section-number">2</div>
          <div class="section-title">检查信息</div>
          <div class="section-subtitle">Task Information</div>
        </div>

        <table class="info-table">
          <tbody>
            <tr>
              <td class="label-cell">任务名称</td>
              <td class="value-cell">{{ report.task_info.task_name }}</td>
              <td class="label-cell">检查策略</td>
              <td class="value-cell">
                <template v-if="report.task_info.policy_names && report.task_info.policy_names.length > 0">
                  {{ report.task_info.policy_names.join('、') }}
                </template>
                <template v-else>
                  {{ report.task_info.policy_name || '-' }}
                </template>
              </td>
            </tr>
            <tr>
              <td class="label-cell">执行时间</td>
              <td class="value-cell">{{ formatDateTimeValue(report.task_info.executed_at) }}</td>
              <td class="label-cell">完成时间</td>
              <td class="value-cell">{{ formatDateTimeValue(report.task_info.completed_at) }}</td>
            </tr>
            <tr>
              <td class="label-cell">检查主机数</td>
              <td class="value-cell">{{ report.task_info.host_count }} 台</td>
              <td class="label-cell">检查规则数</td>
              <td class="value-cell">{{ report.task_info.rule_count }} 条</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 4. 检查结果统计 -->
      <div class="report-page">
        <div class="section-header">
          <div class="section-number">3</div>
          <div class="section-title">检查结果统计</div>
          <div class="section-subtitle">Check Results Statistics</div>
        </div>

        <div class="stats-grid">
          <div class="stats-card passed">
            <div class="stats-icon"><CheckCircleOutlined /></div>
            <div class="stats-info">
              <div class="stats-value">{{ report.statistics.passed_checks }}</div>
              <div class="stats-label">合格</div>
            </div>
            <div class="stats-percent">{{ formatPercent(report.statistics.passed_checks, report.statistics.total_checks) }}</div>
          </div>
          <div class="stats-card failed">
            <div class="stats-icon"><CloseCircleOutlined /></div>
            <div class="stats-info">
              <div class="stats-value">{{ report.statistics.failed_checks }}</div>
              <div class="stats-label">不合格</div>
            </div>
            <div class="stats-percent">{{ formatPercent(report.statistics.failed_checks, report.statistics.total_checks) }}</div>
          </div>
          <div class="stats-card warning">
            <div class="stats-icon"><ExclamationCircleOutlined /></div>
            <div class="stats-info">
              <div class="stats-value">{{ report.statistics.warning_checks }}</div>
              <div class="stats-label">异常</div>
            </div>
            <div class="stats-percent">{{ formatPercent(report.statistics.warning_checks, report.statistics.total_checks) }}</div>
          </div>
          <div class="stats-card na">
            <div class="stats-icon"><MinusCircleOutlined /></div>
            <div class="stats-info">
              <div class="stats-value">{{ report.statistics.na_checks }}</div>
              <div class="stats-label">不适用</div>
            </div>
            <div class="stats-percent">{{ formatPercent(report.statistics.na_checks, report.statistics.total_checks) }}</div>
          </div>
        </div>

        <!-- 严重级别分布 -->
        <div class="severity-distribution" v-if="report.statistics.failed_checks > 0">
          <h4>按严重级别分布（不合格项）</h4>
          <div class="severity-bars">
            <div class="severity-bar-item" v-for="(count, severity) in report.statistics.by_severity" :key="severity">
              <div class="severity-label">
                <span class="severity-tag" :class="severity">{{ getSeverityLabel(severity) }}</span>
              </div>
              <div class="severity-bar-container">
                <div
                  class="severity-bar"
                  :class="severity"
                  :style="{ width: `${(count / report.statistics.failed_checks) * 100}%` }"
                ></div>
              </div>
              <div class="severity-count">{{ count }}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- 5. 安全评分 -->
      <div class="report-page">
        <div class="section-header">
          <div class="section-number">4</div>
          <div class="section-title">安全评分与风险态势</div>
          <div class="section-subtitle">Security Score & Risk Assessment</div>
        </div>

        <div class="score-section">
          <div class="score-display">
            <div class="score-circle" :style="{ borderColor: report.security_score.grade_color }">
              <div class="score-value" :style="{ color: report.security_score.grade_color }">
                {{ Math.round(report.security_score.score) }}
              </div>
              <div class="score-unit">分</div>
            </div>
            <div class="score-grade" :style="{ color: report.security_score.grade_color }">
              {{ report.security_score.grade }}
            </div>
          </div>
          <div class="score-explanation">
            <p>{{ report.security_score.score_explanation }}</p>
            <p class="security-note">
              <InfoCircleOutlined style="color: #F59E0B; margin-right: 8px" />
              {{ report.security_score.security_note }}
            </p>
          </div>
        </div>
      </div>

      <!-- 6. 风险项说明（如有） -->
      <div class="report-page" v-if="report.risk_items && report.risk_items.length > 0">
        <div class="section-header">
          <div class="section-number">5</div>
          <div class="section-title">风险项说明</div>
          <div class="section-subtitle">Risk Items</div>
        </div>

        <div class="risk-items-list">
          <div class="risk-item" v-for="(item, index) in report.risk_items" :key="index">
            <div class="risk-header">
              <span class="risk-severity" :class="item.severity">{{ item.severity_label }}</span>
              <span class="risk-category">{{ item.category }}</span>
              <span class="risk-affected">影响 {{ item.affected_count }} 台主机</span>
            </div>
            <div class="risk-body">
              <div class="risk-description">{{ item.description }}</div>
              <div class="risk-detail">
                <div class="risk-detail-item">
                  <span class="detail-label">可能影响：</span>
                  <span class="detail-value">{{ item.impact }}</span>
                </div>
                <div class="risk-detail-item">
                  <span class="detail-label">整改建议：</span>
                  <span class="detail-value">{{ item.recommendation }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 7. 主机检查明细 -->
      <div class="report-page">
        <div class="section-header">
          <div class="section-number">{{ report.risk_items && report.risk_items.length > 0 ? '6' : '5' }}</div>
          <div class="section-title">主机检查明细</div>
          <div class="section-subtitle">Host Check Details</div>
        </div>

        <table class="data-table">
          <thead>
            <tr>
              <th>主机名</th>
              <th>IP</th>
              <th>操作系统</th>
              <th>得分</th>
              <th>合格</th>
              <th>不合格</th>
              <th>状态</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="host in report.host_details" :key="host.host_id">
              <td>{{ host.hostname || host.host_id }}</td>
              <td>{{ host.ip || '-' }}</td>
              <td>{{ host.os_family || '-' }}</td>
              <td>
                <span :style="{ color: getScoreColor(host.score) }">{{ Math.round(host.score) }}%</span>
              </td>
              <td style="color: #22C55E">{{ host.passed_count }}</td>
              <td style="color: #EF4444">{{ host.failed_count }}</td>
              <td>
                <span class="status-tag" :class="host.status">{{ getHostStatusLabel(host.status) }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 8. 合规与基线覆盖说明 -->
      <div class="report-page">
        <div class="section-header">
          <div class="section-number">{{ report.risk_items && report.risk_items.length > 0 ? '7' : '6' }}</div>
          <div class="section-title">合规与基线覆盖说明</div>
          <div class="section-subtitle">Compliance & Baseline Coverage</div>
        </div>

        <div class="coverage-section">
          <div class="coverage-item">
            <div class="coverage-label">基线来源</div>
            <div class="coverage-value">{{ report.coverage.baseline_source }}</div>
          </div>
          <div class="coverage-item">
            <div class="coverage-label">已覆盖检查领域</div>
            <div class="coverage-tags">
              <span class="coverage-tag covered" v-for="area in report.coverage.covered_areas" :key="area">
                {{ area }}
              </span>
            </div>
          </div>
          <div class="coverage-item" v-if="report.coverage.uncovered_areas.length > 0">
            <div class="coverage-label">尚未覆盖领域</div>
            <div class="coverage-tags">
              <span class="coverage-tag uncovered" v-for="area in report.coverage.uncovered_areas" :key="area">
                {{ area }}
              </span>
            </div>
          </div>
          <div class="coverage-note-box">
            <InfoCircleOutlined style="color: #3B82F6; margin-right: 8px" />
            {{ report.coverage.improvement_note }}
          </div>
        </div>
      </div>

      <!-- 9. 结论与管理建议 -->
      <div class="report-page">
        <div class="section-header">
          <div class="section-number">{{ report.risk_items && report.risk_items.length > 0 ? '8' : '7' }}</div>
          <div class="section-title">结论与管理建议</div>
          <div class="section-subtitle">Conclusion & Recommendations</div>
        </div>

        <div class="recommendation-section">
          <div class="overall-assessment">
            <h4>总体评估</h4>
            <p>{{ report.recommendation.overall_assessment }}</p>
          </div>

          <div class="action-suggestions">
            <h4>行动建议</h4>
            <ul>
              <li v-for="(suggestion, index) in report.recommendation.action_suggestions" :key="index">
                {{ suggestion }}
              </li>
            </ul>
          </div>
        </div>
      </div>

      <!-- 10. 附录 -->
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
            <p><strong>报告生成时间：</strong>{{ report.meta.generated_at }}</p>
            <p><strong>报告编号：</strong>{{ report.meta.report_id }}</p>
          </div>
        </div>
      </div>
      </div><!-- report-container -->
    </div><!-- report-detail-wrapper -->

    </template><!-- baseline tab end -->

    <!-- 其他 Tab -->
    <AntivirusTaskReport v-if="activeTab === 'antivirus'" />
    <VulnTaskReport v-if="activeTab === 'vulnerability'" />
    <RemediationTaskReport v-if="activeTab === 'remediation'" />
    <KubeTaskReport v-if="activeTab === 'kube'" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import {
  FileTextOutlined,
  FilePdfOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  InfoCircleOutlined,
  MinusCircleOutlined,
  ReloadOutlined,
  ArrowLeftOutlined,
} from '@ant-design/icons-vue'
import {
  reportsApi,
  type ExecutiveTaskReport,
} from '@/api/reports'
import { tasksApi } from '@/api/tasks'
import { policiesApi } from '@/api/policies'
import html2pdf from 'html2pdf.js'
import AntivirusTaskReport from './task-reports/AntivirusTaskReport.vue'
import VulnTaskReport from './task-reports/VulnTaskReport.vue'
import RemediationTaskReport from './task-reports/RemediationTaskReport.vue'
import KubeTaskReport from './task-reports/KubeTaskReport.vue'

// Tab 切换 — 从 URL query 持久化
const route = useRoute()
const router = useRouter()
const validTabs = ['baseline', 'antivirus', 'vulnerability', 'kube']
const initialTab = validTabs.includes(route.query.tab as string) ? (route.query.tab as string) : 'baseline'
const activeTab = ref(initialTab)

watch(activeTab, (val) => {
  router.replace({ query: { ...route.query, tab: val } })
})

// 数据
const loading = ref(false)
const loadingTasks = ref(false)
const exportingPDF = ref(false)
const completedTasks = ref<any[]>([])
const policies = ref<any[]>([])
const selectedTaskId = ref<string>('')
const report = ref<ExecutiveTaskReport | null>(null)
const reportContent = ref<HTMLElement | null>(null)

// 任务列表列定义
const taskColumns = [
  { title: '任务名称', key: 'name', dataIndex: 'name', ellipsis: true },
  { title: '检查策略', key: 'policy_name', width: 200 },
  { title: '检查主机', key: 'host_count', width: 100 },
  { title: '完成时间', key: 'completed_at', width: 180 },
  { title: '状态', key: 'status', width: 100 },
  { title: '操作', key: 'actions', width: 120, fixed: 'right' as const },
]

// 加载已完成的任务
const loadCompletedTasks = async () => {
  loadingTasks.value = true
  try {
    const res = await tasksApi.list({ status: 'completed', page_size: 100 }) as any
    completedTasks.value = res.items || res.data?.items || []
  } catch (error: any) {
    message.error(error.message || '加载任务列表失败')
  } finally {
    loadingTasks.value = false
  }
}

// 加载策略列表
const loadPolicies = async () => {
  try {
    const res = await policiesApi.list() as any
    policies.value = res.items || []
  } catch (error) {
    console.error('加载策略列表失败:', error)
  }
}

// 获取策略名称
const getPolicyName = (task: any): string => {
  const policy = policies.value.find(p => p.id === task.policy_id)
  return policy?.name || task.policy_id || '-'
}

// 查看报告
const handleViewReport = async (task: any) => {
  selectedTaskId.value = task.task_id
  await generateReport()
}

// 返回列表
const handleBackToList = () => {
  report.value = null
  selectedTaskId.value = ''
}

// 生成报告
const generateReport = async () => {
  if (!selectedTaskId.value) return
  loading.value = true
  try {
    report.value = await reportsApi.getExecutiveTaskReport(selectedTaskId.value)
  } catch (error: any) {
    message.error(error.message || '生成报告失败')
  } finally {
    loading.value = false
  }
}

// 导出 PDF
const exportPDF = async () => {
  if (!report.value || !reportContent.value) return

  exportingPDF.value = true
  try {
    const taskName = report.value.task_info.task_name.replace(/[\/\\:*?"<>|]/g, '_')
    const dateStr = new Date().toISOString().split('T')[0]
    const filename = `安全基线检查报告-${taskName}_${dateStr}.pdf`

    // 添加 PDF 导出专用 class
    reportContent.value.classList.add('pdf-exporting')

    const options = {
      margin: [10, 10, 10, 10] as [number, number, number, number],
      filename: filename,
      image: { type: 'jpeg' as const, quality: 0.98 },
      html2canvas: {
        scale: 2,
        useCORS: true,
        logging: false,
        letterRendering: true,
        width: 820,
        windowWidth: 820,
        scrollX: 0,
        scrollY: 0,
      },
      jsPDF: {
        unit: 'mm' as const,
        format: 'a4' as const,
        orientation: 'portrait' as const
      },
      pagebreak: {
        mode: ['css', 'legacy'],
        before: [],
        after: [],
        avoid: [
          // 文本元素 - 保持文字完整性
          'tr',
          'p',
          'li',
          'h3',
          'h4',
          'strong',
          'span',
          // 小型内容块
          '.stats-card',
          '.severity-bar-item',
          '.conclusion-banner',
          '.summary-stats',
          '.coverage-note',
          '.coverage-note-box',
          '.security-note',
          '.disclaimer',
          '.coverage-item',
          '.cover-info-item',
          '.risk-header',
          '.risk-body',
          '.risk-detail-item',
          '.category-stat-item',
          '.category-coverage',
          '.info-table',
          // 中型内容块
          '.risk-item',
          '.score-section',
          '.severity-distribution',
          '.overall-assessment',
          '.action-suggestions',
          '.appendix-content',
          '.report-info',
          '.coverage-section',
          '.recommendation-section',
          // 整个附录页面
          '.appendix'
        ]
      }
    }

    await html2pdf().set(options).from(reportContent.value).save()
    message.success('PDF 导出成功')
  } catch (error: any) {
    console.error('PDF export error:', error)
    message.error('PDF 导出失败: ' + (error.message || '未知错误'))
  } finally {
    // 移除 PDF 导出专用 class
    reportContent.value?.classList.remove('pdf-exporting')
    exportingPDF.value = false
  }
}

// 格式化函数
const formatDateTime = (dateStr: string | null): string => {
  if (!dateStr) return '-'
  return dateStr.replace('T', ' ').substring(0, 19)
}

const formatPercent = (value: number, total: number): string => {
  if (total === 0) return '0%'
  return ((value / total) * 100).toFixed(1) + '%'
}

// 状态相关函数
const getConclusionClass = (summary: any): string => {
  if (summary.has_critical_risk) return 'critical'
  if (summary.has_high_risk) return 'high'
  if (summary.compliance_rate < 100) return 'warning'
  return 'success'
}

const getComplianceColor = (rate: number): string => {
  if (rate >= 90) return '#22C55E'
  if (rate >= 70) return '#F59E0B'
  return '#EF4444'
}

const getScoreColor = (score: number): string => {
  if (score >= 80) return '#22C55E'
  if (score >= 60) return '#F59E0B'
  return '#EF4444'
}

const getSeverityLabel = (severity: string): string => {
  const labels: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  }
  return labels[severity] || severity
}

const getHostStatusLabel = (status: string): string => {
  const labels: Record<string, string> = {
    pass: '合格',
    warning: '待整改',
    fail: '不合格',
  }
  return labels[status] || status
}

// 格式化时间值（处理各种时间格式）
const formatDateTimeValue = (dateValue: string | null | undefined): string => {
  if (!dateValue) return '-'
  
  // 如果已经是格式化的字符串，直接处理
  if (typeof dateValue === 'string') {
    // 处理 ISO 格式
    if (dateValue.includes('T')) {
      return dateValue.replace('T', ' ').substring(0, 19)
    }
    // 处理其他格式
    if (dateValue.length >= 19) {
      return dateValue.substring(0, 19)
    }
    return dateValue || '-'
  }
  
  return '-'
}

onMounted(() => {
  loadCompletedTasks()
  loadPolicies()
})
</script>

<style lang="less">
/* 任务报告页面样式 - 非 scoped 以确保 PDF 导出正确 */
.task-report-page {
  width: 100%;
  padding: 16px;

  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;

    h2 {
      margin: 0;
      font-size: 20px;
      font-weight: 600;
    }
  }

  .header-actions {
    display: flex;
    gap: 12px;
    align-items: center;
  }

  /* 任务列表卡片 */
  .task-list-card {
    margin-bottom: 24px;
    border-radius: 8px;
  }

  .task-name {
    font-weight: 500;
    color: var(--mxsec-text-1);
  }

  /* 报告详情区域 */
  .report-detail-wrapper {
    width: 100%;
  }

  .report-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
    padding: 14px 20px;
    background: var(--mxsec-card-bg);
    border-radius: 8px;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
      0 2px 4px rgba(0, 0, 0, 0.04),
      0 4px 8px rgba(0, 0, 0, 0.04);
  }
}

/* 报告容器 - PDF导出核心样式 */
.report-container {
  background: var(--mxsec-card-bg);
  max-width: 820px;
  margin: 0 auto;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;

  /* PDF导出专用样式 */
  &.pdf-exporting {
    box-shadow: none;
    max-width: 820px;
    width: 820px;

    * {
      -webkit-print-color-adjust: exact !important;
      print-color-adjust: exact !important;
    }

    /* PDF导出时让内容自然流动 */
    .report-page {
      page-break-inside: auto !important;
      page-break-after: auto !important;
      page-break-before: auto !important;
      padding: 20px 28px !important;
    }

    .cover-page {
      page-break-after: auto !important;
      min-height: auto !important;
      display: block !important;

      .cover-content {
        padding: 40px 32px !important;
      }
    }

    /* 章节标题后不分页，确保和内容在一起 */
    .section-header {
      page-break-after: avoid !important;
      break-after: avoid !important;
    }

    /* 文字内容避免分割 - 使用双重属性确保兼容性 */
    p, li, h4, h3 {
      page-break-inside: avoid !important;
      break-inside: avoid !important;
      orphans: 3 !important;  /* 页面底部至少保留3行 */
      widows: 3 !important;   /* 页面顶部至少保留3行 */
    }

    /* 表格行避免分割 */
    tr {
      page-break-inside: avoid !important;
      break-inside: avoid !important;
    }

    /* 关键内容块避免分割 */
    .conclusion-banner,
    .summary-stats,
    .stats-card,
    .severity-bar-item,
    .coverage-note,
    .coverage-note-box,
    .security-note,
    .disclaimer,
    .report-info,
    .report-info p,
    .coverage-item,
    .risk-header,
    .risk-body,
    .risk-detail-item,
    .cover-info-item,
    .category-coverage,
    .category-stat-item,
    .info-table,
    .info-table tr {
      page-break-inside: avoid !important;
      break-inside: avoid !important;
    }

    /* 中等大小内容块 - 尽量避免分割 */
    .score-section,
    .severity-distribution,
    .overall-assessment,
    .action-suggestions,
    .risk-item,
    .coverage-section,
    .recommendation-section {
      page-break-inside: avoid !important;
      break-inside: avoid !important;
    }

    /* 附录内容保持完整 - 强制不分割 */
    .appendix-content,
    .appendix-content .disclaimer,
    .appendix-content .report-info {
      page-break-inside: avoid !important;
      break-inside: avoid !important;
    }

    /* 整个附录页面尽量保持完整 */
    .appendix {
      page-break-inside: avoid !important;
      break-inside: avoid !important;
    }

    /* 行内文字元素强制不分割 */
    strong, span, .label, .value {
      page-break-inside: avoid !important;
      break-inside: avoid !important;
      display: inline-block;
    }
  }

  /* 报告页面 - 网页预览 */
  .report-page {
    padding: 24px 32px;
    min-height: auto;

    &:not(.cover-page) {
      border-top: 1px solid var(--mxsec-border);
    }
  }

  /* 封面页 - 网页预览 */
  .cover-page {
    background: linear-gradient(135deg, #3B82F6 0%, #2563EB 100%);
    color: var(--mxsec-card-bg);
    display: block;
    text-align: center;

    .cover-content {
      text-align: center;
      width: 100%;
      padding: 50px 40px;
    }

    .cover-logo {
      margin-bottom: 32px;
    }

    .cover-title {
      font-size: 32px;
      font-weight: 700;
      margin-bottom: 8px;
      letter-spacing: 4px;
      color: var(--mxsec-card-bg);
    }

    .cover-subtitle {
      font-size: 14px;
      opacity: 0.8;
      margin-bottom: 48px;
    }

    .cover-info {
      text-align: left;
      max-width: 360px;
      margin: 0 auto 48px;

      .cover-info-item {
        display: flex;
        padding: 10px 0;
        border-bottom: 1px solid rgba(255, 255, 255, 0.2);

        .label {
          width: 90px;
          opacity: 0.8;
        }

        .value {
          flex: 1;
          font-weight: 500;
        }
      }
    }

    .cover-company {
      font-size: 16px;
      font-weight: 500;
      opacity: 0.9;
    }
  }

  /* 章节标题 */
  .section-header {
    display: flex;
    align-items: baseline;
    margin-bottom: 20px;
    padding-bottom: 10px;
    border-bottom: 2px solid #3B82F6;

    .section-number {
      font-size: 24px;
      font-weight: 700;
      color: var(--mxsec-primary);
      margin-right: 12px;
    }

    .section-title {
      font-size: 18px;
      font-weight: 600;
      color: var(--mxsec-text-1);
      margin-right: 10px;
    }

    .section-subtitle {
      font-size: 12px;
      color: var(--mxsec-text-3);
    }
  }

  /* 执行摘要 */
  .executive-summary {
    .conclusion-banner {
      display: flex;
      align-items: center;
      padding: 14px 20px;
      border-radius: 6px;
      margin-bottom: 20px;

      &.success {
        background-color: var(--mxsec-success-bg);
        border: 1px solid #b7eb8f;
      }

      &.warning {
        background-color: #fffbe6;
        border: 1px solid #ffe58f;
      }

      &.high,
      &.critical {
        background-color: #fff2f0;
        border: 1px solid #ffccc7;
      }

      .conclusion-icon {
        font-size: 22px;
        margin-right: 14px;
      }

      &.success .conclusion-icon {
        color: #22C55E;
      }

      &.warning .conclusion-icon {
        color: #F59E0B;
      }

      &.high .conclusion-icon,
      &.critical .conclusion-icon {
        color: #EF4444;
      }

      .conclusion-text {
        font-size: 16px;
        font-weight: 600;
        color: var(--mxsec-text-1);
      }
    }

    .summary-content {
      color: #595959;
      line-height: 1.7;

      .summary-paragraph {
        margin-bottom: 14px;
      }

      .summary-stats {
        display: flex;
        gap: 32px;
        margin: 24px 0;
        padding: 20px;
        background-color: var(--mxsec-fill-1);
        border-radius: 6px;

        .stat-item {
          text-align: center;
          min-width: 80px;

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
        }
      }

      .coverage-note {
        padding: 10px 14px;
        background-color: var(--mxsec-primary-bg);
        border-radius: 4px;
        color: #2563EB;
        font-size: 13px;
      }

      /* 策略领域覆盖统计 */
      .category-coverage {
        margin: 24px 0;
        padding: 16px;
        background-color: var(--mxsec-fill-1);
        border-radius: 6px;

        h4 {
          font-size: 14px;
          color: var(--mxsec-text-1);
          margin: 0 0 16px 0;
          font-weight: 600;
        }

        .category-stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
          gap: 12px;
        }

        .category-stat-item {
          background: var(--mxsec-card-bg);
          padding: 12px;
          border-radius: 4px;
          border: 1px solid var(--mxsec-border);

          .category-name {
            font-size: 13px;
            color: #595959;
            margin-bottom: 8px;
            font-weight: 500;
          }

          .category-progress {
            height: 6px;
            background-color: var(--mxsec-fill-3);
            border-radius: 3px;
            overflow: hidden;
            margin-bottom: 6px;

            .progress-bar {
              height: 100%;
              border-radius: 3px;
              transition: width 0.3s ease;
            }
          }

          .category-detail {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 12px;

            .pass-rate {
              font-weight: 600;
            }

            .check-count {
              color: var(--mxsec-text-3);
            }
          }
        }
      }
    }
  }

  /* 信息表格 */
  .info-table {
    width: 100%;
    border-collapse: collapse;

    td {
      padding: 10px 14px;
      border: 1px solid var(--mxsec-border);
    }

    .label-cell {
      background-color: var(--mxsec-fill-1);
      font-weight: 500;
      width: 100px;
      color: #595959;
    }

    .value-cell {
      color: var(--mxsec-text-1);
    }
  }

  /* 统计卡片 */
  .stats-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 24px;

    .stats-card {
      display: flex;
      align-items: center;
      padding: 16px;
      border-radius: 6px;
      flex: 1;
      min-width: 160px;
      max-width: 190px;

      &.passed {
        background-color: var(--mxsec-success-bg);
        border: 1px solid #b7eb8f;

        .stats-icon {
          color: #22C55E;
        }
      }

      &.failed {
        background-color: #fff2f0;
        border: 1px solid #ffccc7;

        .stats-icon {
          color: #EF4444;
        }
      }

      &.warning {
        background-color: #fffbe6;
        border: 1px solid #ffe58f;

        .stats-icon {
          color: #F59E0B;
        }
      }

      &.na {
        background-color: var(--mxsec-fill-1);
        border: 1px solid #d9d9d9;

        .stats-icon {
          color: var(--mxsec-text-3);
        }
      }

      .stats-icon {
        font-size: 20px;
        margin-right: 10px;
      }

      .stats-info {
        flex: 1;

        .stats-value {
          font-size: 20px;
          font-weight: 700;
          color: var(--mxsec-text-1);
        }

        .stats-label {
          font-size: 11px;
          color: var(--mxsec-text-3);
        }
      }

      .stats-percent {
        font-size: 12px;
        color: var(--mxsec-text-3);
      }
    }
  }

  /* 严重级别分布 */
  .severity-distribution {
    h4 {
      font-size: 13px;
      color: #595959;
      margin-bottom: 14px;
    }

    .severity-bars {
      .severity-bar-item {
        display: flex;
        align-items: center;
        margin-bottom: 10px;

        .severity-label {
          width: 55px;

          .severity-tag {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            color: var(--mxsec-card-bg);

            &.critical {
              background-color: #EF4444;
            }

            &.high {
              background-color: #ff7875;
            }

            &.medium {
              background-color: #ffa940;
            }

            &.low {
              background-color: #ffc53d;
            }
          }
        }

        .severity-bar-container {
          flex: 1;
          height: 16px;
          background-color: var(--mxsec-fill-3);
          border-radius: 3px;
          margin: 0 10px;
          overflow: hidden;

          .severity-bar {
            height: 100%;
            border-radius: 3px;

            &.critical {
              background-color: #EF4444;
            }

            &.high {
              background-color: #ff7875;
            }

            &.medium {
              background-color: #ffa940;
            }

            &.low {
              background-color: #ffc53d;
            }
          }
        }

        .severity-count {
          width: 35px;
          text-align: right;
          font-weight: 600;
          color: var(--mxsec-text-1);
          font-size: 13px;
        }
      }
    }
  }

  /* 安全评分 */
  .score-section {
    display: flex;
    gap: 32px;
    align-items: flex-start;

    .score-display {
      text-align: center;

      .score-circle {
        width: 120px;
        height: 120px;
        border-radius: 50%;
        border-width: 6px;
        border-style: solid;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        margin-bottom: 10px;

        .score-value {
          font-size: 40px;
          font-weight: 700;
          line-height: 1;
        }

        .score-unit {
          font-size: 12px;
          color: var(--mxsec-text-3);
        }
      }

      .score-grade {
        font-size: 18px;
        font-weight: 600;
      }
    }

    .score-explanation {
      flex: 1;
      color: #595959;
      line-height: 1.7;
      font-size: 14px;

      .security-note {
        margin-top: 14px;
        padding: 10px 14px;
        background-color: #fffbe6;
        border-radius: 4px;
        color: #ad8b00;
        font-size: 13px;
      }
    }
  }

  /* 风险项 */
  .risk-items-list {
    .risk-item {
      border: 1px solid var(--mxsec-border);
      border-radius: 6px;
      margin-bottom: 14px;
      overflow: hidden;

      .risk-header {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 14px;
        background-color: var(--mxsec-fill-1);

        .risk-severity {
          padding: 2px 6px;
          border-radius: 3px;
          font-size: 11px;
          color: var(--mxsec-card-bg);

          &.critical {
            background-color: #EF4444;
          }

          &.high {
            background-color: #ff7875;
          }
        }

        .risk-category {
          color: #595959;
          font-weight: 500;
          font-size: 13px;
        }

        .risk-affected {
          color: var(--mxsec-text-3);
          font-size: 11px;
          margin-left: auto;
        }
      }

      .risk-body {
        padding: 14px;

        .risk-description {
          font-weight: 500;
          color: var(--mxsec-text-1);
          margin-bottom: 10px;
          font-size: 14px;
        }

        .risk-detail {
          .risk-detail-item {
            margin-bottom: 6px;
            color: #595959;
            font-size: 13px;

            .detail-label {
              font-weight: 500;
            }
          }
        }
      }
    }
  }

  /* 数据表格 */
  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;

    th,
    td {
      padding: 8px 10px;
      border: 1px solid var(--mxsec-border);
      text-align: left;
    }

    th {
      background-color: var(--mxsec-fill-1);
      font-weight: 600;
      color: #595959;
    }

    td {
      color: var(--mxsec-text-1);
    }

    .status-tag {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 3px;
      font-size: 11px;

      &.pass {
        background-color: var(--mxsec-success-bg);
        color: #22C55E;
      }

      &.warning {
        background-color: #fffbe6;
        color: #F59E0B;
      }

      &.fail {
        background-color: #fff2f0;
        color: #EF4444;
      }
    }
  }

  /* 覆盖说明 */
  .coverage-section {
    color: #595959;

    .coverage-item {
      margin-bottom: 16px;

      .coverage-label {
        font-weight: 500;
        color: var(--mxsec-text-1);
        margin-bottom: 6px;
        font-size: 14px;
      }

      .coverage-value {
        color: #595959;
        font-size: 13px;
      }

      .coverage-tags {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;

        .coverage-tag {
          display: inline-block;
          padding: 3px 10px;
          border-radius: 3px;
          font-size: 12px;

          &.covered {
            background-color: var(--mxsec-primary-bg);
            color: var(--mxsec-primary);
          }

          &.uncovered {
            background-color: var(--mxsec-fill-2);
            color: var(--mxsec-text-3);
          }
        }
      }
    }

    .coverage-note-box {
      padding: 10px 14px;
      background-color: var(--mxsec-primary-bg);
      border-radius: 4px;
      color: #2563EB;
      margin-top: 14px;
      font-size: 13px;
    }
  }

  /* 管理建议 */
  .recommendation-section {
    color: #595959;
    line-height: 1.7;

    .overall-assessment {
      margin-bottom: 20px;

      h4 {
        font-size: 15px;
        color: var(--mxsec-text-1);
        margin-bottom: 10px;
      }

      p {
        font-size: 14px;
      }
    }

    .action-suggestions {
      h4 {
        font-size: 15px;
        color: var(--mxsec-text-1);
        margin-bottom: 10px;
      }

      ul {
        padding-left: 18px;
        margin: 0;

        li {
          margin-bottom: 6px;
          font-size: 14px;
        }
      }
    }
  }

  /* 附录 */
  .appendix {
    .appendix-content {
      color: #595959;
      line-height: 1.7;

      .disclaimer {
        padding: 16px;
        background-color: var(--mxsec-fill-1);
        border-radius: 6px;
        margin-bottom: 20px;

        h4 {
          font-size: 13px;
          color: var(--mxsec-text-1);
          margin-bottom: 6px;
        }

        p {
          font-size: 13px;
          margin: 0;
        }
      }

      .report-info {
        padding: 12px;
        background-color: var(--mxsec-card-bg);
        border: 1px solid var(--mxsec-border);
        border-radius: 6px;

        p {
          margin-bottom: 6px;
          font-size: 13px;
          line-height: 1.8;

          &:last-child {
            margin-bottom: 0;
          }

          strong {
            color: var(--mxsec-text-1);
            display: inline;
          }
        }
      }
    }
  }
}

/* PDF 导出时附录特殊处理 */
.pdf-exporting .appendix {
  page-break-inside: avoid !important;
  break-inside: avoid !important;

  .appendix-content {
    page-break-inside: avoid !important;
    break-inside: avoid !important;
  }

  .disclaimer {
    page-break-inside: avoid !important;
    break-inside: avoid !important;
  }

  .report-info {
    page-break-inside: avoid !important;
    break-inside: avoid !important;

    p {
      page-break-inside: avoid !important;
      break-inside: avoid !important;
      white-space: nowrap;
    }
  }
}

/* 响应式 */
@media (max-width: 768px) {
  .task-report-page {
    .page-header {
      flex-direction: column;
      align-items: flex-start;
      gap: 12px;
    }

    .header-actions {
      width: 100%;
      flex-direction: column;
    }

    .header-actions .ant-select {
      width: 100% !important;
    }
  }

  .report-container {
    .stats-grid {
      .stats-card {
        min-width: 140px;
      }
    }

    .score-section {
      flex-direction: column;
    }

    .summary-stats {
      flex-direction: column;
      gap: 16px;
    }
  }
}

/* 打印样式 */
@media print {
  .task-report-page .page-header,
  .task-report-page .report-header {
    display: none !important;
  }

  .report-container {
    box-shadow: none;
    max-width: none;

    .report-page {
      page-break-inside: auto;
    }

    .cover-page {
      min-height: auto;
    }

    /* 打印时避免分割的元素 */
    p, li, tr, h3, h4 {
      page-break-inside: avoid;
      break-inside: avoid;
      orphans: 3;
      widows: 3;
    }

    .appendix,
    .appendix-content,
    .disclaimer,
    .report-info {
      page-break-inside: avoid;
      break-inside: avoid;
    }
  }
}
</style>