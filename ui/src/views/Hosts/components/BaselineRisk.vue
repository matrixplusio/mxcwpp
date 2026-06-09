<template>
  <div class="baseline-risk">
    <!-- 统计概览 -->
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-icon-bg total-bg">
          <UnorderedListOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value">{{ totalCount }}</div>
          <div class="stat-label">总计</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-bg pass-bg">
          <CheckCircleOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value pass">{{ passCount }}</div>
          <div class="stat-label">通过</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-bg fail-bg">
          <CloseCircleOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value fail">{{ failCount }}</div>
          <div class="stat-label">失败</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-bg error-bg">
          <ExclamationCircleOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value error">{{ errorCount }}</div>
          <div class="stat-label">错误</div>
        </div>
      </div>
      <div class="stat-divider"></div>
      <div class="stat-card severity-card" :class="{ clickable: criticalCount > 0 }" @click="setSeverityFilter('critical')">
        <div class="stat-icon-bg critical-bg">
          <BugOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value critical">{{ criticalCount }}</div>
          <div class="stat-label">严重</div>
        </div>
      </div>
      <div class="stat-card severity-card" :class="{ clickable: highCount > 0 }" @click="setSeverityFilter('high')">
        <div class="stat-icon-bg high-bg">
          <WarningOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value high">{{ highCount }}</div>
          <div class="stat-label">高危</div>
        </div>
      </div>
      <div class="stat-card severity-card" :class="{ clickable: mediumCount > 0 }" @click="setSeverityFilter('medium')">
        <div class="stat-icon-bg medium-bg">
          <InfoCircleOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value medium">{{ mediumCount }}</div>
          <div class="stat-label">中危</div>
        </div>
      </div>
      <div class="stat-card severity-card" :class="{ clickable: lowCount > 0 }" @click="setSeverityFilter('low')">
        <div class="stat-icon-bg low-bg">
          <SafetyCertificateOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value low">{{ lowCount }}</div>
          <div class="stat-label">低危</div>
        </div>
      </div>
    </div>

    <!-- 筛选器 -->
    <div class="filter-bar">
      <div class="filter-left">
        <a-radio-group v-model:value="statusFilter" button-style="solid" size="small">
          <a-radio-button value="all">全部 ({{ totalCount }})</a-radio-button>
          <a-radio-button value="fail">失败 ({{ failCount + errorCount }})</a-radio-button>
          <a-radio-button value="pass">通过 ({{ passCount }})</a-radio-button>
        </a-radio-group>
        <a-select
          v-model:value="severityFilter"
          placeholder="严重级别"
          style="width: 120px"
          size="small"
          allow-clear
        >
          <a-select-option value="critical">严重</a-select-option>
          <a-select-option value="high">高危</a-select-option>
          <a-select-option value="medium">中危</a-select-option>
          <a-select-option value="low">低危</a-select-option>
        </a-select>
      </div>
      <div class="filter-right">
        <a-input-search
          v-model:value="searchKeyword"
          placeholder="搜索规则ID或标题"
          style="width: 250px"
          allow-clear
        />
        <a-dropdown>
          <template #overlay>
            <a-menu @click="handleExport">
              <a-menu-item key="markdown">
                <FileMarkdownOutlined />
                导出为 Markdown
              </a-menu-item>
              <a-menu-item key="excel">
                <FileExcelOutlined />
                导出为 Excel
              </a-menu-item>
            </a-menu>
          </template>
          <a-button type="primary" :loading="exporting">
            <DownloadOutlined />
            导出
          </a-button>
        </a-dropdown>
      </div>
    </div>

    <a-table
      :columns="columns"
      :data-source="filteredResults"
      :loading="loading"
      :pagination="pagination"
      @change="handleTableChange"
      :row-key="(record: any) => record.task_id + '_' + record.host_id + '_' + record.rule_id"
      size="small"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'status'">
          <a-tag :color="getStatusColor(record.status)">
            {{ getStatusText(record.status) }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'severity'">
          <a-tag :color="getSeverityColor(record.severity)">
            {{ getSeverityText(record.severity) }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'failure_reason'">
          <template v-if="record.status === 'fail' || record.status === 'error'">
            <a-tooltip v-if="record.actual || record.expected" placement="topLeft">
              <template #title>
                <div>
                  <div v-if="record.expected"><strong>期望值:</strong> {{ record.expected }}</div>
                  <div v-if="record.actual"><strong>实际值:</strong> {{ record.actual }}</div>
                </div>
              </template>
              <span class="failure-reason">
                {{ record.actual ? `实际: ${record.actual.slice(0, 30)}${record.actual.length > 30 ? '...' : ''}` : '检查失败' }}
              </span>
            </a-tooltip>
            <span v-else class="failure-reason">检查失败</span>
          </template>
          <span v-else style="color: #22C55E;">-</span>
        </template>
      </template>
    </a-table>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import {
  DownloadOutlined,
  FileMarkdownOutlined,
  FileExcelOutlined,
  UnorderedListOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  BugOutlined,
  WarningOutlined,
  InfoCircleOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons-vue'
import { hostsApi } from '@/api/hosts'
import type { ScanResult } from '@/api/types'

const props = defineProps<{
  hostId: string
}>()

const loading = ref(false)
const exporting = ref(false)
const results = ref<ScanResult[]>([])
const statusFilter = ref<'all' | 'fail' | 'pass'>('all')
const severityFilter = ref<string | undefined>(undefined)
const searchKeyword = ref('')
const pagination = ref({
  pageSize: 20,
  showSizeChanger: true,
  pageSizeOptions: ['10', '20', '50', '100', '200'],
  showTotal: (total: number) => `共 ${total} 条`
})

// P2-9: 单次 reduce 计算所有统计, 替 9 个 filter() 重复遍历同数组
const stats = computed(() => {
  const acc = {
    total: 0, pass: 0, fail: 0, error: 0,
    critical: 0, high: 0, medium: 0, low: 0,
    failed: [] as typeof results.value,
  }
  for (const r of results.value) {
    acc.total++
    if (r.status === 'pass') acc.pass++
    else if (r.status === 'fail') acc.fail++
    else if (r.status === 'error') acc.error++
    if (r.status === 'fail' || r.status === 'error') {
      acc.failed.push(r)
      if (r.severity === 'critical') acc.critical++
      else if (r.severity === 'high') acc.high++
      else if (r.severity === 'medium') acc.medium++
      else if (r.severity === 'low') acc.low++
    }
  }
  return acc
})

const totalCount = computed(() => stats.value.total)
const passCount = computed(() => stats.value.pass)
const failCount = computed(() => stats.value.fail)
const errorCount = computed(() => stats.value.error)

const failedResults = computed(() => stats.value.failed)
const criticalCount = computed(() => stats.value.critical)
const highCount = computed(() => stats.value.high)
const mediumCount = computed(() => stats.value.medium)
const lowCount = computed(() => stats.value.low)

// 点击严重级别快速筛选
const setSeverityFilter = (severity: string) => {
  const s = stats.value
  const map: Record<string, number> = {
    critical: s.critical, high: s.high, medium: s.medium, low: s.low,
  }
  if ((map[severity] || 0) > 0) {
    statusFilter.value = 'fail'
    severityFilter.value = severity
  }
}

// 过滤后的结果
const filteredResults = computed(() => {
  let filtered = results.value

  // 状态筛选
  if (statusFilter.value === 'fail') {
    filtered = filtered.filter(r => r.status === 'fail' || r.status === 'error')
  } else if (statusFilter.value === 'pass') {
    filtered = filtered.filter(r => r.status === 'pass')
  }

  // 严重级别筛选
  if (severityFilter.value) {
    filtered = filtered.filter(r => r.severity === severityFilter.value)
  }

  // 关键词搜索
  if (searchKeyword.value) {
    const keyword = searchKeyword.value.toLowerCase()
    filtered = filtered.filter(r =>
      r.rule_id?.toLowerCase().includes(keyword) ||
      r.title?.toLowerCase().includes(keyword)
    )
  }

  return filtered
})

const columns = [
  {
    title: '规则ID',
    dataIndex: 'rule_id',
    key: 'rule_id',
    width: 180,
    ellipsis: true,
  },
  {
    title: '类别',
    dataIndex: 'category',
    key: 'category',
    width: 100,
  },
  {
    title: '标题',
    dataIndex: 'title',
    key: 'title',
    ellipsis: true,
  },
  {
    title: '严重级别',
    key: 'severity',
    width: 90,
  },
  {
    title: '状态',
    key: 'status',
    width: 80,
  },
  {
    title: '失败原因',
    key: 'failure_reason',
    width: 200,
    ellipsis: true,
  },
  {
    title: '检查时间',
    dataIndex: 'checked_at',
    key: 'checked_at',
    width: 160,
  },
]

const loadBaselineResults = async () => {
  loading.value = true
  try {
    const hostDetail = await hostsApi.get(props.hostId)
    // 显示所有结果
    results.value = hostDetail.baseline_results || []
  } catch (error) {
    console.error('加载基线结果失败:', error)
  } finally {
    loading.value = false
  }
}

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    pass: 'green',
    fail: 'red',
    error: 'orange',
    na: 'default',
  }
  return colors[status] || 'default'
}

const getStatusText = (status: string) => {
  const texts: Record<string, string> = {
    pass: '通过',
    fail: '失败',
    error: '错误',
    na: '不适用',
  }
  return texts[status] || status
}

const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'blue',
  }
  return colors[severity] || 'default'
}

const getSeverityText = (severity: string) => {
  const texts: Record<string, string> = {
    critical: '严重',
    high: '高',
    medium: '中',
    low: '低',
  }
  return texts[severity] || severity
}

const handleExport = async ({ key }: { key: string }) => {
  exporting.value = true
  try {
    const format = key as 'markdown' | 'excel'
    await hostsApi.exportBaselineResults(props.hostId, format)
    message.success(`导出${format === 'markdown' ? 'Markdown' : 'Excel'}成功`)
  } catch (error) {
    console.error('导出失败:', error)
    message.error('导出失败，请重试')
  } finally {
    exporting.value = false
  }
}

const handleTableChange = (pag: any) => {
  pagination.value.pageSize = pag.pageSize
}

onMounted(() => {
  loadBaselineResults()
})
</script>

<style scoped lang="less">
.baseline-risk {
  width: 100%;
}

/* 统计卡片行 */
.stats-row {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  align-items: stretch;
}

.stat-card {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  background: var(--mxsec-card-bg);
  border-radius: 8px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
    0 2px 4px rgba(0, 0, 0, 0.04),
    0 4px 8px rgba(0, 0, 0, 0.04);
  transition: all 0.3s ease;
}

.stat-card.severity-card.clickable {
  cursor: pointer;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08),
      0 8px 24px rgba(0, 0, 0, 0.06);
  }
}

.stat-icon-bg {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  flex-shrink: 0;
  color: var(--mxsec-card-bg);
}

.total-bg {
  background: linear-gradient(135deg, #595959, #434343);
}

.pass-bg {
  background: linear-gradient(135deg, #22C55E, #009A29);
}

.fail-bg {
  background: linear-gradient(135deg, #EF4444, #DC2626);
}

.error-bg {
  background: linear-gradient(135deg, #F59E0B, #d48806);
}

.critical-bg {
  background: linear-gradient(135deg, #EF4444, #a8071a);
}

.high-bg {
  background: linear-gradient(135deg, #ff7a45, #d4380d);
}

.medium-bg {
  background: linear-gradient(135deg, #F59E0B, #d48806);
}

.low-bg {
  background: linear-gradient(135deg, #3B82F6, #2563EB);
}

.stat-info {
  flex: 1;
  min-width: 0;
}

.stat-value {
  font-size: 22px;
  font-weight: 700;
  color: var(--mxsec-text-1);
  line-height: 1;
  margin-bottom: 4px;

  &.pass { color: #22C55E; }
  &.fail { color: #EF4444; }
  &.error { color: #F59E0B; }
  &.critical { color: #DC2626; }
  &.high { color: #fa541c; }
  &.medium { color: #F59E0B; }
  &.low { color: var(--mxsec-primary); }
}

.stat-label {
  font-size: 13px;
  color: var(--mxsec-text-3);
  font-weight: 400;
}

.stat-divider {
  width: 1px;
  background: linear-gradient(180deg, transparent, #d9d9d9, transparent);
  margin: 4px 4px;
  flex-shrink: 0;
}

/* 筛选栏 */
.filter-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  padding: 12px 16px;
  background: var(--mxsec-fill-1);
  border-radius: 8px;
  border: 1px solid var(--mxsec-border);
}

.filter-left {
  display: flex;
  gap: 12px;
  align-items: center;
}

.filter-right {
  display: flex;
  gap: 12px;
  align-items: center;
}

.failure-reason {
  color: #EF4444;
  font-size: 12px;
  cursor: help;
}
</style>
