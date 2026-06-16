<template>
  <div class="policy-detail-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <div class="header-left">
        <a-button type="text" @click="handleBack" class="back-btn">
          <ArrowLeftOutlined />
        </a-button>
        <h2 class="page-title">{{ policy?.name || '基线检查详情' }}</h2>
      </div>
      <div class="header-right">
        <a-button type="primary" @click="handleBatchCheck">
          批量检查
        </a-button>
      </div>
    </div>

    <!-- 基线概述 -->
    <div class="overview-section">
      <div class="overview-header">
        <span class="overview-title">基线概述</span>
        <span class="last-check-time">最近检查时间: {{ lastCheckTime || '-' }}</span>
      </div>
      <div class="overview-stats-row">
        <div class="stat-card">
          <div class="stat-value" :style="{ color: getPassRateColor(passRate) }">{{ Math.floor(passRate) }}%</div>
          <div class="stat-label">通过率</div>
        </div>
        <div class="stat-divider"></div>
        <div class="stat-card">
          <div class="stat-value">{{ hostCount }}</div>
          <div class="stat-label">检查主机</div>
        </div>
        <div class="stat-divider"></div>
        <div class="stat-card">
          <div class="stat-value">{{ ruleCount }}</div>
          <div class="stat-label">检查项</div>
        </div>
        <div class="stat-divider"></div>
        <div class="stat-card">
          <div class="stat-value danger">{{ riskCount }}</div>
          <div class="stat-label">风险项</div>
        </div>
        <div class="stat-divider"></div>
        <div class="stat-card">
          <div class="stat-value success">{{ ruleCount - riskCount }}</div>
          <div class="stat-label">通过项</div>
        </div>
      </div>
    </div>

    <!-- 检查详情区 -->
    <div class="detail-section-wrapper">
      <div class="detail-section-header">
        <span class="section-title">检查详情</span>
      </div>
      <div class="detail-content">
        <!-- 左侧：检查项列表 (50%) -->
        <div class="left-panel">
          <a-table
            :columns="ruleColumns"
            :data-source="filteredRules"
            :loading="loading"
            :pagination="{ pageSize: 15, showSizeChanger: true, showTotal: (total: number) => `共 ${total} 条` }"
            :customRow="(record: Rule) => ({
              onClick: (event: MouseEvent) => {
                const target = event.target as HTMLElement
                if (
                  target.closest('.ant-checkbox-wrapper') ||
                  target.closest('.ant-checkbox') ||
                  target.closest('button') ||
                  target.closest('a')
                ) {
                  return
                }
                handleRuleClick(record)
              },
            })"
            row-key="rule_id"
            class="rule-table"
            :row-class-name="getRowClassName"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'title'">
                <a-tooltip :title="record.title" placement="topLeft">
                  <span class="ellipsis-text">{{ record.title }}</span>
                </a-tooltip>
              </template>
              <template v-else-if="column.key === 'severity'">
                <a-tag :color="getSeverityColor(record.severity)" class="severity-tag">
                  {{ getSeverityText(record.severity) }}
                </a-tag>
              </template>
              <template v-else-if="column.key === 'pass_rate'">
                <span v-if="getRulePassRate(record.rule_id) >= 0" :style="{ color: getPassRateColor(getRulePassRate(record.rule_id)) }">
                  {{ Math.floor(getRulePassRate(record.rule_id)) }}%
                </span>
                <span v-else class="no-data">-</span>
              </template>
            </template>
          </a-table>
        </div>

        <!-- 右侧：检查项详情 (50%) -->
        <div class="right-panel">
          <div v-if="selectedRule" class="rule-detail">
            <!-- 检查项详情：描述和加固建议 -->
            <div class="detail-info-section">
              <h3 class="rule-detail-title">{{ selectedRule.title }}</h3>

              <!-- 描述 -->
              <div class="detail-block">
                <div class="detail-block-label">描述</div>
                <div v-if="selectedRule.description" class="description-content">
                  <div
                    v-for="(line, index) in formatDescription(selectedRule.description)"
                    :key="index"
                    class="description-line"
                  >
                    {{ line }}
                  </div>
                </div>
                <div v-else class="detail-text-empty">-</div>
              </div>

              <!-- 加固建议 -->
              <div class="detail-block">
                <div class="detail-block-label">加固建议</div>
                <div v-if="selectedRule.fix_config?.suggestion" class="suggestion-content">
                  <div
                    v-for="(solution, index) in parseSuggestion(selectedRule.fix_config.suggestion)"
                    :key="index"
                    class="solution-item"
                  >
                    <div class="solution-title">{{ solution.title }}</div>
                    <ol v-if="solution.steps.length > 0" class="solution-steps">
                      <li v-for="(step, stepIndex) in solution.steps" :key="stepIndex" class="solution-step">
                        {{ step }}
                      </li>
                    </ol>
                    <div v-else class="solution-text">{{ solution.content }}</div>
                  </div>
                </div>
                <div v-else class="detail-text-empty">-</div>
              </div>
            </div>

            <!-- 影响主机区域 -->
            <div class="affected-hosts-section">
              <div class="hosts-header">
                <span class="hosts-title">影响主机</span>
                <div class="hosts-actions">
                  <a-button
                    size="small"
                    :disabled="selectedHostIds.length === 0"
                    @click="handleBatchExportHosts"
                  >
                    批量导出
                  </a-button>
                  <a-button
                    type="primary"
                    size="small"
                    :disabled="selectedHostIds.length === 0"
                    @click="handleBatchRecheckHosts"
                  >
                    重新检查
                  </a-button>
                </div>
              </div>

              <!-- 搜索筛选栏 -->
              <div class="hosts-filter-bar">
                <a-input
                  v-model:value="hostSearchKeyword"
                  placeholder="搜索主机名"
                  class="host-search-input"
                  allow-clear
                >
                  <template #prefix>
                    <SearchOutlined />
                  </template>
                </a-input>
                <a-button type="primary" size="small" @click="handleHostSearch">
                  搜索
                </a-button>
                <a-button size="small" @click="loadAffectedHosts">
                  <ReloadOutlined />
                </a-button>
              </div>

              <!-- 主机列表 -->
              <a-table
                :columns="hostColumns"
                :data-source="filteredAffectedHosts"
                :loading="hostsLoading"
                :pagination="{ pageSize: 10, showSizeChanger: true, showTotal: (total: number) => `共 ${total} 条` }"
                :row-selection="{
                  selectedRowKeys: selectedHostIds,
                  onChange: handleHostSelectionChange,
                }"
                row-key="host_id"
                class="host-table"
                size="small"
              >
                <template #bodyCell="{ column, record }">
                  <template v-if="column.key === 'hostname'">
                    <div class="host-info-cell">
                      <span>{{ record.hostname }}</span>
                      <a-tooltip title="复制主机名">
                        <CopyOutlined class="copy-icon" @click.stop="handleCopy(record.hostname, '主机名')" />
                      </a-tooltip>
                    </div>
                  </template>
                  <template v-else-if="column.key === 'host_id'">
                    <div class="host-info-cell">
                      <span class="host-id-text">{{ record.host_id.slice(0, 8) }}...</span>
                      <a-tooltip title="复制主机ID">
                        <CopyOutlined class="copy-icon" @click.stop="handleCopy(record.host_id, '主机ID')" />
                      </a-tooltip>
                    </div>
                  </template>
                  <template v-else-if="column.key === 'result'">
                    <a-tag :color="getResultColor(record.status)" class="result-tag">
                      {{ getResultText(record.status) }}
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
                          {{ record.actual ? `实际: ${record.actual}` : '检查失败' }}
                        </span>
                      </a-tooltip>
                      <span v-else class="failure-reason">检查失败</span>
                    </template>
                    <span v-else class="pass-text">-</span>
                  </template>
                  <template v-else-if="column.key === 'action'">
                    <a-button type="link" size="small" @click="handleWhitelist(record)">
                      加白名单
                    </a-button>
                  </template>
                </template>
                <template #emptyText>
                  <a-empty description="暂无数据" :image="false" />
                </template>
              </a-table>
            </div>
          </div>
          <a-empty v-else description="请从左侧选择一个检查项查看详情" class="empty-state" />
        </div>
      </div>
    </div>

    <!-- 主机选择对话框 -->
    <HostSelectorModal
      v-model:open="hostSelectorVisible"
      :title="hostSelectorTitle"
      :policy-os-family="policy?.os_family || []"
      :policy-os-version="policy?.os_version || ''"
      @confirm="handleHostSelectorConfirm"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ArrowLeftOutlined, ReloadOutlined, SearchOutlined, CopyOutlined } from '@ant-design/icons-vue'
import { policiesApi } from '@/api/policies'
import { resultsApi } from '@/api/results'
import { hostsApi } from '@/api/hosts'
import { tasksApi } from '@/api/tasks'
import type { Policy, Rule, ScanResult } from '@/api/types'
import { message } from 'ant-design-vue'
import HostSelectorModal from './components/HostSelectorModal.vue'

const router = useRouter()
const route = useRoute()

const loading = ref(false)
const hostsLoading = ref(false)
const policy = ref<Policy | null>(null)
const rules = ref<Rule[]>([])
const selectedRule = ref<Rule | null>(null)
const affectedHosts = ref<any[]>([])
const selectedHostIds = ref<string[]>([])
const hostSearchKeyword = ref('')
const lastCheckTime = ref('')

// 主机选择器
const hostSelectorVisible = ref(false)
const hostSelectorTitle = ref('选择检查主机范围')
const pendingRecheckRuleIds = ref<string[]>([])
const recheckLoading = ref(false)

// 统计数据
const passRate = ref(0)
const hostCount = ref(0)
const hostPassCount = ref(0)
const ruleCount = ref(0)
const riskCount = ref(0)

const ruleColumns = [
  {
    title: '检查项',
    key: 'title',
    dataIndex: 'title',
    ellipsis: true,
  },
  {
    title: '级别',
    key: 'severity',
    width: 80,
    align: 'center' as const,
    sorter: (a: Rule, b: Rule) => {
      const severityOrder: Record<string, number> = {
        critical: 4,
        high: 3,
        medium: 2,
        low: 1,
      }
      return (severityOrder[a.severity] || 0) - (severityOrder[b.severity] || 0)
    },
  },
  {
    title: '通过率',
    key: 'pass_rate',
    width: 90,
    align: 'center' as const,
    sorter: (a: Rule, b: Rule) => {
      return getRulePassRate(a.rule_id) - getRulePassRate(b.rule_id)
    },
  },
]

const hostColumns = [
  {
    title: '主机名',
    key: 'hostname',
    dataIndex: 'hostname',
    width: 180,
  },
  {
    title: '主机ID',
    key: 'host_id',
    dataIndex: 'host_id',
    width: 150,
  },
  {
    title: '检查结果',
    key: 'result',
    width: 100,
  },
  {
    title: '失败原因',
    key: 'failure_reason',
    ellipsis: true,
  },
  {
    title: '操作',
    key: 'action',
    width: 100,
  },
]

const filteredRules = computed(() => {
  return rules.value
})

const filteredAffectedHosts = computed(() => {
  if (!hostSearchKeyword.value) return affectedHosts.value
  return affectedHosts.value.filter((host) =>
    host.hostname?.toLowerCase().includes(hostSearchKeyword.value.toLowerCase())
  )
})

const loadPolicyDetail = async () => {
  const policyId = route.params.policyId as string
  if (!policyId) return

  loading.value = true
  try {
    const data = (await policiesApi.get(policyId)) as unknown as Policy
    policy.value = data
    rules.value = data.rules || []
    ruleCount.value = rules.value.length

    console.log('加载策略详情成功:', {
      policyId,
      ruleCount: rules.value.length,
      rules: rules.value,
    })

    // 如果规则列表不为空且没有选中项，默认选中第一项
    if (rules.value.length > 0 && !selectedRule.value) {
      handleRuleClick(rules.value[0])
    }

    // 加载检查结果统计
    await loadStatistics()
  } catch (error) {
    console.error('加载策略详情失败:', error)
  } finally {
    loading.value = false
  }
}

const loadStatistics = async () => {
  if (!policy.value) return

  try {
    // 使用统计 API 获取策略统计信息
    const statistics = await policiesApi.getStatistics(policy.value.id) as any

    // 更新统计数据
    passRate.value = statistics.pass_rate || 0
    hostCount.value = statistics.host_count || 0
    ruleCount.value = statistics.rule_count || 0
    riskCount.value = statistics.risk_count || 0

    // 计算通过的主机数（从统计信息中获取）
    hostPassCount.value = statistics.host_count - (statistics.fail_count || 0)

    // 更新最后检查时间
    if (statistics.last_check_time) {
      lastCheckTime.value = new Date(statistics.last_check_time).toLocaleString('zh-CN')
    }

    // 加载所有检查结果用于计算每个规则的通过率
    await loadRulePassRates()
  } catch (error) {
    console.error('加载统计信息失败:', error)
    // 如果 API 失败，回退到手动计算方式
    await loadStatisticsFallback()
  }
}

// 加载所有检查结果并计算每个规则的通过率
const loadRulePassRates = async () => {
  if (!policy.value) return

  try {
    const resultsResponse = (await resultsApi.list({
      policy_id: policy.value.id,
      page_size: 10000,
    })) as unknown as { total: number; items: ScanResult[] }

    const results = resultsResponse.items

    // 按规则分组计算通过率
    const ruleResultsMap = new Map<string, { pass: number; total: number }>()

    results.forEach((r: ScanResult) => {
      if (!ruleResultsMap.has(r.rule_id)) {
        ruleResultsMap.set(r.rule_id, { pass: 0, total: 0 })
      }
      const stats = ruleResultsMap.get(r.rule_id)!
      stats.total++
      if (r.status === 'pass') {
        stats.pass++
      }
    })

    // 计算并缓存每个规则的通过率
    rulePassRateCache.value.clear()
    ruleResultsMap.forEach((stats, ruleId) => {
      const rate = stats.total > 0 ? Math.round((stats.pass / stats.total) * 100) : 0
      rulePassRateCache.value.set(ruleId, rate)
    })
  } catch (error) {
    console.error('加载规则通过率失败:', error)
  }
}

// 回退的统计计算方式
const loadStatisticsFallback = async () => {
  if (!policy.value) return

  try {
    const resultsResponse = (await resultsApi.list({
      policy_id: policy.value!.id,
      page_size: 10000,
    })) as unknown as { total: number; items: ScanResult[] }

    const results = resultsResponse.items
    const hostIds = new Set(results.map((r: ScanResult) => r.host_id))
    hostCount.value = hostIds.size

    const totalResults = results.length
    const passResults = results.filter((r: ScanResult) => r.status === 'pass').length
    passRate.value = totalResults > 0 ? Math.round((passResults / totalResults) * 100) : 0

    const failedRules = new Set(
      results.filter((r: ScanResult) => r.status === 'fail').map((r: ScanResult) => r.rule_id)
    )
    riskCount.value = failedRules.size

    const hostResultsMap = new Map<string, ScanResult[]>()
    results.forEach((r: ScanResult) => {
      if (!hostResultsMap.has(r.host_id)) {
        hostResultsMap.set(r.host_id, [])
      }
      hostResultsMap.get(r.host_id)!.push(r)
    })

    let passHostCount = 0
    hostResultsMap.forEach((hostResults) => {
      const allPass = hostResults.every((r) => r.status === 'pass')
      if (allPass) {
        passHostCount++
      }
    })
    hostPassCount.value = passHostCount

    // 同时计算每个规则的通过率
    const ruleResultsMap = new Map<string, { pass: number; total: number }>()
    results.forEach((r: ScanResult) => {
      if (!ruleResultsMap.has(r.rule_id)) {
        ruleResultsMap.set(r.rule_id, { pass: 0, total: 0 })
      }
      const stats = ruleResultsMap.get(r.rule_id)!
      stats.total++
      if (r.status === 'pass') {
        stats.pass++
      }
    })

    rulePassRateCache.value.clear()
    ruleResultsMap.forEach((stats, ruleId) => {
      const rate = stats.total > 0 ? Math.round((stats.pass / stats.total) * 100) : 0
      rulePassRateCache.value.set(ruleId, rate)
    })
  } catch (fallbackError) {
    console.error('回退统计计算失败:', fallbackError)
  }
}

const loadAffectedHosts = async () => {
  if (!selectedRule.value || !policy.value) return

  hostsLoading.value = true
  try {
    const resultsResponse = (await resultsApi.list({
      policy_id: policy.value.id,
      rule_id: selectedRule.value.rule_id,
      page_size: 1000,
    })) as unknown as { total: number; items: ScanResult[] }

    // 收集所有主机ID
    const hostIds = [...new Set(resultsResponse.items.map(r => r.host_id))]

    // 批量获取主机信息
    let hostsMap = new Map<string, { hostname: string; tags: string[] }>()
    if (hostIds.length > 0) {
      try {
        const hostsResponse = await hostsApi.list({ page_size: 1000 }) as any
        const hosts = hostsResponse.items || []
        hosts.forEach((h: any) => {
          hostsMap.set(h.host_id, { hostname: h.hostname, tags: h.tags || [] })
        })
      } catch (e) {
        console.error('获取主机列表失败:', e)
      }
    }

    // 按主机分组，保留最新的检测结果
    const hostMap = new Map()
    resultsResponse.items.forEach((result: ScanResult) => {
      const hostInfo = hostsMap.get(result.host_id)
      if (!hostMap.has(result.host_id)) {
        hostMap.set(result.host_id, {
          host_id: result.host_id,
          hostname: hostInfo?.hostname || result.host_id,
          status: result.status,
          actual: result.actual || '',
          expected: result.expected || '',
          tags: hostInfo?.tags || [],
        })
      }
    })

    affectedHosts.value = Array.from(hostMap.values())
  } catch (error) {
    console.error('加载受影响主机失败:', error)
  } finally {
    hostsLoading.value = false
  }
}

// 存储规则通过率缓存
const rulePassRateCache = ref<Map<string, number>>(new Map())

const getRulePassRate = (ruleId: string): number => {
  // 返回缓存的真实通过率，如果没有数据则返回 -1 表示无数据
  if (rulePassRateCache.value.has(ruleId)) {
    return rulePassRateCache.value.get(ruleId)!
  }
  return -1 // 无数据
}

const getPassRateColor = (rate: number): string => {
  if (rate >= 90) return '#22C55E'
  if (rate >= 70) return '#F59E0B'
  if (rate >= 50) return '#D25F00'
  return '#EF4444'
}

const getRowClassName = (record: Rule) => {
  return selectedRule.value?.rule_id === record.rule_id ? 'table-row-selected' : ''
}

const handleBack = () => {
  // 检查是否有历史记录，如果有则返回上一页，否则跳转到策略列表
  if (window.history.length > 1) {
    router.back()
  } else {
    router.push('/policies')
  }
}

// 批量检查 - 检查所有规则
const handleBatchCheck = () => {
  hostSelectorTitle.value = '批量检查 - 选择主机范围'
  pendingRecheckRuleIds.value = [] // 空数组表示检查所有规则
  hostSelectorVisible.value = true
}

const handleRuleClick = (record: Rule) => {
  console.log('点击检查项:', record)
  selectedRule.value = record
  loadAffectedHosts()
}

const handleHostSelectionChange = (keys: string[]) => {
  selectedHostIds.value = keys
}

const handleHostSearch = () => {
  // 搜索已通过filteredAffectedHosts处理
}

// 主机选择确认处理
const handleHostSelectorConfirm = async (data: {
  mode: 'global' | 'custom'
  targetType: 'all' | 'host_ids' | 'os_family'
  hostIds?: string[]
  osFamily?: string[]
}) => {
  if (!policy.value) {
    message.error('策略信息未加载')
    return
  }

  recheckLoading.value = true
  try {
    // 构建任务名称 - 格式: {策略名} - {检查范围} - {时间}
    const dateStr = new Date().toLocaleString('zh-CN', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    }).replace(/\//g, '-')

    let taskName = ''
    if (pendingRecheckRuleIds.value.length === 0) {
      taskName = `${policy.value.name} - 全量检查 - ${dateStr}`
    } else if (pendingRecheckRuleIds.value.length === 1) {
      const rule = rules.value.find(r => r.rule_id === pendingRecheckRuleIds.value[0])
      const ruleTitle = rule?.title || pendingRecheckRuleIds.value[0]
      // 规则标题过长时截断
      const shortTitle = ruleTitle.length > 20 ? ruleTitle.slice(0, 20) + '...' : ruleTitle
      taskName = `${policy.value.name} - ${shortTitle} - ${dateStr}`
    } else {
      taskName = `${policy.value.name} - ${pendingRecheckRuleIds.value.length}个规则 - ${dateStr}`
    }

    // 构建任务目标
    const targets: {
      type: 'all' | 'host_ids' | 'os_family'
      host_ids?: string[]
      os_family?: string[]
    } = {
      type: data.targetType,
    }

    if (data.targetType === 'host_ids' && data.hostIds) {
      targets.host_ids = data.hostIds
    } else if (data.targetType === 'os_family' && data.osFamily) {
      targets.os_family = data.osFamily
    }

    // 创建任务
    const taskData = {
      name: taskName,
      type: 'manual' as const,
      targets,
      policy_id: policy.value.id,
      rule_ids: pendingRecheckRuleIds.value.length > 0 ? pendingRecheckRuleIds.value : undefined,
    }

    await tasksApi.create(taskData)
    message.success('检查任务创建成功，请前往任务执行页面手动执行')

    // 清空待检查规则
    pendingRecheckRuleIds.value = []

  } catch (error) {
    console.error('创建检查任务失败:', error)
  } finally {
    recheckLoading.value = false
  }
}

const handleWhitelist = (host: any) => {
  message.info(`将主机 ${host.hostname} 加入白名单`)
  // TODO: 实现加白名单
}

// 复制内容到剪贴板
const handleCopy = async (text: string, label: string) => {
  try {
    await navigator.clipboard.writeText(text)
    message.success(`${label}已复制到剪贴板`)
  } catch (error) {
    console.error('复制失败:', error)
    message.error('复制失败，请手动复制')
  }
}

// 批量导出受影响主机
const handleBatchExportHosts = () => {
  message.info(`批量导出 ${selectedHostIds.value.length} 个主机`)
  // TODO: 实现批量导出主机
}

// 批量重新检查选中的主机
const handleBatchRecheckHosts = () => {
  if (!selectedRule.value) {
    message.warning('请先选择一个规则')
    return
  }

  // 设置要检查的规则
  pendingRecheckRuleIds.value = [selectedRule.value.rule_id]
  hostSelectorTitle.value = '选择重新检查的主机范围'

  // 打开主机选择器，让用户选择主机范围
  hostSelectorVisible.value = true
}

const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = {
    critical: 'red',
    high: 'red',
    medium: 'orange',
    low: 'blue',
  }
  return colors[severity] || 'default'
}

const getSeverityText = (severity: string) => {
  const texts: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  }
  return texts[severity] || severity
}

const getResultColor = (status: string) => {
  const colors: Record<string, string> = {
    pass: 'green',
    fail: 'red',
    error: 'orange',
    na: 'default',
  }
  return colors[status] || 'default'
}

const getResultText = (status: string) => {
  const texts: Record<string, string> = {
    pass: '通过',
    fail: '失败',
    error: '错误',
    na: '不适用',
  }
  return texts[status] || status
}

// 格式化描述：将描述文本按换行分割，支持多行显示
const formatDescription = (description: string): string[] => {
  if (!description) return []
  return description
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}

// 解析加固建议：支持多个方案和步骤
interface Solution {
  title: string
  content: string
  steps: string[]
}

const parseSuggestion = (suggestion: string): Solution[] => {
  if (!suggestion) return []

  const solutions: Solution[] = []
  const lines = suggestion.split('\n').map((line) => line.trim()).filter((line) => line.length > 0)

  let currentSolution: Solution | null = null

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    // 检测方案标题（支持"方案一"、"方案二"、"方案1"、"方案2"等格式）
    const solutionMatch = line.match(/^方案[一二三四五六七八九十\d]+[：:]\s*(.+)$/)
    if (solutionMatch) {
      // 保存上一个方案
      if (currentSolution) {
        solutions.push(currentSolution)
      }
      // 创建新方案
      currentSolution = {
        title: solutionMatch[1] || solutionMatch[0],
        content: '',
        steps: [],
      }
      continue
    }

    // 如果没有当前方案，创建默认方案
    if (!currentSolution) {
      currentSolution = {
        title: '修复建议',
        content: '',
        steps: [],
      }
    }

    // 检测步骤（支持多种格式：1. 2. ① ② 等）
    // 优先匹配数字编号格式（1. 或 1、）
    const numStepMatch = line.match(/^(\d+)[.、]\s*(.+)$/)
    if (numStepMatch) {
      currentSolution.steps.push(numStepMatch[2])
      continue
    }

    // 匹配中文数字编号（① ② ③ 等）
    const chineseNumMatch = line.match(/^[①②③④⑤⑥⑦⑧⑨⑩][.、]?\s*(.+)$/)
    if (chineseNumMatch) {
      currentSolution.steps.push(chineseNumMatch[1])
      continue
    }

    // 匹配带括号的数字（(1) 或 （1））
    const parenNumMatch = line.match(/^[（(](\d+)[）)]\s*(.+)$/)
    if (parenNumMatch) {
      currentSolution.steps.push(parenNumMatch[2])
      continue
    }

    // 普通文本行
    if (currentSolution.steps.length === 0) {
      // 如果没有步骤，作为内容
      if (currentSolution.content) {
        currentSolution.content += '\n' + line
      } else {
        currentSolution.content = line
      }
    } else {
      // 如果有步骤，可能是步骤的续行（如果行首不是数字或特殊字符）
      if (!line.match(/^[\d①②③④⑤⑥⑦⑧⑨⑩（(]/)) {
        const lastStepIndex = currentSolution.steps.length - 1
        currentSolution.steps[lastStepIndex] += ' ' + line
      } else {
        // 如果行首是数字或特殊字符但不是步骤格式，作为新内容
        if (currentSolution.content) {
          currentSolution.content += '\n' + line
        } else {
          currentSolution.content = line
        }
      }
    }
  }

  // 保存最后一个方案
  if (currentSolution) {
    solutions.push(currentSolution)
  }

  // 如果没有解析出任何方案，返回原始文本作为单个方案
  if (solutions.length === 0) {
    return [
      {
        title: '修复建议',
        content: suggestion,
        steps: [],
      },
    ]
  }

  return solutions
}

onMounted(() => {
  loadPolicyDetail()
})
</script>

<style scoped>
.policy-detail-page {
  width: 100%;
}

/* 页面头部 */
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--mxsec-border);
}

.header-left {
  display: flex;
  align-items: center;
}

.back-btn {
  padding: 0;
  margin-right: 12px;
  font-size: 16px;
  color: #595959;
  transition: color 0.3s;
}

.back-btn:hover {
  color: var(--mxsec-primary);
}

.page-title {
  font-size: 20px;
  font-weight: 600;
  margin: 0;
  color: var(--mxsec-text-1);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

/* 基线概述区域 */
.overview-section {
  background: var(--mxsec-card-bg);
  border-radius: 8px;
  padding: 20px 24px;
  margin-bottom: 20px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
}

.overview-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
}

.overview-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.last-check-time {
  font-size: 13px;
  color: var(--mxsec-text-3);
}

.overview-stats-row {
  display: flex;
  align-items: center;
  justify-content: space-around;
}

.stat-card {
  text-align: center;
  padding: 0 24px;
}

.stat-value {
  font-size: 32px;
  font-weight: 600;
  color: var(--mxsec-text-1);
  line-height: 1.2;
  margin-bottom: 8px;
}

.stat-value.danger {
  color: #EF4444;
}

.stat-value.success {
  color: #22C55E;
}

.stat-label {
  font-size: 14px;
  color: var(--mxsec-text-3);
}

.stat-divider {
  width: 1px;
  height: 50px;
  background: var(--mxsec-fill-3);
}

/* 检查详情区域 */
.detail-section-wrapper {
  background: var(--mxsec-card-bg);
  border-radius: 8px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
}

.detail-section-header {
  padding: 16px 24px;
  border-bottom: 1px solid var(--mxsec-border);
}

.section-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.detail-content {
  display: flex;
  min-height: 600px;
}

/* 左侧面板 - 50% */
.left-panel {
  flex: 0 0 50%;
  border-right: 1px solid var(--mxsec-border);
  padding: 16px 20px;
  min-width: 0;
}

/* 表格样式 */
.rule-table :deep(.ant-table) {
  background: var(--mxsec-card-bg);
}

.rule-table :deep(.ant-table-thead > tr > th) {
  background: var(--mxsec-fill-1);
  font-weight: 600;
  color: var(--mxsec-text-1);
  border-bottom: 1px solid var(--mxsec-border);
  padding: 12px 16px;
  font-size: 13px;
}

.rule-table :deep(.ant-table-tbody > tr) {
  cursor: pointer;
  transition: all 0.2s;
}

.rule-table :deep(.ant-table-tbody > tr > td) {
  padding: 12px 16px;
  font-size: 13px;
  border-bottom: 1px solid var(--mxsec-border-light);
}

.rule-table :deep(.ant-table-tbody > tr:hover) {
  background: #f5f7fa;
}

.rule-table :deep(.ant-table-tbody > tr.table-row-selected) {
  background: var(--mxsec-primary-bg);
}

.rule-table :deep(.ant-table-tbody > tr.table-row-selected:hover) {
  background: #bae7ff;
}

.rule-table :deep(.ant-table-tbody > tr:last-child > td) {
  border-bottom: none;
}

.ellipsis-text {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.severity-tag {
  font-weight: 500;
  border: none;
  padding: 2px 10px;
  border-radius: 4px;
  font-size: 12px;
}

.no-data {
  color: #bfbfbf;
}

/* 右侧面板 - 50% */
.right-panel {
  flex: 0 0 50%;
  padding: 16px 20px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-width: 0;
}

.rule-detail {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}

/* 检查项详情区域 */
.detail-info-section {
  flex-shrink: 0;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--mxsec-border);
  margin-bottom: 20px;
}

.rule-detail-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--mxsec-text-1);
  margin: 0 0 16px 0;
  line-height: 1.5;
}

.detail-block {
  margin-bottom: 16px;
}

.detail-block:last-child {
  margin-bottom: 0;
}

.detail-block-label {
  font-size: 14px;
  font-weight: 600;
  color: var(--mxsec-text-1);
  margin-bottom: 8px;
}

.detail-text-empty {
  color: #bfbfbf;
  font-size: 13px;
  font-style: italic;
}

.description-content {
  color: #595959;
  font-size: 13px;
  line-height: 1.8;
}

.description-line {
  margin-bottom: 4px;
}

.description-line:last-child {
  margin-bottom: 0;
}

.suggestion-content {
  color: #595959;
  font-size: 13px;
  line-height: 1.8;
}

.solution-item {
  margin-bottom: 12px;
}

.solution-item:last-child {
  margin-bottom: 0;
}

.solution-title {
  font-weight: 600;
  color: var(--mxsec-text-1);
  font-size: 13px;
  margin-bottom: 8px;
  padding-left: 8px;
  border-left: 3px solid #3B82F6;
}

.solution-steps {
  margin: 0;
  padding-left: 20px;
  color: #595959;
}

.solution-step {
  margin-bottom: 4px;
  line-height: 1.7;
}

.solution-step:last-child {
  margin-bottom: 0;
}

.solution-text {
  color: #595959;
  line-height: 1.7;
  white-space: pre-wrap;
  word-wrap: break-word;
}

/* 影响主机区域 */
.affected-hosts-section {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
}

.hosts-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
  flex-shrink: 0;
}

.hosts-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.hosts-actions {
  display: flex;
  gap: 8px;
}

.hosts-filter-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  flex-shrink: 0;
}

.host-search-input {
  flex: 1;
  max-width: 200px;
}

.host-tags {
  color: var(--mxsec-text-3);
  font-size: 12px;
}

/* 主机表格 */
.host-table {
  flex: 1;
  overflow: auto;
}

.host-table :deep(.ant-table) {
  background: transparent;
}

.host-table :deep(.ant-table-container) {
  border: none;
}

.host-table :deep(.ant-table-thead > tr > th) {
  background: var(--mxsec-fill-1);
  font-weight: 600;
  color: var(--mxsec-text-1);
  border-bottom: 1px solid var(--mxsec-border);
  padding: 10px 12px;
  font-size: 12px;
}

.host-table :deep(.ant-table-tbody > tr > td) {
  border-bottom: 1px solid var(--mxsec-border-light);
  padding: 10px 12px;
  font-size: 12px;
}

.host-table :deep(.ant-table-tbody > tr:last-child > td) {
  border-bottom: none;
}

.result-tag {
  font-weight: 500;
  border: none;
  padding: 2px 8px;
  font-size: 12px;
}

.empty-state {
  padding: 60px 0;
}

/* 主机信息单元格样式 */
.host-info-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.host-id-text {
  font-family: monospace;
  color: #595959;
}

.copy-icon {
  color: #bfbfbf;
  cursor: pointer;
  font-size: 12px;
  transition: color 0.2s;
}

.copy-icon:hover {
  color: var(--mxsec-primary);
}

/* 失败原因样式 */
.failure-reason {
  color: #EF4444;
  font-size: 12px;
  cursor: help;
}

.pass-text {
  color: #bfbfbf;
}

/* 响应式 */
@media (max-width: 1200px) {
  .detail-content {
    flex-direction: column;
  }

  .left-panel {
    flex: none;
    border-right: none;
    border-bottom: 1px solid var(--mxsec-border);
    padding-bottom: 20px;
  }

  .right-panel {
    flex: none;
    padding-top: 20px;
    max-height: none;
  }
}

@media (max-width: 768px) {
  .overview-stats-row {
    flex-wrap: wrap;
    gap: 20px;
  }

  .stat-divider {
    display: none;
  }

  .stat-card {
    flex: 0 0 calc(50% - 10px);
    padding: 10px;
  }
}
</style>
