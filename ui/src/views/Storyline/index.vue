<template>
  <div class="storyline-page">
    <div class="page-header">
      <h2>攻击故事线</h2>
      <a-button @click="handleRefresh">
        <ReloadOutlined /> 刷新
      </a-button>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[12, 12]" class="section-row">
      <a-col :span="8">
        <StatCard title="总故事线" :value="stats.total" color="#3B82F6" />
      </a-col>
      <a-col :span="8">
        <StatCard title="活跃" :value="stats.active" color="#F59E0B" />
      </a-col>
      <a-col :span="8">
        <StatCard title="严重 (活跃)" :value="stats.critical_active" color="#EF4444" />
      </a-col>
    </a-row>

    <!-- 筛选栏 -->
    <div class="filter-bar">
      <a-input v-model:value="filters.host_id" placeholder="主机 ID" style="width: 200px" allow-clear @pressEnter="handleSearch" />
      <a-select v-model:value="filters.severity" placeholder="严重度" style="width: 120px" allow-clear @change="handleSearch">
        <a-select-option value="critical">严重</a-select-option>
        <a-select-option value="high">高危</a-select-option>
        <a-select-option value="medium">中危</a-select-option>
        <a-select-option value="low">低危</a-select-option>
      </a-select>
      <a-select v-model:value="filters.status" placeholder="状态" style="width: 120px" allow-clear @change="handleSearch">
        <a-select-option value="active">活跃</a-select-option>
        <a-select-option value="investigating">调查中</a-select-option>
        <a-select-option value="resolved">已处理</a-select-option>
      </a-select>
    </div>

    <!-- 故事线表格 -->
    <a-table
      :columns="columns"
      :data-source="storylines"
      :loading="loading"
      :pagination="pagination"
      row-key="id"
      size="small"
      @change="handleTableChange"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'severity'">
          <a-tag :color="getSeverityConfig(record.severity).tagColor">
            {{ getSeverityConfig(record.severity).label }}
          </a-tag>
        </template>
        <template v-if="column.key === 'risk_score'">
          <a-progress
            :percent="record.risk_score"
            :stroke-color="record.risk_score >= 80 ? '#EF4444' : record.risk_score >= 60 ? '#F59E0B' : '#FADC19'"
            :size="[80, 6]"
            :show-info="true"
          />
        </template>
        <template v-if="column.key === 'phase'">
          <a-tag color="volcano">{{ getPhaseLabel(record.phase) }}</a-tag>
        </template>
        <template v-if="column.key === 'status'">
          <a-tag :color="getStatusColor(record.status)">{{ getStatusLabel(record.status) }}</a-tag>
        </template>
        <template v-if="column.key === 'action'">
          <a-space>
            <a @click="showDetail(record)">详情</a>
            <a v-if="record.status === 'active'" @click="handleResolve(record)">处理</a>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 故事线详情抽屉 -->
    <DetailDrawer v-model:open="detailVisible" title="攻击故事线详情" :width="700">
      <a-spin :spinning="detailLoading">
        <template v-if="detail">
          <!-- 顶部: 风险评分 + 严重度 + MITRE 阶段 -->
          <div class="story-header">
            <div class="story-score-ring">
              <svg width="70" height="70" viewBox="0 0 70 70">
                <circle cx="35" cy="35" r="30" fill="none" stroke="rgba(30,58,95,0.3)" stroke-width="5" />
                <circle cx="35" cy="35" r="30" fill="none"
                  :stroke="riskScoreColor(detail.storyline.risk_score)"
                  stroke-width="5"
                  :stroke-dasharray="188.5"
                  :stroke-dashoffset="188.5 * (1 - detail.storyline.risk_score / 100)"
                  stroke-linecap="round" transform="rotate(-90 35 35)"
                />
              </svg>
              <div class="score-text" :style="{ color: riskScoreColor(detail.storyline.risk_score) }">
                {{ detail.storyline.risk_score }}
              </div>
            </div>
            <div class="story-meta">
              <h3 class="story-id">{{ detail.storyline.story_id }}</h3>
              <div class="story-tags">
                <a-tag :color="getSeverityConfig(detail.storyline.severity).tagColor">
                  {{ getSeverityConfig(detail.storyline.severity).label }}
                </a-tag>
                <a-tag v-if="detail.storyline.phase" color="volcano">
                  {{ getPhaseLabel(detail.storyline.phase) }}
                </a-tag>
                <a-tag :color="getStatusColor(detail.storyline.status)">
                  {{ getStatusLabel(detail.storyline.status) }}
                </a-tag>
              </div>
              <div class="story-info">
                <span>主机: {{ detail.storyline.hostname }}</span>
                <span>事件: {{ detail.storyline.event_count }}</span>
                <span>告警: {{ detail.storyline.alert_count || 0 }}</span>
              </div>
            </div>
          </div>

          <!-- 摘要 -->
          <div v-if="detail.storyline.summary" class="story-summary">
            {{ detail.storyline.summary }}
          </div>

          <!-- 匹配规则 -->
          <div v-if="detail.storyline.rule_names" class="story-rules">
            <span class="section-label">匹配规则</span>
            <span class="rule-text">{{ detail.storyline.rule_names }}</span>
          </div>

          <!-- 时间范围 -->
          <div class="story-timerange">
            <span class="section-label">时间范围</span>
            <span>{{ detail.storyline.first_seen_at }} — {{ detail.storyline.last_seen_at }}</span>
          </div>

          <!-- 事件时间线 -->
          <div class="timeline-section">
            <div class="section-label">事件时间线 ({{ detail.events.length }})</div>
            <a-timeline mode="left" class="story-timeline">
              <a-timeline-item
                v-for="event in detail.events"
                :key="event.id"
                :color="event.rule_name ? '#EF4444' : '#3B82F6'"
              >
                <div class="tl-event">
                  <div class="tl-header">
                    <span class="tl-time">{{ event.timestamp }}</span>
                    <a-tag size="small" :color="getEventTypeColor(event.event_type)">{{ event.event_type }}</a-tag>
                    <a-tag v-if="event.rule_name" size="small" color="red">{{ event.rule_name }}</a-tag>
                  </div>
                  <div class="tl-body">
                    <code>{{ event.exe }}</code>
                    <span v-if="event.pid" class="tl-pid"> (PID: {{ event.pid }})</span>
                  </div>
                </div>
              </a-timeline-item>
            </a-timeline>
          </div>
        </template>
      </a-spin>

      <template #footer v-if="detail && detail.storyline.status === 'active'">
        <a-button type="primary" @click="handleResolve(detail!.storyline as any)">标记已处理</a-button>
      </template>
    </DetailDrawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ReloadOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import StatCard from '@/components/StatCard.vue'
import DetailDrawer from '@/components/DetailDrawer.vue'
import { storylineApi } from '@/api/storyline'
import type { Storyline, StorylineDetail, StorylineStats } from '@/api/storyline'
import { getSeverityConfig } from '@/constants/severity'

const loading = ref(false)
const detailLoading = ref(false)
const detailVisible = ref(false)
const storylines = ref<Storyline[]>([])
const detail = ref<StorylineDetail | null>(null)
const stats = reactive<StorylineStats>({ total: 0, active: 0, critical_active: 0 })

const filters = reactive({
  host_id: '',
  severity: undefined as string | undefined,
  status: undefined as string | undefined,
})

const pagination = reactive({
  current: 1, pageSize: 20, total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  { title: '最后活动', dataIndex: 'last_seen_at', width: 170 },
  { title: '主机', dataIndex: 'hostname', width: 120, ellipsis: true },
  { title: '严重度', key: 'severity', width: 80, align: 'center' as const },
  { title: '风险分', key: 'risk_score', width: 120 },
  { title: '阶段', key: 'phase', width: 110 },
  { title: '事件数', dataIndex: 'event_count', width: 80, align: 'center' as const },
  { title: '告警数', dataIndex: 'alert_count', width: 80, align: 'center' as const },
  { title: '摘要', dataIndex: 'summary', ellipsis: true },
  { title: '状态', key: 'status', width: 80, align: 'center' as const },
  { title: '操作', key: 'action', width: 100 },
]

const getPhaseLabel = (phase: string) => {
  const labels: Record<string, string> = {
    initial_access: '初始访问', execution: '执行', persistence: '持久化',
    privilege_escalation: '提权', defense_evasion: '防御规避', credential_access: '凭据访问',
    discovery: '发现', lateral_movement: '横向移动', collection: '数据收集',
    exfiltration: '数据窃取', command_and_control: 'C2 通信', impact: '影响',
  }
  return labels[phase] || phase || '-'
}

const getStatusColor = (status: string) => ({ active: 'orange', investigating: 'blue', resolved: 'green' }[status] || 'default')
const getStatusLabel = (status: string) => ({ active: '活跃', investigating: '调查中', resolved: '已处理' }[status] || status)
const getEventTypeColor = (type: string) => {
  const colors: Record<string, string> = {
    process_exec: 'blue', file_open: 'orange', file_write: 'orange',
    tcp_connect: 'cyan', udp_send: 'green', dns_query: 'purple',
  }
  return colors[type] || 'default'
}

const riskScoreColor = (score: number): string => {
  if (score >= 80) return '#EF4444'
  if (score >= 60) return '#F59E0B'
  return '#3B82F6'
}

const showDetail = async (record: Storyline) => {
  detailVisible.value = true
  detailLoading.value = true
  try { detail.value = await storylineApi.get(record.story_id) } catch { /* handled */ } finally { detailLoading.value = false }
}

const fetchStorylines = async () => {
  loading.value = true
  try {
    const res = await storylineApi.list({
      page: pagination.current, page_size: pagination.pageSize,
      host_id: filters.host_id || undefined, severity: filters.severity, status: filters.status,
    })
    storylines.value = res.items || []
    pagination.total = res.total
  } catch { /* handled */ } finally { loading.value = false }
}

const fetchStats = async () => {
  try { const res = await storylineApi.stats(); Object.assign(stats, res) } catch { /* silent */ }
}

const handleResolve = async (record: Storyline) => {
  try {
    await storylineApi.resolve(record.story_id)
    message.success('故事线已标记为已处理')
    detailVisible.value = false
    fetchStorylines(); fetchStats()
  } catch { /* handled */ }
}

const handleSearch = () => { pagination.current = 1; fetchStorylines() }
const handleRefresh = () => { fetchStorylines(); fetchStats() }
const handleTableChange = (pag: any) => { pagination.current = pag.current; pagination.pageSize = pag.pageSize; fetchStorylines() }

onMounted(() => { fetchStorylines(); fetchStats() })
</script>

<style scoped>
.storyline-page { padding: 0; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.page-header h2 { margin: 0; font-size: 20px; }
.section-row { margin-bottom: 16px; }

/* 故事线详情 Header */
.story-header {
  display: flex;
  gap: 20px;
  align-items: center;
  margin-bottom: 20px;
  padding: 20px;
  background: var(--mxsec-body-bg);
  border-radius: 10px;
}

.story-score-ring { position: relative; width: 70px; height: 70px; flex-shrink: 0; }
.score-text { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 20px; font-weight: 700; }

.story-meta { flex: 1; }
.story-id { margin: 0 0 8px; font-size: 16px; color: var(--mxsec-text-1); }
.story-tags { display: flex; gap: 6px; margin-bottom: 8px; }
.story-info { display: flex; gap: 16px; font-size: 12px; color: var(--mxsec-text-3); }

.story-summary { padding: 12px 16px; background: var(--mxsec-body-bg); border-radius: 8px; font-size: 13px; color: var(--mxsec-text-2); margin-bottom: 16px; line-height: 1.6; }
.story-rules { font-size: 13px; margin-bottom: 12px; }
.story-timerange { font-size: 13px; color: var(--mxsec-text-2); margin-bottom: 20px; }

.section-label { font-size: 13px; color: var(--mxsec-text-3); font-weight: 500; margin-right: 8px; display: block; margin-bottom: 8px; }
.rule-text { color: var(--mxsec-text-1); }

.timeline-section { margin-top: 4px; }

/* Timeline 暗色适配 */
.story-timeline { margin-top: 12px; }
.tl-event { margin-bottom: 4px; }
.tl-header { display: flex; align-items: center; gap: 6px; margin-bottom: 4px; }
.tl-time { color: var(--mxsec-text-3); font-size: 12px; }
.tl-body code { font-size: 12px; color: var(--mxsec-text-1); background: var(--mxsec-body-bg); padding: 2px 6px; border-radius: 4px; }
.tl-pid { color: var(--mxsec-text-3); font-size: 12px; }
</style>
