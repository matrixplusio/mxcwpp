<template>
  <div class="asset-relations-panel">
    <div class="toolbar">
      <div class="toolbar-left">
        <a-input-search
          v-model:value="keyword"
          allow-clear
          :placeholder="searchPlaceholder"
          style="max-width: 360px"
          @search="loadRelations"
        />
        <div v-if="enableQuickFilters" class="quick-filters">
          <a-checkable-tag :checked="onlyHighRisk" @change="handleHighRiskToggle">
            高风险优先
          </a-checkable-tag>
          <a-checkable-tag :checked="onlyWithVulns" @change="handleWithVulnsToggle">
            仅看有漏洞
          </a-checkable-tag>
          <a-checkable-tag :checked="onlyExposed" @change="handleExposedToggle">
            仅看暴露端口
          </a-checkable-tag>
          <a-checkable-tag :checked="onlyChanged" @change="handleChangedToggle">
            仅看最近变更
          </a-checkable-tag>
        </div>
      </div>
      <div class="toolbar-meta">
        <span>关系视图 {{ filteredRelationItems.length }} / {{ relations?.total ?? 0 }}</span>
        <span>高风险 {{ riskyRelationCount }}</span>
        <span>漏洞 {{ vulnerableRelationCount }}</span>
        <span>暴露端口 {{ exposedRelationCount }}</span>
        <span v-if="relations?.scope === 'global'">全局范围</span>
        <span v-else>当前主机</span>
      </div>
    </div>

    <a-spin :spinning="loading">
      <div v-if="filteredRelationItems.length > 0" class="relation-list">
        <div
          v-for="item in filteredRelationItems"
          :key="`${item.host.host_id}-${item.process.pid}`"
          class="relation-card"
        >
          <div class="summary-main">
            <div class="summary-head">
              <div class="summary-title-row">
                <div class="process-title">
                  {{ processTitle(item) }}
                  <span class="process-pid">PID {{ item.process.pid }}</span>
                </div>

                <div class="header-tags">
                  <a-tag :color="confidenceColor(item.confidence.level)">
                    {{ confidenceLabel(item.confidence.level) }}
                  </a-tag>
                  <a-tag color="blue">{{ item.relation_score }} 关联</a-tag>
                </div>
              </div>

              <div v-if="showHostSummary" class="host-summary">
                <span class="host-name">{{ item.host.hostname || shorten(item.host.host_id, 12) }}</span>
                <span class="host-meta">{{ item.host.ipv4?.[0] || shorten(item.host.host_id, 12) }}</span>
                <span v-if="item.host.business_line" class="host-meta">{{ item.host.business_line }}</span>
              </div>

              <div class="process-meta">
                <span>用户 {{ item.process.username || '-' }}</span>
                <span v-if="item.process.collected_at">采集 {{ item.process.collected_at }}</span>
                <span v-if="item.container">容器 {{ item.container.container_name || item.container.container_id }}</span>
                <span v-if="item.risks.last_changed_at">最近变更 {{ item.risks.last_changed_at }}</span>
              </div>
            </div>

            <div class="summary-body">
              <div class="process-cmdline">{{ item.process.cmdline || item.process.exe || '-' }}</div>

              <div class="summary-counters">
                <div class="summary-counter">
                  <span class="counter-label">端口</span>
                  <span class="counter-value">{{ item.ports?.length ?? 0 }}</span>
                </div>
                <div class="summary-counter">
                  <span class="counter-label">应用</span>
                  <span class="counter-value">{{ item.apps?.length ?? 0 }}</span>
                </div>
                <div class="summary-counter">
                  <span class="counter-label">软件包</span>
                  <span class="counter-value">{{ item.software?.length ?? 0 }}</span>
                </div>
                <div class="summary-counter">
                  <span class="counter-label">服务</span>
                  <span class="counter-value">{{ item.services?.length ?? 0 }}</span>
                </div>
                <div class="summary-counter">
                  <span class="counter-label">漏洞</span>
                  <span class="counter-value danger">{{ item.vulnerabilities?.length ?? 0 }}</span>
                </div>
                <div class="summary-counter">
                  <span class="counter-label">变更</span>
                  <span class="counter-value warn">{{ item.recent_changes?.length ?? 0 }}</span>
                </div>
              </div>
            </div>
          </div>

          <div class="risk-strip compact">
            <div class="risk-chip">
              <span class="chip-label">暴露端口</span>
              <span class="chip-value">{{ item.risks.exposed_port_count }}</span>
            </div>
            <div class="risk-chip">
              <span class="chip-label">漏洞命中</span>
              <span class="chip-value danger">{{ item.risks.vulnerability_count }}</span>
            </div>
            <div class="risk-chip">
              <span class="chip-label">FIM 变更</span>
              <span class="chip-value warn">{{ item.risks.fim_change_count }}</span>
            </div>
          </div>

          <div class="summary-footer">
            <div class="tag-row">
              <a-tag v-for="reason in previewMatchedBy(item)" :key="reason">
                {{ reason }}
              </a-tag>
              <a-tag v-if="(item.confidence.matched_by?.length ?? 0) > 3" color="default">
                +{{ (item.confidence.matched_by?.length ?? 0) - 3 }}
              </a-tag>
            </div>
            <div class="card-actions">
              <a-button size="small" @click="openRelation(item)">查看详情</a-button>
              <a-button
                v-if="showDrilldown"
                type="link"
                size="small"
                @click="openHost(item.host.host_id)"
              >
                查看主机
              </a-button>
            </div>
          </div>
        </div>
      </div>

      <a-empty v-else :description="filteredEmptyDescription" />
    </a-spin>

    <a-drawer
      v-model:open="drawerOpen"
      :title="drawerTitle"
      width="760"
      placement="right"
      destroy-on-close
    >
      <template v-if="selectedRelation">
        <div class="drawer-summary">
          <div class="drawer-summary-title">{{ selectedRelation.process.cmdline || selectedRelation.process.exe || '-' }}</div>
          <div class="drawer-summary-meta">
            <span>主机 {{ selectedRelation.host.hostname || shorten(selectedRelation.host.host_id, 12) }}</span>
            <span>PID {{ selectedRelation.process.pid }}</span>
            <span>用户 {{ selectedRelation.process.username || '-' }}</span>
            <span v-if="selectedRelation.process.collected_at">采集 {{ selectedRelation.process.collected_at }}</span>
          </div>
          <div class="tag-row">
            <a-tag :color="confidenceColor(selectedRelation.confidence.level)">
              {{ confidenceLabel(selectedRelation.confidence.level) }}
            </a-tag>
            <a-tag color="blue">{{ selectedRelation.relation_score }} 关联</a-tag>
            <a-tag v-for="kind in selectedRelation.related_kinds || []" :key="kind">
              {{ kind }}
            </a-tag>
          </div>
        </div>

        <a-tabs>
          <a-tab-pane key="overview" tab="概览">
            <div class="detail-section">
              <div class="section-label">主机与进程</div>
              <div class="detail-grid">
                <div class="detail-item">
                  <span class="detail-label">主机</span>
                  <span class="detail-value">{{ selectedRelation.host.hostname || '-' }}</span>
                </div>
                <div class="detail-item">
                  <span class="detail-label">Host ID</span>
                  <span class="detail-value break-all">{{ selectedRelation.host.host_id }}</span>
                </div>
                <div class="detail-item">
                  <span class="detail-label">IP</span>
                  <span class="detail-value">{{ selectedRelation.host.ipv4?.join(', ') || '-' }}</span>
                </div>
                <div class="detail-item">
                  <span class="detail-label">业务线</span>
                  <span class="detail-value">{{ selectedRelation.host.business_line || '-' }}</span>
                </div>
                <div class="detail-item">
                  <span class="detail-label">进程</span>
                  <span class="detail-value">{{ selectedRelation.process.exe || '-' }}</span>
                </div>
                <div class="detail-item">
                  <span class="detail-label">PID / PPID</span>
                  <span class="detail-value">{{ selectedRelation.process.pid }} / {{ selectedRelation.process.ppid || '-' }}</span>
                </div>
              </div>
            </div>

            <div v-if="selectedRelation.confidence.matched_by?.length" class="detail-section">
              <div class="section-label">关联依据</div>
              <div class="tag-row">
                <a-tag v-for="reason in selectedRelation.confidence.matched_by" :key="reason">
                  {{ reason }}
                </a-tag>
              </div>
            </div>

            <div v-if="selectedRelation.container" class="detail-section">
              <div class="section-label">运行容器</div>
              <div class="container-card">
                <div class="container-name">
                  {{ selectedRelation.container.container_name || selectedRelation.container.container_id }}
                </div>
                <div class="container-meta">
                  <span>{{ selectedRelation.container.image || '-' }}</span>
                  <span>{{ selectedRelation.container.runtime || '-' }}</span>
                  <span>{{ selectedRelation.container.status || '-' }}</span>
                </div>
              </div>
            </div>
          </a-tab-pane>

          <a-tab-pane key="runtime" tab="运行资产">
            <div v-if="selectedRelation.ports?.length" class="detail-section">
              <div class="section-label">开放端口</div>
              <div class="tag-row">
                <a-tag
                  v-for="port in selectedRelation.ports"
                  :key="`${port.protocol}-${port.port}-${port.state}`"
                  color="geekblue"
                >
                  {{ port.protocol }}/{{ port.port }} · {{ port.state || 'unknown' }}
                </a-tag>
              </div>
            </div>

            <div v-if="selectedRelation.apps?.length" class="detail-section">
              <div class="section-label">检测应用</div>
              <div class="tag-row">
                <a-tag
                  v-for="app in selectedRelation.apps"
                  :key="`${app.app_type}-${app.app_name}-${app.port}`"
                  color="cyan"
                >
                  {{ app.app_name || app.app_type }}<template v-if="app.version"> · {{ app.version }}</template><template v-if="app.port"> · :{{ app.port }}</template>
                </a-tag>
              </div>
            </div>

            <div v-if="selectedRelation.software?.length" class="detail-section">
              <div class="section-header">
                <div class="section-label">相关软件包</div>
                <a-button
                  v-if="selectedRelation.software[0]"
                  type="link"
                  size="small"
                  @click="openVulnerabilityDrilldown(selectedRelation.host.host_id, selectedRelation.software[0].name)"
                >
                  查看相关漏洞
                </a-button>
              </div>
              <div class="tag-row">
                <a-tag
                  v-for="pkg in selectedRelation.software"
                  :key="`${pkg.name}-${pkg.version}`"
                  color="green"
                  class="clickable-tag"
                  @click="openVulnerabilityDrilldown(selectedRelation.host.host_id, pkg.name)"
                >
                  {{ pkg.name }}<template v-if="pkg.version"> · {{ pkg.version }}</template><template v-if="pkg.package_type"> · {{ pkg.package_type }}</template>
                </a-tag>
              </div>
            </div>

            <div v-if="selectedRelation.services?.length" class="detail-section">
              <div class="section-label">相关服务</div>
              <div class="tag-row">
                <a-tag
                  v-for="service in selectedRelation.services"
                  :key="service.service_name"
                  color="orange"
                >
                  {{ service.service_name }} · {{ service.status || 'unknown' }}
                </a-tag>
              </div>
            </div>
          </a-tab-pane>

          <a-tab-pane key="risk" tab="风险与变更">
            <div class="risk-strip">
              <div class="risk-chip">
                <span class="chip-label">暴露端口</span>
                <span class="chip-value">{{ selectedRelation.risks.exposed_port_count }}</span>
              </div>
              <div class="risk-chip">
                <span class="chip-label">漏洞命中</span>
                <span class="chip-value danger">{{ selectedRelation.risks.vulnerability_count }}</span>
              </div>
              <div class="risk-chip">
                <span class="chip-label">FIM 变更</span>
                <span class="chip-value warn">{{ selectedRelation.risks.fim_change_count }}</span>
              </div>
            </div>

            <div v-if="selectedRelation.vulnerabilities?.length" class="detail-section">
              <div class="section-label">相关漏洞</div>
              <div class="tag-row">
                <a-tag
                  v-for="vuln in selectedRelation.vulnerabilities"
                  :key="`${vuln.cve_id}-${vuln.component}`"
                  :color="vulnerabilityColor(vuln.severity)"
                  class="clickable-tag"
                  @click="openVulnerabilityDrilldown(selectedRelation.host.host_id, vuln.component, vuln.cve_id)"
                >
                  {{ vuln.cve_id }} · {{ vuln.component }}
                </a-tag>
              </div>
            </div>

            <div v-if="selectedRelation.recent_changes?.length" class="detail-section">
              <div class="section-label">最近变更</div>
              <div class="change-list">
                <div
                  v-for="change in selectedRelation.recent_changes"
                  :key="change.event_id"
                  class="change-item"
                >
                  <div class="change-path">{{ change.file_path }}</div>
                  <div class="change-meta">
                    <span>{{ change.change_type }}</span>
                    <span>{{ change.severity }}</span>
                    <span>{{ change.detected_at }}</span>
                  </div>
                </div>
              </div>
            </div>
          </a-tab-pane>
        </a-tabs>
      </template>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { assetsApi } from '@/api/assets'
import type { AssetRelationItem, AssetRelationsResult } from '@/api/types'

const props = withDefaults(defineProps<{
  hostId?: string
  businessLine?: string
  defaultOnlyHighRisk?: boolean
  showQuickFilters?: boolean
}>(), {
  hostId: undefined,
  businessLine: undefined,
  defaultOnlyHighRisk: false,
  showQuickFilters: true,
})

const router = useRouter()
const loading = ref(false)
const keyword = ref('')
const relations = ref<AssetRelationsResult>()
const drawerOpen = ref(false)
const selectedRelation = ref<AssetRelationItem>()
const onlyHighRisk = ref(props.defaultOnlyHighRisk)
const onlyWithVulns = ref(false)
const onlyExposed = ref(false)
const onlyChanged = ref(false)

const relationItems = computed(() => relations.value?.items ?? [])
const filteredRelationItems = computed(() => {
  const items = relationItems.value.filter((item) => {
    if (onlyWithVulns.value && (item.risks.vulnerability_count ?? 0) <= 0) return false
    if (onlyExposed.value && (item.risks.exposed_port_count ?? 0) <= 0) return false
    if (onlyChanged.value && (item.risks.fim_change_count ?? 0) <= 0) return false
    if (onlyHighRisk.value && !isHighRisk(item)) return false
    return true
  })

  return items.slice().sort((left, right) => {
    const riskDiff = riskScore(right) - riskScore(left)
    if (riskDiff !== 0) return riskDiff
    return right.relation_score - left.relation_score
  })
})
const showHostSummary = computed(() => !props.hostId)
const showDrilldown = computed(() => !props.hostId)
const enableQuickFilters = computed(() => props.showQuickFilters)
const riskyRelationCount = computed(() => relationItems.value.filter((item) => isHighRisk(item)).length)
const vulnerableRelationCount = computed(() => relationItems.value.filter((item) => (item.risks.vulnerability_count ?? 0) > 0).length)
const exposedRelationCount = computed(() => relationItems.value.filter((item) => (item.risks.exposed_port_count ?? 0) > 0).length)
const drawerTitle = computed(() => (
  selectedRelation.value
    ? `${processTitle(selectedRelation.value)} · 资产关系详情`
    : '资产关系详情'
))
const searchPlaceholder = computed(() => (
  props.hostId
    ? '搜索进程、端口、应用、服务、软件包、漏洞、变更'
    : '全局搜索主机、进程、端口、应用、服务、漏洞、变更'
))
const emptyDescription = computed(() => (
  props.hostId
    ? '当前主机暂无可展示的资产关系'
    : '当前范围暂无可展示的资产关系'
))
const filteredEmptyDescription = computed(() => (
  relationItems.value.length > 0
    ? '当前筛选条件下暂无匹配的资产关系'
    : emptyDescription.value
))

const confidenceLabel = (level: string) => {
  if (level === 'exact') return '精确关联'
  if (level === 'mixed') return '混合关联'
  return '启发式关联'
}

const confidenceColor = (level: string) => {
  if (level === 'exact') return 'green'
  if (level === 'mixed') return 'blue'
  return 'orange'
}

const vulnerabilityColor = (severity: string) => {
  const normalized = severity?.toLowerCase()
  if (normalized === 'critical') return 'red'
  if (normalized === 'high') return 'volcano'
  if (normalized === 'medium') return 'orange'
  return 'gold'
}

const processTitle = (item: AssetRelationItem) => {
  if (item.apps?.[0]?.app_name) return item.apps[0].app_name
  if (item.apps?.[0]?.app_type) return item.apps[0].app_type
  const exe = item.process.exe || ''
  const parts = exe.split('/')
  return parts[parts.length - 1] || exe || 'unknown'
}

const riskScore = (item: AssetRelationItem) => (
  (item.risks.vulnerability_count ?? 0) * 100 +
  (item.risks.exposed_port_count ?? 0) * 10 +
  (item.risks.fim_change_count ?? 0) * 5 +
  (item.relation_score ?? 0)
)

const isHighRisk = (item: AssetRelationItem) => (
  (item.risks.vulnerability_count ?? 0) > 0 ||
  (item.risks.exposed_port_count ?? 0) > 0 ||
  (item.risks.fim_change_count ?? 0) > 0
)

const previewMatchedBy = (item: AssetRelationItem) => (item.confidence.matched_by ?? []).slice(0, 3)

const shorten = (value?: string, max = 12) => {
  if (!value) return '-'
  if (value.length <= max) return value
  return `${value.slice(0, max)}...`
}

const openHost = (hostId: string) => {
  router.push({ path: `/hosts/${hostId}`, query: { tab: 'fingerprint' } })
}

const openRelation = (item: AssetRelationItem) => {
  selectedRelation.value = item
  drawerOpen.value = true
}

const openVulnerabilityDrilldown = (hostId?: string, component?: string, search?: string) => {
  router.push({
    path: '/vulnerabilities',
    query: {
      host_id: hostId || undefined,
      component: component || undefined,
      search: search || undefined,
    },
  })
}

const handleHighRiskToggle = (checked: boolean) => {
  onlyHighRisk.value = checked
}

const handleWithVulnsToggle = (checked: boolean) => {
  onlyWithVulns.value = checked
}

const handleExposedToggle = (checked: boolean) => {
  onlyExposed.value = checked
}

const handleChangedToggle = (checked: boolean) => {
  onlyChanged.value = checked
}

const loadRelations = async () => {
  loading.value = true
  try {
    relations.value = await assetsApi.getRelations({
      host_id: props.hostId || undefined,
      business_line: props.businessLine || undefined,
      keyword: keyword.value || undefined,
      limit: props.hostId ? 20 : 30,
      all: !props.hostId && !props.businessLine,
    })
  } catch {
    relations.value = undefined
  } finally {
    loading.value = false
  }
}

watch(
  () => [props.hostId, props.businessLine],
  () => {
    loadRelations()
  }
)

onMounted(() => {
  loadRelations()
})
</script>

<style scoped>
.asset-relations-panel {
  width: 100%;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}

.toolbar-left {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}

.quick-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.toolbar-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  font-size: 12px;
  color: #4E5969;
}

.relation-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.relation-card {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 16px;
  border: 1px solid #E5E8EF;
  border-radius: 10px;
  background: linear-gradient(180deg, #FFFFFF 0%, #FAFBFD 100%);
}

.summary-main {
  min-width: 0;
  flex: 1;
}

.summary-head {
  min-width: 0;
}

.summary-title-row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.header-tags {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
}

.host-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 8px;
}

.host-name {
  font-size: 13px;
  font-weight: 700;
  color: #1D2129;
}

.host-meta {
  font-size: 12px;
  color: #4E5969;
}

.process-title {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 8px;
  font-size: 16px;
  font-weight: 700;
  color: #1D2129;
}

.process-pid {
  font-size: 12px;
  font-weight: 600;
  color: #4E5969;
}

.process-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 6px;
  font-size: 12px;
  color: #86909C;
}

.process-cmdline {
  margin-top: 10px;
  padding: 8px 10px;
  background: #F7F8FA;
  border-radius: 8px;
  font-size: 12px;
  line-height: 1.5;
  color: #4E5969;
  word-break: break-all;
}

.summary-body {
  display: grid;
  grid-template-columns: minmax(0, 1.6fr) minmax(320px, 1fr);
  gap: 14px;
  margin-top: 10px;
}

.summary-counters {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
}

.summary-counter {
  padding: 8px 10px;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  background: #FFFFFF;
}

.counter-label {
  display: block;
  font-size: 12px;
  color: #86909C;
}

.counter-value {
  display: block;
  margin-top: 4px;
  font-size: 18px;
  font-weight: 700;
  color: #1D2129;
}

.counter-value.danger {
  color: #C73636;
}

.counter-value.warn {
  color: #D46B08;
}

.risk-strip {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin-top: 12px;
}

.risk-strip.compact {
  width: 276px;
  min-width: 276px;
  margin-top: 0;
  grid-template-columns: 1fr;
}

.risk-chip {
  padding: 10px 12px;
  border-radius: 8px;
  background: #F7FAFF;
  border: 1px solid #E5E8EF;
}

.chip-label {
  display: block;
  font-size: 12px;
  color: #86909C;
}

.chip-value {
  display: block;
  margin-top: 4px;
  font-size: 20px;
  font-weight: 700;
  color: #1D2129;
}

.chip-value.danger {
  color: #C73636;
}

.chip-value.warn {
  color: #D46B08;
}

.summary-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 12px;
}

.section-label {
  margin-bottom: 8px;
  font-size: 12px;
  font-weight: 600;
  color: #4E5969;
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 8px;
}

.card-actions {
  display: flex;
  align-items: center;
  gap: 4px;
}

.tag-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.clickable-tag {
  cursor: pointer;
}

.detail-section {
  margin-bottom: 20px;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.detail-item {
  padding: 12px;
  border-radius: 8px;
  background: #F7F8FA;
}

.detail-label {
  display: block;
  font-size: 12px;
  color: #86909C;
}

.detail-value {
  display: block;
  margin-top: 6px;
  font-size: 13px;
  color: #1D2129;
}

.break-all {
  word-break: break-all;
}

.change-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.change-item {
  padding: 10px 12px;
  border-radius: 8px;
  background: #FFF7E8;
  border: 1px solid #FFE7BA;
}

.change-path {
  font-size: 12px;
  line-height: 1.5;
  color: #1D2129;
  word-break: break-all;
}

.change-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 6px;
  font-size: 12px;
  color: #8C6B1F;
}

.container-section {
  margin-top: 16px;
}

.container-card {
  padding: 12px;
  border-radius: 8px;
  background: #F5F9FF;
  border: 1px solid #DCE8FF;
}

.container-name {
  font-size: 13px;
  font-weight: 700;
  color: #1D2129;
}

.container-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 6px;
  font-size: 12px;
  color: #4E5969;
}

.drawer-summary {
  margin-bottom: 16px;
  padding: 14px;
  border-radius: 10px;
  background: linear-gradient(135deg, #FBFCFF 0%, #F5F9FF 100%);
  border: 1px solid #DCE8FF;
}

.drawer-summary-title {
  font-size: 13px;
  line-height: 1.6;
  color: #1D2129;
  word-break: break-all;
}

.drawer-summary-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin: 10px 0 12px;
  font-size: 12px;
  color: #4E5969;
}

@media (max-width: 1280px) {
  .relation-card {
    flex-direction: column;
  }

  .risk-strip.compact {
    width: 100%;
    min-width: 0;
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 960px) {
  .summary-body {
    grid-template-columns: 1fr;
  }

  .detail-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 640px) {
  .toolbar {
    flex-direction: column;
    align-items: stretch;
  }

  .summary-title-row,
  .summary-footer {
    flex-direction: column;
    align-items: flex-start;
  }

  .summary-counters,
  .risk-strip.compact,
  .risk-strip {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
