<template>
  <div class="asset-fingerprint-page">
    <div class="page-header">
      <h2>资产指纹</h2>
      <span class="page-header-hint">全局资产指纹采集汇总，跨主机维度查看</span>
    </div>

    <a-row :gutter="[16, 16]" class="section-row">
      <a-col v-for="item in tabStats" :key="item.key" :xs="12" :md="8" :xl="6" :xxl="4">
        <div
          class="fp-stat-card"
          :class="{ active: activeTab === item.key }"
          @click="activeTab = item.key"
        >
          <div class="fp-stat-icon">
            <component :is="item.icon" />
          </div>
          <div class="fp-stat-value">{{ item.count }}</div>
          <div class="fp-stat-label">{{ item.label }}</div>
        </div>
      </a-col>
    </a-row>

    <div class="dashboard-card">
      <div class="card-body">
        <a-alert
          v-if="collectionStatus?.message"
          :type="collectionStatus.level === 'error' ? 'error' : 'warning'"
          show-icon
          style="margin-bottom: 16px"
          :message="collectionStatus.message"
          :description="collectionStatusDescription"
        />

        <div v-if="overview" class="overview-panel">
          <div class="overview-header">
            <div>
              <div class="overview-title">采集覆盖总览</div>
              <div class="overview-subtitle">
                {{ overview.scope === 'host' ? '当前主机资产覆盖情况' : '全局主机资产覆盖情况' }}
              </div>
            </div>
            <div class="overview-meta">
              <span>覆盖率 {{ formatRate(overview.coverage_rate) }}</span>
              <span v-if="overview.last_collected_at">最近采集 {{ overview.last_collected_at }}</span>
            </div>
          </div>

          <a-row :gutter="[12, 12]">
            <a-col v-for="item in overviewCards" :key="item.key" :xs="12" :md="8" :xl="4">
              <div class="overview-card">
                <div class="overview-card-label">{{ item.label }}</div>
                <div class="overview-card-value">{{ item.value }}</div>
                <div v-if="item.hint" class="overview-card-hint">{{ item.hint }}</div>
              </div>
            </a-col>
          </a-row>
        </div>

        <AssetRecordsTable
          v-model:selectedHostId="filterHost"
          v-model:selectedBusinessLine="filterBusinessLine"
          :asset-type="activeTab"
          :allow-host-filter="true"
          :allow-business-line-filter="true"
          :host-options="hostOptions"
          :business-line-options="businessLineOptions"
          :host-map="hostMap"
        />

        <div class="insight-panel">
          <div class="insight-header">
            <div class="insight-title">资产洞察</div>
            <div class="insight-subtitle">默认收起，并放到主资产表后面，避免影响主操作区</div>
          </div>

          <a-collapse
            v-model:activeKey="activeInsightPanels"
            accordion
            ghost
            class="insight-collapse"
          >
            <a-collapse-panel key="portrait" header="资产画像">
              <div class="topn-content">
                <a-tag v-for="item in topItems" :key="`${item.name}-${item.value}`" color="blue">
                  {{ item.name }} · {{ item.value }}
                </a-tag>
                <span v-if="topItems.length === 0" class="topn-empty">当前筛选条件下暂无聚合数据</span>
              </div>
            </a-collapse-panel>

            <a-collapse-panel key="history" header="资产历史">
              <AssetHistoryPanel
                :host-id="filterHost"
                :business-line="filterBusinessLine"
                title="资产历史"
              />
            </a-collapse-panel>

            <a-collapse-panel key="risk" header="风险收敛">
              <div class="relations-subtitle">聚焦有漏洞、暴露端口或最近 FIM 变更的高风险资产对象</div>
              <AssetRelationsPanel
                :host-id="filterHost"
                :business-line="filterBusinessLine"
                :default-only-high-risk="true"
              />
            </a-collapse-panel>

            <a-collapse-panel key="relations" header="资产关系">
              <div class="relations-subtitle">跨主机检索进程、端口、应用、软件包、漏洞与 FIM 变更关联</div>
              <AssetRelationsPanel
                :host-id="filterHost"
                :business-line="filterBusinessLine"
              />
            </a-collapse-panel>
          </a-collapse>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import {
  ApiOutlined,
  AppstoreOutlined,
  CloudOutlined,
  CloudServerOutlined,
  CodeOutlined,
  DatabaseOutlined,
  DeploymentUnitOutlined,
  HddOutlined,
  NodeIndexOutlined,
  PartitionOutlined,
  UserOutlined,
} from '@ant-design/icons-vue'
import { assetsApi } from '@/api/assets'
import { businessLinesApi, type BusinessLine } from '@/api/business-lines'
import { hostsApi } from '@/api/hosts'
import type { AssetCollectionStatus, AssetOverview, AssetTopItem } from '@/api/types'
import AssetHistoryPanel from '@/components/assets/AssetHistoryPanel.vue'
import AssetRecordsTable from '@/components/assets/AssetRecordsTable.vue'
import AssetRelationsPanel from '@/components/assets/AssetRelationsPanel.vue'

type AssetTabKey =
  | 'ports'
  | 'processes'
  | 'users'
  | 'packages'
  | 'containers'
  | 'apps'
  | 'network-interfaces'
  | 'volumes'
  | 'kmods'
  | 'services'
  | 'crontabs'

interface HostOption {
  value: string
  label: string
}

interface HostMapItem {
  hostname?: string
  ipv4?: string[]
  business_line?: string
}

interface BusinessLineOption {
  value: string
  label: string
}

interface AssetTabStat {
  key: AssetTabKey
  label: string
  count: number
  icon: any
}

const activeTab = ref<AssetTabKey>('ports')
const filterHost = ref<string>()
const filterBusinessLine = ref<string>()
const collectionStatus = ref<AssetCollectionStatus>()
const overview = ref<AssetOverview>()
const activeInsightPanels = ref<string[]>([])
const hostOptions = ref<HostOption[]>([])
const businessLineOptions = ref<BusinessLineOption[]>([])
const hostMap = ref<Record<string, HostMapItem>>({})
const topItems = ref<AssetTopItem[]>([])

const tabStats = ref<AssetTabStat[]>([
  { key: 'ports', label: '开放端口', count: 0, icon: ApiOutlined },
  { key: 'processes', label: '运行进程', count: 0, icon: CodeOutlined },
  { key: 'users', label: '系统用户', count: 0, icon: UserOutlined },
  { key: 'packages', label: '软件包', count: 0, icon: AppstoreOutlined },
  { key: 'containers', label: '容器', count: 0, icon: CloudOutlined },
  { key: 'apps', label: '应用', count: 0, icon: DatabaseOutlined },
  { key: 'network-interfaces', label: '网卡', count: 0, icon: NodeIndexOutlined },
  { key: 'volumes', label: '磁盘卷', count: 0, icon: HddOutlined },
  { key: 'kmods', label: '内核模块', count: 0, icon: PartitionOutlined },
  { key: 'services', label: '系统服务', count: 0, icon: CloudServerOutlined },
  { key: 'crontabs', label: '定时任务', count: 0, icon: DeploymentUnitOutlined },
])

const collectionStatusDescription = computed(() => {
  if (!collectionStatus.value) return undefined

  const parts: string[] = []
  if (collectionStatus.value.collector.version) {
    parts.push(`collector 版本: ${collectionStatus.value.collector.version}`)
  }
  if (collectionStatus.value.last_collected_at) {
    parts.push(`最近采集时间: ${collectionStatus.value.last_collected_at}`)
  }
  return parts.length > 0 ? parts.join(' | ') : undefined
})

const overviewCards = computed(() => {
  if (!overview.value) return []

  return [
    {
      key: 'total',
      label: '纳管主机',
      value: overview.value.total_hosts,
      hint: overview.value.scope === 'host' ? '当前筛选主机' : '当前筛选范围内主机总数',
    },
    {
      key: 'covered',
      label: '已采集主机',
      value: overview.value.covered_hosts,
      hint: '至少存在一类资产指纹',
    },
    {
      key: 'uncovered',
      label: '待补采主机',
      value: overview.value.uncovered_hosts,
      hint: '当前还没有任何资产数据',
    },
    {
      key: 'online',
      label: '在线主机',
      value: overview.value.online_hosts,
      hint: '最近心跳在线',
    },
    {
      key: 'offline',
      label: '离线主机',
      value: overview.value.offline_hosts,
      hint: '当前不可达或无心跳',
    },
    {
      key: 'business-line',
      label: '业务线',
      value: overview.value.business_line_count,
      hint: '当前范围覆盖的业务线数量',
    },
  ]
})

const formatRate = (value?: number) => `${(value ?? 0).toFixed(1)}%`

const loadOverview = async () => {
  try {
    overview.value = await assetsApi.getOverview(filterHost.value, filterBusinessLine.value)
  } catch {
    overview.value = undefined
  }
}

const loadStats = async () => {
  try {
    const stats = await assetsApi.getStatistics(filterHost.value, filterBusinessLine.value)
    for (const tab of tabStats.value) {
      if (tab.key === 'ports') tab.count = stats.ports ?? 0
      else if (tab.key === 'processes') tab.count = stats.processes ?? 0
      else if (tab.key === 'users') tab.count = stats.users ?? 0
      else if (tab.key === 'packages') tab.count = stats.software ?? 0
      else if (tab.key === 'containers') tab.count = stats.containers ?? 0
      else if (tab.key === 'apps') tab.count = stats.apps ?? 0
      else if (tab.key === 'network-interfaces') tab.count = stats.network_interfaces ?? 0
      else if (tab.key === 'volumes') tab.count = stats.volumes ?? 0
      else if (tab.key === 'kmods') tab.count = stats.kmods ?? 0
      else if (tab.key === 'services') tab.count = stats.services ?? 0
      else if (tab.key === 'crontabs') tab.count = stats.crons ?? 0
    }
  } catch {
    // ignore
  }
}

const loadCollectionStatus = async () => {
  try {
    collectionStatus.value = await assetsApi.getCollectionStatus(filterHost.value, filterBusinessLine.value)
  } catch {
    collectionStatus.value = undefined
  }
}

const loadTopN = async () => {
  try {
    const res = await assetsApi.getTopN({
      type: activeTab.value,
      host_id: filterHost.value,
      business_line: filterBusinessLine.value,
      limit: 5,
    })
    topItems.value = res.items ?? []
  } catch {
    topItems.value = []
  }
}

const loadHosts = async () => {
  try {
    const params: Record<string, unknown> = { page_size: 1000 }
    if (filterBusinessLine.value) params.business_line = filterBusinessLine.value
    const res = await hostsApi.list(params)
    hostOptions.value = (res.items ?? []).map((host) => ({
      value: host.host_id,
      label: host.hostname ? `${host.hostname} (${host.ipv4?.[0] || host.host_id.slice(0, 12)})` : (host.ipv4?.[0] || host.host_id),
    }))

    hostMap.value = Object.fromEntries((res.items ?? []).map((host) => [
      host.host_id,
      {
        hostname: host.hostname,
        ipv4: host.ipv4,
        business_line: host.business_line,
      },
    ]))
  } catch {
    hostOptions.value = []
    hostMap.value = {}
  }
}

const loadBusinessLines = async () => {
  try {
    const res = await businessLinesApi.list({ enabled: 'true', page_size: 1000 })
    businessLineOptions.value = (res.items ?? []).map((item: BusinessLine) => ({
      value: item.code,
      label: item.name,
    }))
  } catch {
    businessLineOptions.value = []
  }
}

watch(filterHost, () => {
  loadOverview()
  loadStats()
  loadCollectionStatus()
  loadTopN()
})

watch(filterBusinessLine, () => {
  filterHost.value = undefined
  loadHosts()
  loadOverview()
  loadStats()
  loadCollectionStatus()
  loadTopN()
})

watch(activeTab, () => {
  loadTopN()
})

onMounted(() => {
  loadBusinessLines()
  loadHosts()
  loadOverview()
  loadStats()
  loadCollectionStatus()
  loadTopN()
})
</script>

<style scoped>
.asset-fingerprint-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.fp-stat-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  height: 100%;
}

.fp-stat-card:hover { border-color: var(--mxsec-primary); }

.fp-stat-card.active {
  border-color: var(--mxsec-primary);
  background: var(--mxsec-primary-bg);
}

.fp-stat-icon { font-size: 20px; color: var(--mxsec-primary); margin-bottom: 8px; }
.fp-stat-value { font-size: 22px; font-weight: 700; color: var(--mxsec-text-1); line-height: 1.2; }
.fp-stat-label { font-size: 12px; color: var(--mxsec-text-3); margin-top: 4px; }

.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
}

.card-body { padding: 20px; }

.overview-panel {
  margin-bottom: 16px;
  padding: 16px;
  background: var(--mxsec-fill-1);
  border: 1px solid var(--mxsec-border);
  border-radius: 10px;
}

.overview-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
}

.overview-title {
  font-size: 14px;
  font-weight: 700;
  color: var(--mxsec-text-1);
}

.overview-subtitle {
  margin-top: 4px;
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.overview-meta {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 12px;
  font-size: 12px;
  color: var(--mxsec-text-2);
}

.overview-card {
  min-height: 96px;
  padding: 14px;
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
}

.overview-card-label {
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.overview-card-value {
  margin-top: 8px;
  font-size: 28px;
  line-height: 1.1;
  font-weight: 700;
  color: var(--mxsec-text-1);
}

.overview-card-hint {
  margin-top: 8px;
  font-size: 12px;
  color: var(--mxsec-text-2);
}

.insight-panel {
  margin-bottom: 16px;
  padding: 16px;
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 10px;
}

.insight-header {
  margin-bottom: 8px;
}

.insight-title {
  font-size: 14px;
  font-weight: 700;
  color: var(--mxsec-text-1);
}

.insight-subtitle {
  margin-top: 4px;
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.topn-empty {
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.insight-collapse :deep(.ant-collapse-header) {
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.topn-content {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.relations-subtitle {
  margin-bottom: 14px;
  font-size: 12px;
  color: var(--mxsec-text-3);
}
</style>
