<template>
  <div class="asset-fingerprint">
    <a-alert
      v-if="collectionStatus?.message"
      :type="collectionStatus.level === 'error' ? 'error' : 'warning'"
      show-icon
      style="margin-bottom: 16px"
      :message="collectionStatus.message"
      :description="collectionStatusDescription"
    />

    <a-card title="资产指纹" :bordered="false" style="margin-bottom: 16px">
      <a-row :gutter="[16, 16]">
        <a-col v-for="item in fingerprintItems" :key="item.key" :xs="12" :md="8" :xl="6">
          <a-card
            :bordered="false"
            class="fingerprint-card"
            :class="{ active: activeTab === item.key }"
            hoverable
            @click="handleItemClick(item.key)"
          >
            <div class="fingerprint-value">{{ item.value }}</div>
            <div class="fingerprint-label">{{ item.label }}</div>
          </a-card>
        </a-col>
      </a-row>
    </a-card>

    <a-tabs v-model:activeKey="activeTab" @change="handleTabChange">
      <a-tab-pane
        v-for="item in fingerprintItems"
        :key="item.key"
        :tab="`${item.label}(${item.value})`"
      >
        <AssetRecordsTable
          v-if="activeTab === item.key"
          :asset-type="item.key"
          :selected-host-id="hostId"
        />
      </a-tab-pane>
    </a-tabs>

    <a-card title="资产洞察" :bordered="false" style="margin-top: 16px">
      <div class="insight-card-hint">默认收起，并放到主资产表后面，避免把主机资产详情挤到太下面</div>
      <a-collapse
        v-model:activeKey="activeInsightPanels"
        accordion
        ghost
        class="insight-collapse"
      >
        <a-collapse-panel key="risk" header="风险收敛">
          <AssetRelationsPanel :host-id="hostId" :default-only-high-risk="true" />
        </a-collapse-panel>
        <a-collapse-panel key="relations" header="资产关系">
          <AssetRelationsPanel :host-id="hostId" />
        </a-collapse-panel>
        <a-collapse-panel key="history" header="资产历史">
          <AssetHistoryPanel :host-id="hostId" title="主机资产历史" />
        </a-collapse-panel>
      </a-collapse>
    </a-card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { assetsApi } from '@/api/assets'
import { message } from 'ant-design-vue'
import type { AssetCollectionStatus } from '@/api/types'
import AssetRecordsTable from '@/components/assets/AssetRecordsTable.vue'
import AssetRelationsPanel from '@/components/assets/AssetRelationsPanel.vue'
import AssetHistoryPanel from '@/components/assets/AssetHistoryPanel.vue'

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

const props = defineProps<{
  hostId: string
}>()

const route = useRoute()
const router = useRouter()

const collectionStatus = ref<AssetCollectionStatus>()
const activeInsightPanels = ref<string[]>([])
const validSubTabs: AssetTabKey[] = [
  'processes',
  'ports',
  'users',
  'packages',
  'containers',
  'apps',
  'network-interfaces',
  'volumes',
  'kmods',
  'services',
  'crontabs',
]

const activeTab = ref<AssetTabKey>(
  validSubTabs.includes(route.query.subtab as AssetTabKey)
    ? (route.query.subtab as AssetTabKey)
    : 'processes'
)

const fingerprintItems = ref<Array<{ key: AssetTabKey; label: string; value: number }>>([
  { key: 'processes', label: '运行进程', value: 0 },
  { key: 'ports', label: '开放端口', value: 0 },
  { key: 'users', label: '系统用户', value: 0 },
  { key: 'packages', label: '系统软件', value: 0 },
  { key: 'containers', label: '容器', value: 0 },
  { key: 'apps', label: '应用', value: 0 },
  { key: 'network-interfaces', label: '网卡', value: 0 },
  { key: 'volumes', label: '磁盘卷', value: 0 },
  { key: 'kmods', label: '内核模块', value: 0 },
  { key: 'services', label: '系统服务', value: 0 },
  { key: 'crontabs', label: '定时任务', value: 0 },
])

const loadStatistics = async () => {
  if (!props.hostId) return

  try {
    const stats = await assetsApi.getStatistics(props.hostId)
    fingerprintItems.value.forEach((item) => {
      if (item.key === 'processes') item.value = stats.processes ?? 0
      else if (item.key === 'ports') item.value = stats.ports ?? 0
      else if (item.key === 'users') item.value = stats.users ?? 0
      else if (item.key === 'packages') item.value = stats.software ?? 0
      else if (item.key === 'containers') item.value = stats.containers ?? 0
      else if (item.key === 'apps') item.value = stats.apps ?? 0
      else if (item.key === 'network-interfaces') item.value = stats.network_interfaces ?? 0
      else if (item.key === 'volumes') item.value = stats.volumes ?? 0
      else if (item.key === 'kmods') item.value = stats.kmods ?? 0
      else if (item.key === 'services') item.value = stats.services ?? 0
      else if (item.key === 'crontabs') item.value = stats.crons ?? 0
    })
  } catch (error) {
    console.error('加载资产统计失败:', error)
    message.error('加载资产统计失败')
  }
}

const loadCollectionStatus = async () => {
  if (!props.hostId) return

  try {
    collectionStatus.value = await assetsApi.getCollectionStatus(props.hostId)
  } catch (error) {
    console.error('加载资产采集状态失败:', error)
  }
}

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

const handleItemClick = (key: AssetTabKey) => {
  activeTab.value = key
  router.replace({ query: { ...route.query, subtab: key } })
}

const handleTabChange = (key: string) => {
  activeTab.value = key as AssetTabKey
  router.replace({ query: { ...route.query, subtab: key } })
}

watch(
  () => route.query.subtab,
  (newTab) => {
    if (newTab && validSubTabs.includes(newTab as AssetTabKey)) {
      activeTab.value = newTab as AssetTabKey
    }
  }
)

onMounted(() => {
  loadStatistics()
  loadCollectionStatus()
})

watch(
  () => props.hostId,
  () => {
    loadStatistics()
    loadCollectionStatus()
  }
)
</script>

<style scoped>
.asset-fingerprint {
  width: 100%;
}

.fingerprint-card {
  text-align: center;
  cursor: pointer;
  border-radius: 8px;
}

.fingerprint-card.active {
  background: var(--mxsec-primary-bg);
}

.fingerprint-value {
  font-size: 24px;
  font-weight: 700;
  margin-bottom: 8px;
}

.fingerprint-label {
  color: var(--mxsec-text-3);
}

.insight-card-hint {
  margin-bottom: 8px;
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.insight-collapse :deep(.ant-collapse-header) {
  font-weight: 600;
  color: var(--mxsec-text-1);
}
</style>
