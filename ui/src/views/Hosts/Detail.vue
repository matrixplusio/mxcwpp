<template>
  <div class="host-detail-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <a-button type="text" @click="handleBack" style="padding: 0; margin-right: 8px">
        <ArrowLeftOutlined />
      </a-button>
      <div class="header-content">
        <h2 style="margin: 0">{{ host?.hostname || '主机详情' }}</h2>
      </div>
    </div>

    <!-- 全页加载状态 -->
    <div v-if="loading" class="page-loading">
      <a-spin size="large" tip="正在加载主机信息..." />
    </div>

    <!-- 加载失败状态 -->
    <div v-else-if="loadError" class="page-empty">
      <a-result
        status="error"
        title="加载失败"
        :sub-title="loadError"
      >
        <template #extra>
          <a-button type="primary" @click="loadHostDetail">重新加载</a-button>
          <a-button @click="handleBack">返回列表</a-button>
        </template>
      </a-result>
    </div>

    <!-- 数据为空状态 -->
    <div v-else-if="!host" class="page-empty">
      <a-result
        status="warning"
        title="未找到主机信息"
        sub-title="该主机可能已被删除或尚未上报数据"
      >
        <template #extra>
          <a-button type="primary" @click="handleBack">返回列表</a-button>
        </template>
      </a-result>
    </div>

    <!-- 正常内容 -->
    <a-tabs v-else v-model:activeKey="activeTab" @change="handleTabChange">
      <a-tab-pane key="overview" tab="主机概览">
        <HostOverview :host="host" :loading="false" :score-data="scoreData" @update:host="host = $event" @view-detail="handleViewDetail" />
      </a-tab-pane>
      <a-tab-pane key="alerts" :tab="`安全告警(${alertCount})`">
        <SecurityAlerts :host-id="hostId" />
      </a-tab-pane>
      <a-tab-pane key="vulnerabilities" :tab="`漏洞风险(${vulnerabilityCount})`">
        <VulnerabilityRisk :host-id="hostId" />
      </a-tab-pane>
      <a-tab-pane key="baseline" :tab="`基线风险(${baselineCount})`">
        <BaselineRisk :host-id="hostId" />
      </a-tab-pane>
      <a-tab-pane key="edr" :tab="`EDR 告警(${edrAlertCount})`">
        <EDRAlerts :host-id="hostId" />
      </a-tab-pane>
      <a-tab-pane key="antivirus" :tab="`病毒查杀(${antivirusCount})`">
        <AntivirusScan :host-id="hostId" />
      </a-tab-pane>
      <a-tab-pane key="performance" tab="性能监控">
        <PerformanceMonitor :host-id="hostId" />
      </a-tab-pane>
      <a-tab-pane key="fingerprint" tab="资产指纹">
        <AssetFingerprint :host-id="hostId" />
      </a-tab-pane>
    </a-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ArrowLeftOutlined } from '@ant-design/icons-vue'
import { hostsApi } from '@/api/hosts'
import { alertsApi } from '@/api/alerts'
import { antivirusApi } from '@/api/antivirus'
import type { HostDetail, BaselineScore } from '@/api/types'
import HostOverview from './components/HostOverview.vue'
import SecurityAlerts from './components/SecurityAlerts.vue'
import VulnerabilityRisk from './components/VulnerabilityRisk.vue'
import BaselineRisk from './components/BaselineRisk.vue'
import EDRAlerts from './components/EDRAlerts.vue'
import AntivirusScan from './components/AntivirusScan.vue'
import PerformanceMonitor from './components/PerformanceMonitor.vue'
import AssetFingerprint from './components/AssetFingerprint.vue'

const router = useRouter()
const route = useRoute()

const loading = ref(false)
const loadError = ref('')
const host = ref<HostDetail | null>(null)
const scoreData = ref<BaselineScore | null>(null)
const validTabs = ['overview', 'alerts', 'vulnerabilities', 'baseline', 'edr', 'antivirus', 'performance', 'fingerprint']
const activeTab = ref((route.query.tab as string) && validTabs.includes(route.query.tab as string) ? (route.query.tab as string) : 'overview')
const hostId = ref('')

const alertCount = ref(0)
const vulnerabilityCount = ref(0)
const baselineCount = ref(0)
const edrAlertCount = ref(0)
const antivirusCount = ref(0)

const loadHostDetail = async () => {
  const id = route.params.hostId as string
  if (!id) return

  hostId.value = id
  loading.value = true
  loadError.value = ''
  try {
    const [hostData, scoreResult, riskStats, edrRes, antivirusRes] = await Promise.all([
      hostsApi.get(id),
      hostsApi.getScore(id).catch(() => null),
      hostsApi.getRiskStatistics(id).catch(() => null),
      alertsApi.list({ host_id: id, alert_type: 'edr' as any, page: 1, page_size: 1 }).catch(() => null),
      antivirusApi.listResults({ host_id: id, page: 1, page_size: 1 }).catch(() => null),
    ])
    host.value = hostData
    scoreData.value = scoreResult

    // 计算基线风险数量
    if (scoreResult) {
      baselineCount.value = scoreResult.fail_count
    }

    if (riskStats) {
      alertCount.value = riskStats.alerts.total
      vulnerabilityCount.value = riskStats.vulnerabilities.total
      if (!scoreResult) {
        baselineCount.value = riskStats.baseline.total
      }
    }

    edrAlertCount.value = edrRes?.total ?? 0
    antivirusCount.value = antivirusRes?.total ?? 0
  } catch (error: any) {
    console.error('加载主机详情失败:', error)
    loadError.value = error?.response?.data?.message || error?.message || '网络请求失败，请检查网络连接'
  } finally {
    loading.value = false
  }
}

const handleBack = () => {
  // 使用 router.back() 以保留列表页的 URL 查询参数（筛选条件、分页）
  if (window.history.length > 1) {
    router.back()
  } else {
    router.push('/hosts')
  }
}

const handleTabChange = (key: string) => {
  router.replace({ query: { ...route.query, tab: key } })
}

const handleViewDetail = (tab: string) => {
  activeTab.value = tab
  router.replace({ query: { ...route.query, tab } })
}

// 监听 URL query 变化（如浏览器前进/后退）
watch(
  () => route.query.tab,
  (newTab) => {
    if (newTab && validTabs.includes(newTab as string)) {
      activeTab.value = newTab as string
    }
  }
)

onMounted(() => {
  loadHostDetail()
})
</script>

<style scoped lang="less">
.host-detail-page {
  width: 100%;
}

.page-header {
  display: flex;
  align-items: center;
  margin-bottom: 16px;
}

.header-content {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 16px;
}

.page-header h2 {
  font-size: 20px;
  font-weight: 600;
  margin: 0;
}

.page-loading {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 400px;
}

.page-empty {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 400px;
}

/* 优化 Tab 栏样式 */
:deep(.ant-tabs) {
  .ant-tabs-nav {
    margin-bottom: 16px;

    &::before {
      border-bottom: 1px solid #e8e8e8;
    }
  }

  .ant-tabs-tab {
    padding: 10px 16px;
    font-size: 14px;
    color: #595959;
    transition: all 0.3s ease;
    border-radius: 6px 6px 0 0;

    &:hover {
      color: #165DFF;
    }

    &.ant-tabs-tab-active {
      .ant-tabs-tab-btn {
        color: #165DFF;
        font-weight: 500;
      }
    }
  }

  .ant-tabs-ink-bar {
    background: linear-gradient(90deg, #165DFF, #0E42D2);
    height: 3px;
    border-radius: 3px 3px 0 0;
  }
}
</style>
