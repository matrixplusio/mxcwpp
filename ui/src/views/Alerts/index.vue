<template>
  <div class="alerts-page">
    <div class="page-header">
      <h2 class="page-title">告警管理</h2>
      <a-button type="primary" @click="showConfigModal = true">
        <template #icon><SettingOutlined /></template>
        告警配置
      </a-button>
    </div>
    
    <!-- 统计 -->
    <div class="stats">
      <div class="stat-card stat-active">
        <div class="stat-icon-bg">
          <BellOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value">{{ statistics.active || 0 }}</div>
          <div class="stat-label">活跃告警</div>
        </div>
      </div>
      <div class="stat-card stat-critical">
        <div class="stat-icon-bg">
          <CloseCircleOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value critical">{{ statistics.critical || 0 }}</div>
          <div class="stat-label">严重</div>
        </div>
      </div>
      <div class="stat-card stat-high">
        <div class="stat-icon-bg">
          <ExclamationCircleOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value high">{{ statistics.high || 0 }}</div>
          <div class="stat-label">高危</div>
        </div>
      </div>
      <div class="stat-card stat-medium">
        <div class="stat-icon-bg">
          <WarningOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value medium">{{ statistics.medium || 0 }}</div>
          <div class="stat-label">中危</div>
        </div>
      </div>
      <div class="stat-card stat-low">
        <div class="stat-icon-bg">
          <InfoCircleOutlined />
        </div>
        <div class="stat-info">
          <div class="stat-value low">{{ statistics.low || 0 }}</div>
          <div class="stat-label">低危</div>
        </div>
      </div>
    </div>

    <!-- 标签切换 -->
    <div class="tabs-header">
      <div
        :class="['tab-item', { active: activeTab === 'active' }]"
        @click="switchTab('active')"
      >
        活跃告警
      </div>
      <div
        :class="['tab-item', { active: activeTab === 'history' }]"
        @click="switchTab('history')"
      >
        历史告警
      </div>
    </div>

    <!-- 表格 -->
    <AlertTable
      v-if="activeTab === 'active'"
      :alerts="alerts"
      :loading="loading"
      :pagination="pagination"
      :filters="filters"
      status="active"
      @change="handleTableChange"
      @resolve="handleResolve"
      @ignore="handleIgnore"
      @refresh="loadAlerts"
    />
    <AlertTable
      v-else
      :alerts="alerts"
      :loading="loading"
      :pagination="pagination"
      :filters="filters"
      status="history"
      @change="handleTableChange"
      @refresh="loadAlerts"
    />

    <!-- 告警配置弹窗 -->
    <a-modal
      v-model:open="showConfigModal"
      title="告警配置"
      @ok="handleSaveConfig"
      :confirm-loading="savingConfig"
    >
      <a-form layout="vertical">
        <a-form-item label="重复告警通知间隔">
          <a-select v-model:value="alertConfig.repeat_alert_interval" style="width: 100%">
            <a-select-option :value="15">15 分钟</a-select-option>
            <a-select-option :value="30">30 分钟</a-select-option>
            <a-select-option :value="60">1 小时</a-select-option>
            <a-select-option :value="120">2 小时</a-select-option>
            <a-select-option :value="360">6 小时</a-select-option>
            <a-select-option :value="720">12 小时</a-select-option>
            <a-select-option :value="1440">24 小时</a-select-option>
          </a-select>
          <div class="config-tip">
            同一主机同一问题在此间隔内只会通知一次，避免重复告警轰炸
          </div>
        </a-form-item>
        <a-form-item label="定期汇总">
          <a-switch v-model:checked="alertConfig.enable_periodic_summary" />
          <span style="margin-left: 8px; color: #86909C;">
            {{ alertConfig.enable_periodic_summary ? '已启用：已存在的告警按间隔定期发送' : '已关闭：只在首次发现时发送通知' }}
          </span>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import {
  SettingOutlined,
  BellOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  WarningOutlined,
  InfoCircleOutlined,
} from '@ant-design/icons-vue'
import { alertsApi, type Alert, type AlertStatistics } from '@/api/alerts'
import { systemConfigApi, type AlertConfig } from '@/api/system-config'
import AlertTable from './components/AlertTable.vue'

const route = useRoute()
const router = useRouter()

const validTabs = ['active', 'history'] as const
const initTab = validTabs.includes(route.query.tab as any) ? (route.query.tab as 'active' | 'history') : 'active'
const activeTab = ref<'active' | 'history'>(initTab)
const loading = ref(false)
const alerts = ref<Alert[]>([])
const statistics = ref<AlertStatistics>({
  total: 0,
  active: 0,
  resolved: 0,
  ignored: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
})

// 告警配置
const showConfigModal = ref(false)
const savingConfig = ref(false)
const alertConfig = reactive<AlertConfig>({
  repeat_alert_interval: 30,
  enable_periodic_summary: true,
})

const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const filters = ref({
  severity: undefined as 'critical' | 'high' | 'medium' | 'low' | undefined,
  host_id: undefined as string | undefined,
  category: undefined as string | undefined,
  alert_type: undefined as 'baseline' | 'agent_offline' | undefined,
  keyword: undefined as string | undefined,
  runtime_type: undefined as string | undefined,
})


const loadStatistics = async () => {
  try {
    const data = await alertsApi.statistics()
    statistics.value = data
  } catch (error: any) {
    console.error('加载告警统计失败:', error)
  }
}

const loadAlerts = async () => {
  loading.value = true
  try {
    const params: any = {
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
    }

    // 根据标签页设置状态
    if (activeTab.value === 'active') {
      params.status = 'active'
    } else {
      // 历史告警：已解决或已忽略
      params.status = 'resolved,ignored'
    }

    // 添加其他过滤条件
    if (filters.value.severity) {
      params.severity = filters.value.severity
    }
    if (filters.value.host_id) {
      params.host_id = filters.value.host_id
    }
    if (filters.value.category) {
      params.category = filters.value.category
    }
    if (filters.value.alert_type) {
      params.alert_type = filters.value.alert_type
    }
    if (filters.value.keyword) {
      params.keyword = filters.value.keyword
    }
    if (filters.value.runtime_type) {
      params.runtime_type = filters.value.runtime_type
    }

    const response = await alertsApi.list(params)
    alerts.value = response.items || []
    pagination.value.total = response.total || 0
  } catch (error: any) {
    message.error(error?.message || '加载告警列表失败')
  } finally {
    loading.value = false
  }
}

const switchTab = (tab: 'active' | 'history') => {
  activeTab.value = tab
  router.replace({ query: { ...route.query, tab } })
  pagination.value.current = 1
  loadAlerts()
}

// 监听 URL query 变化（浏览器前进/后退）
watch(
  () => route.query.tab,
  (newTab) => {
    if (newTab && validTabs.includes(newTab as any) && newTab !== activeTab.value) {
      activeTab.value = newTab as 'active' | 'history'
      pagination.value.current = 1
      loadAlerts()
    }
  }
)

const handleTableChange = (newFilters: any) => {
  // 如果传入了 page 参数，使用传入的值（翻页操作）
  if (newFilters.page) {
    pagination.value.current = newFilters.page
  } else {
    // 否则重置为第 1 页（筛选条件变化）
    pagination.value.current = 1
  }
  // 如果传入了 pageSize 参数，更新每页条数
  if (newFilters.pageSize) {
    pagination.value.pageSize = newFilters.pageSize
  }
  // 更新其他过滤条件（排除 page 和 pageSize）
  const { page, pageSize, ...otherFilters } = newFilters
  filters.value = { ...filters.value, ...otherFilters }
  loadAlerts()
}

const handleResolve = async (alert: Alert, reason?: string) => {
  try {
    await alertsApi.resolve(alert.id, reason)
    message.success('告警已解决')
    loadAlerts()
    loadStatistics()
  } catch (error: any) {
    message.error(error?.message || '解决告警失败')
  }
}

const handleIgnore = async (alert: Alert) => {
  try {
    await alertsApi.ignore(alert.id)
    message.success('告警已忽略')
    loadAlerts()
    loadStatistics()
  } catch (error: any) {
    message.error(error?.message || '忽略告警失败')
  }
}

// 加载告警配置
const loadAlertConfig = async () => {
  try {
    const config = await systemConfigApi.getAlertConfig()
    alertConfig.repeat_alert_interval = config.repeat_alert_interval
    alertConfig.enable_periodic_summary = config.enable_periodic_summary
  } catch (error: any) {
    console.error('加载告警配置失败:', error)
  }
}

// 保存告警配置
const handleSaveConfig = async () => {
  savingConfig.value = true
  try {
    await systemConfigApi.updateAlertConfig(alertConfig)
    message.success('告警配置保存成功')
    showConfigModal.value = false
  } catch (error: any) {
    message.error(error?.message || '保存告警配置失败')
  } finally {
    savingConfig.value = false
  }
}

onMounted(() => {
  loadStatistics()
  loadAlerts()
  loadAlertConfig()
})
</script>

<style scoped lang="less">
.alerts-page {
  padding: 0;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.page-title {
  font-size: 20px;
  font-weight: 600;
  margin: 0;
  color: #262626;
}

.config-tip {
  margin-top: 8px;
  font-size: 13px;
  color: #86909C;
}

.stats {
  display: flex;
  gap: 16px;
  margin-bottom: 24px;
}

.stat-card {
  flex: 1;
  background: #fff;
  border: none;
  border-radius: 8px;
  padding: 20px;
  display: flex;
  align-items: center;
  gap: 16px;
  transition: all 0.3s ease;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
    0 2px 4px rgba(0, 0, 0, 0.04),
    0 4px 8px rgba(0, 0, 0, 0.04);

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08),
      0 8px 24px rgba(0, 0, 0, 0.06);
  }
}

.stat-icon-bg {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  flex-shrink: 0;
  color: #fff;
}

.stat-active .stat-icon-bg {
  background: linear-gradient(135deg, #165DFF, #0E42D2);
}

.stat-critical .stat-icon-bg {
  background: linear-gradient(135deg, #F53F3F, #CB2634);
}

.stat-high .stat-icon-bg {
  background: linear-gradient(135deg, #ff7a45, #d4380d);
}

.stat-medium .stat-icon-bg {
  background: linear-gradient(135deg, #FF7D00, #d48806);
}

.stat-low .stat-icon-bg {
  background: linear-gradient(135deg, #165DFF, #0E42D2);
}

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: #262626;
  margin-bottom: 4px;
  line-height: 1;

  &.critical {
    color: #F53F3F;
  }

  &.high {
    color: #ff7a45;
  }

  &.medium {
    color: #FF7D00;
  }

  &.low {
    color: #165DFF;
  }
}

.stat-label {
  font-size: 13px;
  color: #86909C;
  font-weight: 400;
}

.tabs-header {
  display: flex;
  gap: 0;
  margin-bottom: 24px;
  background: #fff;
  border: none;
  border-radius: 8px;
  padding: 4px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
    0 2px 4px rgba(0, 0, 0, 0.04);
}

.tab-item {
  flex: 1;
  padding: 10px 20px;
  text-align: center;
  cursor: pointer;
  border-radius: 6px;
  font-size: 14px;
  color: #595959;
  transition: all 0.3s ease;
  font-weight: 400;

  &:hover {
    color: #165DFF;
    background: #f5f7fa;
  }

  &.active {
    background: linear-gradient(135deg, #165DFF 0%, #0E42D2 100%);
    color: #fff;
    font-weight: 500;
    box-shadow: 0 2px 8px rgba(22, 93, 255, 0.3);

    &:hover {
      background: linear-gradient(135deg, #4080FF 0%, #165DFF 100%);
      color: #fff;
    }
  }
}
</style>
