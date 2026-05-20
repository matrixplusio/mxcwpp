<template>
  <div class="hosts-page">
    <!-- 主机状态分布和风险分布 -->
    <a-row :gutter="16" style="margin-bottom: 16px" class="distribution-row">
      <!-- 主机状态分布 -->
      <a-col :span="12" class="distribution-col">
        <a-card title="主机状态分布" :bordered="false" class="distribution-card">
          <div class="status-distribution-container">
            <div class="chart-container" @click="handleStatusChartClick">
              <v-chart
                class="status-chart"
                :option="statusChartOption"
                autoresize
              />
              <div class="chart-hint">点击图表查看详情</div>
            </div>
            <div class="legend-container">
              <div class="status-legend">
                <div class="legend-item">
                  <span class="legend-color" style="background: #00B42A"></span>
                  <span>运行中</span>
                  <span class="legend-value">{{ statusDistribution.running }}</span>
                </div>
                <div class="legend-item">
                  <span class="legend-color" style="background: #FF7D00"></span>
                  <span>运行异常</span>
                  <span class="legend-value">{{ statusDistribution.abnormal }}</span>
                </div>
                <div class="legend-item">
                  <span class="legend-color" style="background: #F53F3F"></span>
                  <span>离线</span>
                  <span class="legend-value">{{ statusDistribution.offline }}</span>
                </div>
                <div class="legend-item">
                  <span class="legend-color" style="background: #165DFF"></span>
                  <span>未安装</span>
                  <span class="legend-value">{{ statusDistribution.not_installed }}</span>
                </div>
                <div class="legend-item">
                  <span class="legend-color" style="background: #86909C"></span>
                  <span>已卸载</span>
                  <span class="legend-value">{{ statusDistribution.uninstalled }}</span>
                </div>
              </div>
            </div>
          </div>
        </a-card>
      </a-col>

      <!-- 主机基线风险分布 -->
      <a-col :span="12" class="distribution-col">
        <a-card title="主机基线风险分布" :bordered="false" class="distribution-card">
          <div class="risk-distribution-container">
            <div class="risk-card">
              <div class="risk-icon" style="border-color: #CB2634">
                <ExclamationCircleOutlined style="color: #CB2634" />
              </div>
              <div class="risk-content">
                <div class="risk-label">严重</div>
                <div class="risk-value" style="color: #CB2634">{{ riskDistribution.critical }}</div>
              </div>
            </div>
            <div class="risk-card">
              <div class="risk-icon" style="border-color: #F53F3F">
                <ExclamationCircleOutlined style="color: #F53F3F" />
              </div>
              <div class="risk-content">
                <div class="risk-label">高危</div>
                <div class="risk-value" style="color: #F53F3F">{{ riskDistribution.high }}</div>
              </div>
            </div>
            <div class="risk-card">
              <div class="risk-icon" style="border-color: #FF7D00">
                <ExclamationCircleOutlined style="color: #FF7D00" />
              </div>
              <div class="risk-content">
                <div class="risk-label">中危</div>
                <div class="risk-value" style="color: #FF7D00">{{ riskDistribution.medium }}</div>
              </div>
            </div>
            <div class="risk-card">
              <div class="risk-icon" style="border-color: #165DFF">
                <ExclamationCircleOutlined style="color: #165DFF" />
              </div>
              <div class="risk-content">
                <div class="risk-label">低危</div>
                <div class="risk-value" style="color: #165DFF">{{ riskDistribution.low }}</div>
              </div>
            </div>
          </div>
        </a-card>
      </a-col>
    </a-row>

    <!-- 主机内容 -->
    <a-card title="主机内容" :bordered="false">
      <!-- 操作按钮和筛选 -->
      <div class="action-bar">
        <div class="action-left">
          <a-space>
            <a-tooltip title="功能开发中，敬请期待">
              <a-button disabled>Agent离线通知</a-button>
            </a-tooltip>
            <a-button @click="handleBatchExportHosts">批量导出主机</a-button>
            <a-button @click="handleBatchAddTags">批量添加标签</a-button>
            <a-tooltip title="功能开发中，敬请期待">
              <a-button disabled>批量下发任务</a-button>
            </a-tooltip>
            <a-dropdown>
              <a-button>
                更多
                <DownOutlined />
              </a-button>
              <template #overlay>
                <a-menu>
                  <a-menu-item @click="handleBatchRestartAgent">重启 Agent</a-menu-item>
                  <a-menu-item @click="handleBatchBindBusinessLine">批量绑定业务线</a-menu-item>
                  <a-menu-item disabled>
                    <a-tooltip title="功能开发中，敬请期待" placement="left">
                      <span>批量导入标签</span>
                    </a-tooltip>
                  </a-menu-item>
                  <a-menu-item @click="handleBatchDeleteHost" danger>批量删除主机</a-menu-item>
                </a-menu>
              </template>
            </a-dropdown>
          </a-space>
        </div>
        <div class="action-right">
          <a-space>
            <span style="color: #4E5969">主机范围:</span>
            <a-select
              v-model:value="filters.hostRange"
              placeholder="全部"
              style="width: 120px"
            >
              <a-select-option value="all">全部</a-select-option>
              <a-select-option value="online">在线</a-select-option>
              <a-select-option value="offline">离线</a-select-option>
            </a-select>
            <a-button @click="loadHosts">
              <template #icon>
                <ReloadOutlined />
              </template>
            </a-button>
          </a-space>
        </div>
      </div>

      <!-- 搜索区域 -->
      <div class="filter-bar">
        <a-select
          v-model:value="filters.business_line"
          placeholder="业务线"
          style="width: 150px"
          allow-clear
          show-search
          :filter-option="filterBusinessLineOption"
        >
          <a-select-option value="__unbound__">
            <span style="color: #86909C;">无业务线</span>
          </a-select-option>
          <a-select-option v-for="bl in businessLines" :key="bl.code" :value="bl.code">
            {{ bl.name }}
          </a-select-option>
        </a-select>
        <a-select
          v-model:value="filters.os_family"
          placeholder="操作系统"
          style="width: 150px"
          allow-clear
        >
          <a-select-option
            v-for="os in osOptions"
            :key="os.value"
            :value="os.value"
          >
            {{ os.label }}
          </a-select-option>
        </a-select>
        <a-select
          v-model:value="filters.status"
          placeholder="状态"
          style="width: 120px"
          allow-clear
        >
          <a-select-option value="online">在线</a-select-option>
          <a-select-option value="offline">离线</a-select-option>
        </a-select>
        <a-select
          v-model:value="filters.runtime_type"
          placeholder="运行环境"
          style="width: 120px"
          allow-clear
        >
          <a-select-option value="vm">虚拟机/物理机</a-select-option>
          <a-select-option value="docker">Docker 容器</a-select-option>
          <a-select-option value="k8s">K8s Pod</a-select-option>
        </a-select>
        <a-input
          v-model:value="filters.search"
          placeholder="搜索主机名、ID 或 IP 地址"
          style="width: 300px"
          allow-clear
          @press-enter="handleSearch"
        >
          <template #prefix>
            <SearchOutlined />
          </template>
        </a-input>
        <a-button type="primary" @click="handleSearch">
          <template #icon>
            <SearchOutlined />
          </template>
          搜索
        </a-button>
      </div>

    <!-- 主机列表表格 -->
    <a-table
      :columns="columns"
      :data-source="hosts"
      :loading="loading"
      :pagination="pagination"
      :row-selection="rowSelection"
      @change="handleTableChange"
      row-key="host_id"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'hostname'">
          <div style="display: flex; align-items: center; gap: 8px;">
            <router-link :to="`/hosts/${record.host_id}`" class="host-link">
              {{ record.hostname }}
            </router-link>
            <a-tag v-if="record.runtime_type === 'docker'" color="blue" style="margin: 0;">
              Docker
            </a-tag>
            <a-tag v-else-if="record.runtime_type === 'k8s'" color="purple" style="margin: 0;">
              K8s
            </a-tag>
          </div>
        </template>
        <template v-else-if="column.key === 'tags'">
          <a-space>
            <a-tag v-for="tag in record.tags" :key="tag">{{ tag }}</a-tag>
            <span v-if="!record.tags || record.tags.length === 0" style="color: #86909C">-</span>
          </a-space>
        </template>
        <template v-else-if="column.key === 'risk'">
          <ScoreDisplay :host-id="record.host_id" />
        </template>
        <template v-else-if="column.key === 'status'">
          <a-tag :color="record.status === 'online' ? 'green' : 'red'">
            {{ record.status === 'online' ? '在线' : '离线' }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'resource_usage'">
          <div>
            <div>CPU: {{ record.cpu_usage || 0 }}%</div>
            <div>内存: {{ record.memory_usage || 0 }}%</div>
          </div>
        </template>
        <template v-else-if="column.key === 'action'">
          <div class="action-cell">
            <a-button type="link" size="small" class="action-link" @click="$router.push(`/hosts/${record.host_id}`)">详情</a-button>
            <a-divider type="vertical" />
            <a-popconfirm
              title="确定重启此主机的 Agent？"
              ok-text="确定"
              cancel-text="取消"
              @confirm="handleRestartSingleAgent(record)"
            >
              <a-button type="link" size="small" class="action-link" :disabled="record.status !== 'online'">重启</a-button>
            </a-popconfirm>
            <a-divider type="vertical" />
            <template v-if="record.status === 'online'">
              <a-tooltip title="在线主机不允许删除，请先确认主机已离线">
                <a-button type="link" size="small" class="action-link action-link-danger" disabled>删除</a-button>
              </a-tooltip>
            </template>
            <template v-else>
              <a-popconfirm
                title="确定要删除这台主机吗？"
                description="删除后将同时删除该主机的所有扫描结果、告警和相关数据，此操作不可恢复。"
                ok-text="确定"
                cancel-text="取消"
                @confirm="handleDeleteHost(record)"
              >
                <a-button type="link" size="small" class="action-link action-link-danger">删除</a-button>
              </a-popconfirm>
            </template>
          </div>
        </template>
      </template>
      <template #emptyText>
        <a-empty description="暂无数据" />
      </template>
    </a-table>
    </a-card>

    <!-- 批量绑定业务线对话框 -->
    <a-modal
      v-model:open="batchBindBusinessLineModalVisible"
      title="批量绑定业务线"
      :width="500"
      @ok="handleConfirmBatchBindBusinessLine"
      @cancel="handleCancelBatchBindBusinessLine"
    >
      <div style="margin-bottom: 16px;">
        <div style="margin-bottom: 8px; color: #4E5969;">
          已选择 <strong>{{ batchBindHostIds.length }}</strong> 台主机
        </div>
      </div>
      <div style="margin-bottom: 16px;">
        <div style="margin-bottom: 8px; font-weight: 500;">选择业务线</div>
        <a-select
          v-model:value="batchBindBusinessLine"
          placeholder="请选择业务线"
          style="width: 100%"
          show-search
          allow-clear
          :filter-option="filterBusinessLineOption"
        >
          <a-select-option v-for="bl in businessLines" :key="bl.code" :value="bl.code">
            {{ bl.name }}
          </a-select-option>
        </a-select>
        <div style="margin-top: 8px; color: #86909C; font-size: 12px;">
          提示：选择业务线后，所选主机将绑定到该业务线。留空表示取消业务线绑定。
        </div>
      </div>
    </a-modal>

    <!-- 批量添加标签对话框 -->
    <a-modal
      v-model:open="batchTagsModalVisible"
      title="批量更新标签"
      :width="500"
      @ok="handleConfirmBatchTags"
      @cancel="batchTagsModalVisible = false"
    >
      <div style="margin-bottom: 16px;">
        <div style="margin-bottom: 8px; color: #4E5969;">
          已选择 <strong>{{ selectedRowKeys.length }}</strong> 台主机
        </div>
      </div>
      <div style="margin-bottom: 16px;">
        <div style="margin-bottom: 8px; font-weight: 500;">更新模式</div>
        <a-radio-group v-model:value="batchTagsMode">
          <a-radio value="append">追加标签（保留原有标签）</a-radio>
          <a-radio value="replace">替换标签（覆盖原有标签）</a-radio>
        </a-radio-group>
      </div>
      <div style="margin-bottom: 16px;">
        <div style="margin-bottom: 8px; font-weight: 500;">输入标签</div>
        <a-select
          v-model:value="batchTagsValue"
          mode="tags"
          placeholder="输入标签后按回车添加"
          style="width: 100%"
          :token-separators="[',']"
        />
        <div style="margin-top: 8px; color: #86909C; font-size: 12px;">
          每个标签最长 50 个字符，每台主机最多 10 个标签。
        </div>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import {
  ReloadOutlined,
  SearchOutlined,
  DownOutlined,
  ExclamationCircleOutlined,
} from '@ant-design/icons-vue'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart } from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
} from 'echarts/components'
import VChart from 'vue-echarts'
import { hostsApi, type HostStatusDistribution, type HostRiskDistribution } from '@/api/hosts'
import { businessLinesApi, type BusinessLine } from '@/api/business-lines'
import type { Host } from '@/api/types'
import ScoreDisplay from './components/ScoreDisplay.vue'
import { message, Modal } from 'ant-design-vue'
import { formatDateTime } from '@/utils/date'
import { OS_OPTIONS } from '@/constants/os'

// 注册 ECharts 组件
use([CanvasRenderer, PieChart, TitleComponent, TooltipComponent, LegendComponent])

const router = useRouter()
const route = useRoute()
const osOptions = OS_OPTIONS

const loading = ref(false)
const hosts = ref<Host[]>([])
const selectedRowKeys = ref<string[]>([])
const businessLines = ref<BusinessLine[]>([])

// 批量绑定业务线
const batchBindBusinessLineModalVisible = ref(false)
const batchBindBusinessLine = ref<string>('')
const batchBindHostIds = ref<string[]>([]) // 打开模态框时快照选中的主机 ID

// 批量添加标签
const batchTagsModalVisible = ref(false)
const batchTagsMode = ref<'append' | 'replace'>('append')
const batchTagsValue = ref<string[]>([])
const statusDistribution = ref<HostStatusDistribution>({
  running: 0,
  abnormal: 0,
  offline: 0,
  not_installed: 0,
  uninstalled: 0,
})
const riskDistribution = ref<HostRiskDistribution>({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
})

const filters = reactive({
  hostRange: 'all' as string,
  search: '' as string,
  business_line: undefined as string | undefined,
  os_family: undefined as string | undefined,
  status: undefined as string | undefined,
  runtime_type: undefined as string | undefined, // 运行环境类型筛选：vm/docker/k8s
})


// 主机状态分布饼图配置
const statusChartOption = computed(() => {
  const data = [
    {
      value: statusDistribution.value.running,
      name: '运行中',
      itemStyle: { color: '#00B42A' },
    },
    {
      value: statusDistribution.value.abnormal,
      name: '运行异常',
      itemStyle: { color: '#FF7D00' },
    },
    {
      value: statusDistribution.value.offline,
      name: '离线',
      itemStyle: { color: '#F53F3F' },
    },
    {
      value: statusDistribution.value.not_installed,
      name: '未安装',
      itemStyle: { color: '#165DFF' },
    },
    {
      value: statusDistribution.value.uninstalled,
      name: '已卸载',
      itemStyle: { color: '#86909C' },
    },
  ]

  // 如果所有值都是0，显示一个占位饼图（显示所有分类，但值为0）
  const hasData = data.some((item) => item.value > 0)

  return {
    tooltip: {
      trigger: 'item',
      formatter: (params: any) => {
        if (!hasData) {
          return `${params.name}: 0`
        }
        return `${params.name}: ${params.value} (${params.percent}%)`
      },
    },
    series: [
      {
        name: '主机状态',
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '50%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 4,
          borderColor: '#fff',
          borderWidth: 2,
        },
        label: {
          show: hasData,
          formatter: '{b}: {c}',
          fontSize: 12,
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 14,
            fontWeight: 'bold',
          },
        },
        labelLine: {
          show: hasData,
        },
        // 即使没有数据也显示所有分类的饼图
        data: hasData
          ? data.filter((item) => item.value > 0)
          : data.map((item) => ({
              ...item,
              value: 1, // 每个分类占相等比例（20%）
              itemStyle: { ...item.itemStyle, opacity: 0.5 }, // 降低透明度表示无数据
            })),
        animation: true,
        animationType: 'scale',
        animationEasing: 'elasticOut',
      },
    ],
  }
})

const rowSelection = computed(() => ({
  selectedRowKeys: selectedRowKeys.value,
  onChange: (keys: string[]) => {
    selectedRowKeys.value = keys
  },
}))

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  {
    title: '主机名称',
    key: 'hostname',
    width: 200,
  },
  {
    title: '标签',
    key: 'tags',
    width: 150,
  },
  {
    title: '业务线',
    dataIndex: 'business_line',
    key: 'business_line',
    width: 120,
    customRender: ({ record }: { record: Host }) => {
      if (!record.business_line) return '-'
      const bl = businessLines.value.find(b => b.code === record.business_line)
      return bl ? bl.name : record.business_line
    },
  },
  {
    title: '操作系统',
    key: 'os',
    width: 180,
    customRender: ({ record }: { record: Host }) => {
      return `${record.os_family} ${record.os_version}`
    },
  },
  {
    title: '风险',
    key: 'risk',
    width: 150,
  },
  {
    title: '状态',
    key: 'status',
    width: 100,
  },
  {
    title: '客户端资源使用',
    key: 'resource_usage',
    width: 150,
  },
  {
    title: '更新时间',
    dataIndex: 'last_heartbeat',
    key: 'last_heartbeat',
    width: 180,
    customRender: ({ record }: { record: Host }) => {
      return formatDateTime(record.last_heartbeat)
    },
  },
  {
    title: '操作',
    key: 'action',
    width: 160,
    fixed: 'right' as const,
  },
]

// 同步筛选条件到 URL 查询参数
const syncFiltersToURL = () => {
  const query: Record<string, string> = {}
  if (pagination.current !== 1) query.page = String(pagination.current)
  if (pagination.pageSize !== 20) query.page_size = String(pagination.pageSize)
  if (filters.search) query.search = filters.search
  if (filters.business_line) query.business_line = filters.business_line
  if (filters.os_family) query.os_family = filters.os_family
  if (filters.status) query.status = filters.status
  if (filters.runtime_type) query.runtime_type = filters.runtime_type
  router.replace({ query })
}

const loadHosts = async () => {
  loading.value = true
  syncFiltersToURL()
  try {
    const params: any = {
      page: pagination.current,
      page_size: pagination.pageSize,
    }
    if (filters.os_family) {
      params.os_family = filters.os_family
    }
    if (filters.status) {
      params.status = filters.status
    }
    if (filters.business_line) {
      params.business_line = filters.business_line
    }
    if (filters.search && filters.search.trim()) {
      params.search = filters.search.trim()
    }
    if (filters.runtime_type) {
      params.runtime_type = filters.runtime_type
    }
    const response = await hostsApi.list(params)
    hosts.value = response.items
    pagination.total = response.total
  } catch (error) {
    console.error('加载主机列表失败:', error)
    message.error('加载主机列表失败')
  } finally {
    loading.value = false
  }
}

// 加载业务线列表
const loadBusinessLines = async () => {
  try {
    const response = await businessLinesApi.list({ enabled: 'true', page_size: 1000 })
    businessLines.value = response.items
  } catch (error) {
    console.error('加载业务线列表失败:', error)
  }
}

// 业务线筛选选项过滤
const filterBusinessLineOption = (input: string, option: any) => {
  return option.children[0].children.toLowerCase().indexOf(input.toLowerCase()) >= 0
}

const loadStatusDistribution = async () => {
  try {
    const data = await hostsApi.getStatusDistribution()
    statusDistribution.value = data
  } catch (error) {
    console.error('加载主机状态分布失败:', error)
  }
}

const loadRiskDistribution = async () => {
  try {
    const data = await hostsApi.getRiskDistribution()
    riskDistribution.value = data
  } catch (error) {
    console.error('加载主机风险分布失败:', error)
  }
}

const handleStatusChartClick = () => {
  // TODO: 实现点击图表查看详情的功能
  message.info('点击图表查看详情功能开发中')
}

const handleSearch = () => {
  pagination.current = 1
  loadHosts()
}


const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  loadHosts()
}

// 删除主机
const handleDeleteHost = async (record: Host) => {
  try {
    await hostsApi.delete(record.host_id)
    message.success(`主机 ${record.hostname} 删除成功`)

    // 刷新主机列表和统计
    loadHosts()
    loadStatusDistribution()
    loadRiskDistribution()
  } catch (error: any) {
    console.error('删除主机失败:', error)
    message.error(error?.message || '删除主机失败，请重试')
  }
}

// 重启单台主机 Agent
const handleRestartSingleAgent = async (record: Host) => {
  await doRestartAgent([record.host_id])
}

// 批量重启 Agent
const handleBatchRestartAgent = () => {
  if (selectedRowKeys.value.length === 0) {
    // 无选择 → 确认重启全部在线主机
    Modal.confirm({
      title: '重启全部在线 Agent',
      content: '确定要重启所有在线主机的 Agent 吗？Agent 会短暂离线后自动恢复。',
      okText: '确定重启',
      okType: 'danger',
      cancelText: '取消',
      onOk: () => doRestartAgent([]),
    })
  } else {
    // 有选择 → 确认重启选中的主机
    Modal.confirm({
      title: '重启选中主机的 Agent',
      content: `确定要重启选中的 ${selectedRowKeys.value.length} 台主机的 Agent 吗？`,
      okText: '确定重启',
      okType: 'danger',
      cancelText: '取消',
      onOk: () => doRestartAgent(selectedRowKeys.value),
    })
  }
}

// 执行重启
const doRestartAgent = async (hostIds: string[]) => {
  try {
    await hostsApi.restartAgent(hostIds.length > 0 ? hostIds : undefined)
    message.success('重启命令已提交，Agent 将在数秒后重启')
    selectedRowKeys.value = []
  } catch (error: any) {
    console.error('重启 Agent 失败:', error)
    message.error(error?.message || '重启 Agent 失败，请重试')
  }
}

// 批量删除主机
const handleBatchDeleteHost = () => {
  if (selectedRowKeys.value.length === 0) {
    message.warning('请先选择要删除的主机')
    return
  }

  // 检查选中主机中是否包含在线主机
  const selectedHosts = hosts.value.filter(h => selectedRowKeys.value.includes(h.host_id))
  const onlineCount = selectedHosts.filter(h => h.status === 'online').length
  const offlineCount = selectedRowKeys.value.length - onlineCount

  if (onlineCount > 0 && offlineCount > 0) {
    // 混合状态：先确认删除离线主机
    Modal.confirm({
      title: '批量删除主机',
      content: `选中的 ${selectedRowKeys.value.length} 台主机中有 ${onlineCount} 台在线、${offlineCount} 台离线。是否仅删除离线主机？`,
      okText: `删除 ${offlineCount} 台离线主机`,
      okType: 'danger',
      cancelText: '取消',
      onOk: async () => {
        await doBatchDelete(false)
      },
    })
  } else if (onlineCount > 0) {
    // 全部在线：仅提供强制删除选项
    Modal.confirm({
      title: '批量删除主机',
      content: `选中的 ${selectedRowKeys.value.length} 台主机全部在线。在线主机删除后 Agent 将无法上报数据，确定要强制删除吗？`,
      okText: '强制删除',
      okType: 'danger',
      cancelText: '取消',
      onOk: async () => {
        await doBatchDelete(true)
      },
    })
  } else {
    // 全部离线，直接确认删除
    Modal.confirm({
      title: '批量删除主机',
      content: `确定要删除选中的 ${selectedRowKeys.value.length} 台主机及其所有关联数据吗？此操作不可恢复。`,
      okText: '确定删除',
      okType: 'danger',
      cancelText: '取消',
      onOk: async () => {
        await doBatchDelete(false)
      },
    })
  }
}

// 执行批量删除
const doBatchDelete = async (force: boolean) => {
  try {
    const res = await hostsApi.batchDelete(selectedRowKeys.value, force)
    const parts: string[] = [`成功删除 ${res.deleted} 台主机`]
    if (res.skipped > 0) parts.push(`${res.skipped} 台在线已跳过`)
    if (res.failed > 0) parts.push(`${res.failed} 台失败`)
    message.success(parts.join('，'))
    selectedRowKeys.value = []
    loadHosts()
    loadStatusDistribution()
    loadRiskDistribution()
  } catch (error: any) {
    message.error(error?.message || '批量删除失败')
  }
}

// 批量添加标签
const handleBatchAddTags = () => {
  if (selectedRowKeys.value.length === 0) {
    message.warning('请先选择要操作的主机')
    return
  }
  batchTagsMode.value = 'append'
  batchTagsValue.value = []
  batchTagsModalVisible.value = true
}

// 确认批量更新标签
const handleConfirmBatchTags = async () => {
  if (batchTagsValue.value.length === 0) {
    message.warning('请输入至少一个标签')
    return
  }
  // 校验标签长度
  for (const tag of batchTagsValue.value) {
    if (tag.length > 50) {
      message.warning('标签长度不能超过 50 个字符')
      return
    }
  }
  try {
    const res = await hostsApi.batchUpdateTags(selectedRowKeys.value, batchTagsValue.value, batchTagsMode.value)
    message.success(`成功更新 ${res.updated} 台主机标签${res.failed > 0 ? `，${res.failed} 台失败` : ''}`)
    selectedRowKeys.value = []
    batchTagsModalVisible.value = false
    loadHosts()
  } catch (error: any) {
    message.error(error?.message || '批量更新标签失败')
  }
}

// 批量导出主机
const handleBatchExportHosts = () => {
  const exportHosts = selectedRowKeys.value.length > 0
    ? hosts.value.filter(h => selectedRowKeys.value.includes(h.host_id))
    : hosts.value

  if (exportHosts.length === 0) {
    message.warning('没有可导出的主机数据')
    return
  }

  // 构建 CSV 内容
  const headers = ['主机名称', 'Host ID', 'IP 地址', '操作系统', '状态', '业务线', '标签', '最后心跳时间']
  const rows = exportHosts.map(h => {
    const bl = businessLines.value.find(b => b.code === h.business_line)
    return [
      h.hostname,
      h.host_id,
      (h.ipv4 || []).join(';'),
      `${h.os_family} ${h.os_version}`,
      h.status === 'online' ? '在线' : '离线',
      bl ? bl.name : (h.business_line || ''),
      (h.tags || []).join(';'),
      h.last_heartbeat || '',
    ]
  })

  // 生成 CSV（BOM 头确保 Excel 正确识别 UTF-8）
  const csvContent = '\uFEFF' + [headers, ...rows].map(row =>
    row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')
  ).join('\n')

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', `hosts_export_${new Date().toISOString().slice(0, 10)}.csv`)
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.URL.revokeObjectURL(url)

  message.success(`已导出 ${exportHosts.length} 台主机数据`)
}

// 批量绑定业务线
const handleBatchBindBusinessLine = () => {
  if (selectedRowKeys.value.length === 0) {
    message.warning('请先选择要绑定的主机')
    return
  }
  batchBindHostIds.value = [...selectedRowKeys.value]
  batchBindBusinessLine.value = ''
  batchBindBusinessLineModalVisible.value = true
}

// 确认批量绑定业务线
const handleConfirmBatchBindBusinessLine = async () => {
  const hostIds = [...batchBindHostIds.value]
  if (hostIds.length === 0) {
    message.warning('请先选择要绑定的主机')
    return
  }

  try {
    const businessLine = batchBindBusinessLine.value || ''
    const res = await hostsApi.batchUpdateBusinessLine(hostIds, businessLine)
    message.success(`成功更新 ${res.updated} 台主机业务线`)

    // 清空选择并关闭对话框
    selectedRowKeys.value = []
    batchBindHostIds.value = []
    batchBindBusinessLineModalVisible.value = false
    batchBindBusinessLine.value = ''

    // 刷新主机列表
    loadHosts()
  } catch (error: any) {
    console.error('批量绑定业务线失败:', error)
  }
}

// 取消批量绑定业务线
const handleCancelBatchBindBusinessLine = () => {
  batchBindBusinessLineModalVisible.value = false
  batchBindBusinessLine.value = ''
  batchBindHostIds.value = []
}

onMounted(() => {
  // 从 URL 查询参数恢复筛选条件和分页
  const q = route.query
  if (q.page) pagination.current = Number(q.page) || 1
  if (q.page_size) pagination.pageSize = Number(q.page_size) || 20
  if (q.search) filters.search = q.search as string
  if (q.business_line) filters.business_line = q.business_line as string
  if (q.os_family) filters.os_family = q.os_family as string
  if (q.status) filters.status = q.status as string
  if (q.runtime_type) filters.runtime_type = q.runtime_type as string

  loadBusinessLines()
  loadHosts()
  loadStatusDistribution()
  loadRiskDistribution()
})
</script>

<style scoped>
.hosts-page {
  width: 100%;
}

.distribution-row {
  display: flex;
  align-items: stretch;
}

.distribution-col {
  display: flex;
}

.distribution-card {
  width: 100%;
  display: flex;
  flex-direction: column;
}

.distribution-card :deep(.ant-card-body) {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.status-distribution-container {
  display: flex;
  align-items: flex-start;
  gap: 24px;
  flex: 1;
  min-height: 280px;
}

.chart-container {
  flex: 1;
  position: relative;
  cursor: pointer;
}

.status-chart {
  width: 100%;
  height: 200px;
}

.chart-hint {
  text-align: center;
  margin-top: 8px;
  color: #86909C;
  font-size: 12px;
}

.legend-container {
  flex: 1;
  min-width: 200px;
}

.status-legend {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  border-radius: 6px;
  transition: background 0.2s;
}

.legend-item:hover {
  background: #f5f7fa;
}

.legend-color {
  width: 12px;
  height: 12px;
  border-radius: 3px;
  display: inline-block;
}

.legend-value {
  margin-left: auto;
  font-weight: 600;
  color: #1D2129;
}

.risk-distribution-container {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
  flex: 1;
  align-content: start;
}

.risk-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  border: none;
  border-radius: 8px;
  background: #F7F8FA;
  min-height: 70px;
  transition: all 0.3s ease;
}

.risk-card:hover {
  background: #f0f5ff;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.06);
}

.risk-icon {
  width: 44px;
  height: 44px;
  border: 2px solid;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  flex-shrink: 0;
}

.risk-content {
  flex: 1;
  min-width: 0;
}

.risk-label {
  font-size: 12px;
  color: #4E5969;
  margin-bottom: 4px;
  line-height: 1.4;
  word-break: break-word;
}

.risk-value {
  font-size: 22px;
  font-weight: 700;
  color: #1D2129;
}

.action-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid #f0f0f0;
}

.action-left {
  flex: 1;
}

.action-right {
  display: flex;
  align-items: center;
}

.filter-bar {
  margin-bottom: 16px;
  display: flex;
  gap: 8px;
  align-items: center;
  padding: 12px 16px;
  background: #F7F8FA;
  border-radius: 6px;
  border: 1px solid #f0f0f0;
}

.host-link {
  color: #165DFF;
  text-decoration: none;
}

.host-link:hover {
  color: #4080FF;
  text-decoration: underline;
}

.action-cell {
  display: flex;
  align-items: center;
  white-space: nowrap;
}

.action-link {
  padding: 0 2px;
  height: auto;
  line-height: 1;
}

.action-link-danger {
  color: #F53F3F;
}

.action-link-danger:hover {
  color: #ff7875;
}
</style>
