<template>
  <a-modal
    v-model:open="visible"
    :title="title"
    width="800px"
    :confirm-loading="loading"
    @ok="handleOk"
    @cancel="handleCancel"
  >
    <div class="host-selector">
      <!-- 选择模式 -->
      <a-form layout="vertical">
        <a-form-item label="选择范围">
          <a-radio-group v-model:value="selectionMode" @change="handleModeChange">
            <a-radio-button value="global">
              <GlobalOutlined />
              全局匹配
            </a-radio-button>
            <a-radio-button value="custom">
              <FilterOutlined />
              自定义选择
            </a-radio-button>
          </a-radio-group>
        </a-form-item>

        <!-- 全局匹配说明 -->
        <div v-if="selectionMode === 'global'" class="mode-description">
          <a-alert
            type="info"
            show-icon
          >
            <template #message>
              <span>将对所有符合策略系统要求的在线主机执行检查</span>
            </template>
            <template #description>
              <div class="policy-os-info">
                <span v-if="policyOsFamily && policyOsFamily.length > 0">
                  支持的操作系统:
                  <a-tag v-for="os in policyOsFamily" :key="os" color="blue">{{ os }}</a-tag>
                </span>
                <span v-else>支持所有操作系统</span>
                <span v-if="policyOsVersion" style="margin-left: 12px;">
                  版本要求: <a-tag color="green">{{ policyOsVersion }}</a-tag>
                </span>
              </div>
              <div class="host-count-info">
                预计匹配主机数: <strong>{{ matchedHostCount }}</strong> 台 (在线)
              </div>
            </template>
          </a-alert>
        </div>

        <!-- 自定义选择 -->
        <div v-if="selectionMode === 'custom'" class="custom-selection">
          <!-- 筛选条件 -->
          <a-card size="small" title="筛选条件" class="filter-card">
            <a-row :gutter="16">
              <a-col :span="8">
                <a-form-item label="操作系统">
                  <a-select
                    v-model:value="filters.osFamily"
                    placeholder="选择操作系统"
                    allow-clear
                    mode="multiple"
                    @change="handleFilterChange"
                  >
                    <a-select-option v-for="os in availableOsFamilies" :key="os" :value="os">
                      {{ os }}
                    </a-select-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item label="标签">
                  <a-select
                    v-model:value="filters.tags"
                    placeholder="选择标签"
                    allow-clear
                    mode="multiple"
                    @change="handleFilterChange"
                  >
                    <a-select-option v-for="tag in availableTags" :key="tag" :value="tag">
                      {{ tag }}
                    </a-select-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :span="8">
                <a-form-item label="搜索">
                  <a-input
                    v-model:value="filters.search"
                    placeholder="搜索主机名/ID"
                    allow-clear
                    @change="handleFilterChange"
                  >
                    <template #prefix>
                      <SearchOutlined />
                    </template>
                  </a-input>
                </a-form-item>
              </a-col>
            </a-row>
          </a-card>

          <!-- 主机列表 -->
          <a-card size="small" class="host-list-card">
            <template #title>
              <div class="host-list-header">
                <span>选择主机</span>
                <span class="selected-count">
                  已选择 {{ selectedHostIds.length }} 台主机
                </span>
              </div>
            </template>
            <template #extra>
              <a-space>
                <a-button size="small" @click="handleSelectAll">
                  全选
                </a-button>
                <a-button size="small" @click="handleClearSelection">
                  清空
                </a-button>
                <a-button size="small" @click="loadHosts" :loading="hostsLoading">
                  <template #icon>
                    <ReloadOutlined />
                  </template>
                </a-button>
              </a-space>
            </template>
            <a-table
              :columns="hostColumns"
              :data-source="filteredHosts"
              :loading="hostsLoading"
              :pagination="{ pageSize: 10, showSizeChanger: true, showTotal: (total: number) => `共 ${total} 条` }"
              :row-selection="{
                selectedRowKeys: selectedHostIds,
                onChange: handleHostSelectionChange,
              }"
              row-key="host_id"
              size="small"
              :scroll="{ y: 300 }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'status'">
                  <a-badge
                    :status="record.status === 'online' ? 'success' : 'default'"
                    :text="record.status === 'online' ? '在线' : '离线'"
                  />
                </template>
                <template v-else-if="column.key === 'tags'">
                  <template v-if="record.tags && record.tags.length > 0">
                    <a-tag v-for="tag in record.tags.slice(0, 3)" :key="tag" size="small">
                      {{ tag }}
                    </a-tag>
                    <span v-if="record.tags.length > 3" class="more-tags">
                      +{{ record.tags.length - 3 }}
                    </span>
                  </template>
                  <span v-else class="no-tags">-</span>
                </template>
              </template>
            </a-table>
          </a-card>
        </div>
      </a-form>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import {
  GlobalOutlined,
  FilterOutlined,
  SearchOutlined,
  ReloadOutlined,
} from '@ant-design/icons-vue'
import { hostsApi } from '@/api/hosts'
import type { Host } from '@/api/types'

interface Props {
  open: boolean
  title?: string
  policyOsFamily?: string[]
  policyOsVersion?: string
}

interface Emits {
  (e: 'update:open', value: boolean): void
  (e: 'confirm', data: {
    mode: 'global' | 'custom'
    targetType: 'all' | 'host_ids' | 'os_family'
    hostIds?: string[]
    osFamily?: string[]
  }): void
}

const props = withDefaults(defineProps<Props>(), {
  title: '选择检查主机范围',
  policyOsFamily: () => [],
  policyOsVersion: '',
})

const emit = defineEmits<Emits>()

const visible = computed({
  get: () => props.open,
  set: (val) => emit('update:open', val),
})

const loading = ref(false)
const hostsLoading = ref(false)
const selectionMode = ref<'global' | 'custom'>('global')
const hosts = ref<Host[]>([])
const selectedHostIds = ref<string[]>([])
const matchedHostCount = ref(0)

const filters = ref({
  osFamily: [] as string[],
  tags: [] as string[],
  search: '',
})

// 可用的操作系统列表
const availableOsFamilies = computed(() => {
  const families = new Set<string>()
  hosts.value.forEach(host => {
    if (host.os_family) {
      families.add(host.os_family)
    }
  })
  return Array.from(families).sort()
})

// 可用的标签列表
const availableTags = computed(() => {
  const tags = new Set<string>()
  hosts.value.forEach(host => {
    if (host.tags && Array.isArray(host.tags)) {
      host.tags.forEach(tag => tags.add(tag))
    }
  })
  return Array.from(tags).sort()
})

// 过滤后的主机列表
const filteredHosts = computed(() => {
  let result = hosts.value

  // 只显示在线主机
  result = result.filter(host => host.status === 'online')

  // 按操作系统过滤
  if (filters.value.osFamily.length > 0) {
    result = result.filter(host =>
      filters.value.osFamily.includes(host.os_family)
    )
  }

  // 按标签过滤
  if (filters.value.tags.length > 0) {
    result = result.filter(host =>
      host.tags && filters.value.tags.some(tag => host.tags!.includes(tag))
    )
  }

  // 按搜索关键词过滤
  if (filters.value.search) {
    const keyword = filters.value.search.toLowerCase()
    result = result.filter(host =>
      host.hostname.toLowerCase().includes(keyword) ||
      host.host_id.toLowerCase().includes(keyword)
    )
  }

  return result
})

const hostColumns = [
  {
    title: '主机名',
    dataIndex: 'hostname',
    key: 'hostname',
    ellipsis: true,
  },
  {
    title: '主机ID',
    dataIndex: 'host_id',
    key: 'host_id',
    width: 150,
    ellipsis: true,
  },
  {
    title: '操作系统',
    dataIndex: 'os_family',
    key: 'os_family',
    width: 120,
  },
  {
    title: '状态',
    key: 'status',
    width: 80,
  },
  {
    title: '标签',
    key: 'tags',
    width: 150,
  },
]

// 加载主机列表
const loadHosts = async () => {
  hostsLoading.value = true
  try {
    const response = await hostsApi.list({ page_size: 1000 }) as any
    hosts.value = response.items || []

    // 计算匹配策略要求的在线主机数
    calculateMatchedHostCount()
  } catch (error) {
    console.error('加载主机列表失败:', error)
  } finally {
    hostsLoading.value = false
  }
}

// 计算匹配策略要求的主机数
const calculateMatchedHostCount = () => {
  let count = 0
  hosts.value.forEach(host => {
    if (host.status !== 'online') return

    // 如果策略没有指定 OS Family，匹配所有主机
    if (!props.policyOsFamily || props.policyOsFamily.length === 0) {
      count++
      return
    }

    // 检查 OS Family 是否匹配
    const familyMatched = props.policyOsFamily.some(
      family => family.toLowerCase() === host.os_family?.toLowerCase()
    )
    if (familyMatched) {
      count++
    }
  })
  matchedHostCount.value = count
}

const handleModeChange = () => {
  // 切换模式时清空选择
  selectedHostIds.value = []
}

const handleFilterChange = () => {
  // 过滤条件变化时，可能需要更新选择
}

const handleHostSelectionChange = (keys: string[]) => {
  selectedHostIds.value = keys
}

const handleSelectAll = () => {
  selectedHostIds.value = filteredHosts.value.map(host => host.host_id)
}

const handleClearSelection = () => {
  selectedHostIds.value = []
}

const handleOk = () => {
  if (selectionMode.value === 'custom' && selectedHostIds.value.length === 0) {
    message.warning('请至少选择一台主机')
    return
  }

  loading.value = true

  try {
    if (selectionMode.value === 'global') {
      // 全局模式：使用策略的 OS Family
      if (props.policyOsFamily && props.policyOsFamily.length > 0) {
        emit('confirm', {
          mode: 'global',
          targetType: 'os_family',
          osFamily: props.policyOsFamily,
        })
      } else {
        emit('confirm', {
          mode: 'global',
          targetType: 'all',
        })
      }
    } else {
      // 自定义模式：使用选中的主机 ID
      emit('confirm', {
        mode: 'custom',
        targetType: 'host_ids',
        hostIds: selectedHostIds.value,
      })
    }

    visible.value = false
  } finally {
    loading.value = false
  }
}

const handleCancel = () => {
  visible.value = false
}

// 监听 visible 变化，重新加载数据
watch(() => props.open, (val) => {
  if (val) {
    loadHosts()
    // 重置选择
    selectionMode.value = 'global'
    selectedHostIds.value = []
    filters.value = {
      osFamily: [],
      tags: [],
      search: '',
    }
  }
})

onMounted(() => {
  if (props.open) {
    loadHosts()
  }
})
</script>

<style scoped>
.host-selector {
  min-height: 400px;
}

.mode-description {
  margin-top: 16px;
}

.policy-os-info {
  margin-bottom: 8px;
}

.host-count-info {
  color: var(--mxsec-primary);
  font-size: 14px;
}

.custom-selection {
  margin-top: 16px;
}

.filter-card {
  margin-bottom: 16px;
}

.host-list-card {
  margin-top: 16px;
}

.host-list-header {
  display: flex;
  align-items: center;
  gap: 16px;
}

.selected-count {
  font-size: 12px;
  color: var(--mxsec-primary);
  font-weight: normal;
}

.more-tags {
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.no-tags {
  color: #bfbfbf;
}

:deep(.ant-table-tbody > tr) {
  cursor: pointer;
}

:deep(.ant-table-tbody > tr:hover) {
  background: var(--mxsec-fill-1);
}
</style>
