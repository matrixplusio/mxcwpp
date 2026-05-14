<template>
  <a-card :bordered="false">
    <!-- 筛选条件 -->
    <div style="margin-bottom: 16px">
      <a-space>
        <span>协议类型：</span>
        <a-select
          v-model:value="filters.protocol"
          placeholder="全部"
          style="width: 120px"
          allow-clear
          @change="handleSearch"
        >
          <a-select-option value="tcp">TCP</a-select-option>
          <a-select-option value="udp">UDP</a-select-option>
        </a-select>
        <a-button @click="handleReset">重置</a-button>
      </a-space>
    </div>

    <a-table
      :columns="columns"
      :data-source="ports"
      :loading="loading"
      :pagination="pagination"
      @change="handleTableChange"
      row-key="id"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'protocol'">
          <a-tag :color="record.protocol === 'tcp' ? 'blue' : 'green'">
            {{ record.protocol.toUpperCase() }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'port'">
          <a-tag color="orange">{{ record.port }}</a-tag>
        </template>
        <template v-else-if="column.key === 'state'">
          <a-tag v-if="record.state" :color="getStateColor(record.state)">
            {{ record.state }}
          </a-tag>
          <span v-else style="color: #86909C">-</span>
        </template>
        <template v-else-if="column.key === 'container_id'">
          <a-tag v-if="record.container_id" color="blue">{{ record.container_id.substring(0, 12) }}</a-tag>
          <span v-else style="color: #86909C">-</span>
        </template>
      </template>
      <template #emptyText>
        <a-empty description="暂无端口数据" />
      </template>
    </a-table>
  </a-card>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, watch } from 'vue'
import { assetsApi } from '@/api/assets'
import type { Port } from '@/api/types'
import { message } from 'ant-design-vue'

const props = defineProps<{
  hostId: string
}>()

const loading = ref(false)
const ports = ref<Port[]>([])
const filters = reactive({
  protocol: undefined as string | undefined,
})
const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  {
    title: '协议',
    dataIndex: 'protocol',
    key: 'protocol',
    width: 100,
  },
  {
    title: '端口',
    dataIndex: 'port',
    key: 'port',
    width: 100,
  },
  {
    title: '状态',
    dataIndex: 'state',
    key: 'state',
    width: 120,
  },
  {
    title: '进程ID',
    dataIndex: 'pid',
    key: 'pid',
    width: 100,
  },
  {
    title: '进程名',
    dataIndex: 'process_name',
    key: 'process_name',
    width: 200,
    ellipsis: true,
  },
  {
    title: '容器ID',
    dataIndex: 'container_id',
    key: 'container_id',
    width: 150,
  },
  {
    title: '采集时间',
    dataIndex: 'collected_at',
    key: 'collected_at',
    width: 180,
    customRender: ({ record }: { record: Port }) => {
      return new Date(record.collected_at).toLocaleString('zh-CN')
    },
  },
]

const getStateColor = (state: string) => {
  if (state === 'LISTEN') return 'green'
  if (state === 'ESTABLISHED') return 'blue'
  return 'default'
}

const loadPorts = async () => {
  if (!props.hostId) return

  loading.value = true
  try {
    const response = await assetsApi.listPorts({
      host_id: props.hostId,
      protocol: filters.protocol,
      page: pagination.current,
      page_size: pagination.pageSize,
    })
    ports.value = response.items
    pagination.total = response.total
  } catch (error) {
    console.error('加载端口列表失败:', error)
    message.error('加载端口列表失败')
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  pagination.current = 1
  loadPorts()
}

const handleReset = () => {
  filters.protocol = undefined
  pagination.current = 1
  loadPorts()
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  loadPorts()
}

watch(
  () => props.hostId,
  () => {
    if (props.hostId) {
      pagination.current = 1
      loadPorts()
    }
  },
  { immediate: true }
)

onMounted(() => {
  if (props.hostId) {
    loadPorts()
  }
})
</script>
