<template>
  <a-card :bordered="false">
    <a-table
      :columns="columns"
      :data-source="processes"
      :loading="loading"
      :pagination="pagination"
      @change="handleTableChange"
      row-key="id"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'pid'">
          <a-tag>{{ record.pid }}</a-tag>
        </template>
        <template v-else-if="column.key === 'cmdline'">
          <a-tooltip :title="record.cmdline">
            <span style="max-width: 400px; display: inline-block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">
              {{ record.cmdline || '-' }}
            </span>
          </a-tooltip>
        </template>
        <template v-else-if="column.key === 'container_id'">
          <a-tag v-if="record.container_id" color="blue">{{ record.container_id.substring(0, 12) }}</a-tag>
          <span v-else style="color: #86909C">-</span>
        </template>
        <template v-else-if="column.key === 'exe_hash'">
          <a-tag v-if="record.exe_hash" color="green">{{ record.exe_hash.substring(0, 8) }}...</a-tag>
          <span v-else style="color: #86909C">-</span>
        </template>
      </template>
      <template #emptyText>
        <a-empty description="暂无进程数据" />
      </template>
    </a-table>
  </a-card>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, watch } from 'vue'
import { assetsApi } from '@/api/assets'
import type { Process } from '@/api/types'

const props = defineProps<{
  hostId: string
}>()

const loading = ref(false)
const processes = ref<Process[]>([])
const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  {
    title: 'PID',
    dataIndex: 'pid',
    key: 'pid',
    width: 100,
  },
  {
    title: 'PPID',
    dataIndex: 'ppid',
    key: 'ppid',
    width: 100,
  },
  {
    title: '命令',
    dataIndex: 'cmdline',
    key: 'cmdline',
    ellipsis: true,
  },
  {
    title: '可执行文件',
    dataIndex: 'exe',
    key: 'exe',
    width: 200,
    ellipsis: true,
  },
  {
    title: 'MD5',
    dataIndex: 'exe_hash',
    key: 'exe_hash',
    width: 150,
  },
  {
    title: '用户',
    dataIndex: 'username',
    key: 'username',
    width: 120,
  },
  {
    title: 'UID/GID',
    key: 'uid_gid',
    width: 120,
    customRender: ({ record }: { record: Process }) => {
      return `${record.uid}/${record.gid}`
    },
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
    customRender: ({ record }: { record: Process }) => {
      return new Date(record.collected_at).toLocaleString('zh-CN')
    },
  },
]

const loadProcesses = async () => {
  if (!props.hostId) return

  loading.value = true
  try {
    const response = await assetsApi.listProcesses({
      host_id: props.hostId,
      page: pagination.current,
      page_size: pagination.pageSize,
    })
    processes.value = response.items
    pagination.total = response.total
  } catch (error) {
    console.error('加载进程列表失败:', error)
  } finally {
    loading.value = false
  }
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  loadProcesses()
}

watch(
  () => props.hostId,
  () => {
    if (props.hostId) {
      pagination.current = 1
      loadProcesses()
    }
  },
  { immediate: true }
)

onMounted(() => {
  if (props.hostId) {
    loadProcesses()
  }
})
</script>
