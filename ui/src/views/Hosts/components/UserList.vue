<template>
  <a-card :bordered="false">
    <a-table
      :columns="columns"
      :data-source="users"
      :loading="loading"
      :pagination="pagination"
      @change="handleTableChange"
      row-key="id"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'username'">
          <a-tag color="blue">{{ record.username }}</a-tag>
        </template>
        <template v-else-if="column.key === 'has_password'">
          <a-tag :color="record.has_password ? 'green' : 'red'">
            {{ record.has_password ? '有密码' : '无密码' }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'uid'">
          <a-tag>{{ record.uid }}</a-tag>
        </template>
      </template>
      <template #emptyText>
        <a-empty description="暂无用户数据" />
      </template>
    </a-table>
  </a-card>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, watch } from 'vue'
import { assetsApi } from '@/api/assets'
import type { AssetUser } from '@/api/types'
import { message } from 'ant-design-vue'

const props = defineProps<{
  hostId: string
}>()

const loading = ref(false)
const users = ref<AssetUser[]>([])
const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  {
    title: '用户名',
    dataIndex: 'username',
    key: 'username',
    width: 150,
  },
  {
    title: 'UID',
    dataIndex: 'uid',
    key: 'uid',
    width: 100,
  },
  {
    title: 'GID',
    dataIndex: 'gid',
    key: 'gid',
    width: 100,
  },
  {
    title: '组名',
    dataIndex: 'groupname',
    key: 'groupname',
    width: 150,
  },
  {
    title: '主目录',
    dataIndex: 'home_dir',
    key: 'home_dir',
    width: 200,
    ellipsis: true,
  },
  {
    title: 'Shell',
    dataIndex: 'shell',
    key: 'shell',
    width: 150,
  },
  {
    title: '密码状态',
    dataIndex: 'has_password',
    key: 'has_password',
    width: 120,
  },
  {
    title: '备注',
    dataIndex: 'comment',
    key: 'comment',
    width: 200,
    ellipsis: true,
  },
  {
    title: '采集时间',
    dataIndex: 'collected_at',
    key: 'collected_at',
    width: 180,
    customRender: ({ record }: { record: AssetUser }) => {
      return new Date(record.collected_at).toLocaleString('zh-CN')
    },
  },
]

const loadUsers = async () => {
  if (!props.hostId) return

  loading.value = true
  try {
    const response = await assetsApi.listUsers({
      host_id: props.hostId,
      page: pagination.current,
      page_size: pagination.pageSize,
    })
    users.value = response.items
    pagination.total = response.total
  } catch (error) {
    console.error('加载用户列表失败:', error)
    message.error('加载用户列表失败')
  } finally {
    loading.value = false
  }
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  loadUsers()
}

watch(
  () => props.hostId,
  () => {
    if (props.hostId) {
      pagination.current = 1
      loadUsers()
    }
  },
  { immediate: true }
)

onMounted(() => {
  if (props.hostId) {
    loadUsers()
  }
})
</script>
