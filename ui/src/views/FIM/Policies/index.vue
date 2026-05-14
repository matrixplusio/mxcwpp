<template>
  <div class="fim-policies">
    <div class="page-header">
      <h2>FIM 策略管理</h2>
      <a-button type="primary" @click="showCreateModal">
        <PlusOutlined /> 新建策略
      </a-button>
    </div>

    <!-- 筛选栏 -->
    <div class="filter-bar">
      <a-input
        v-model:value="filters.name"
        placeholder="搜索策略名称"
        style="width: 240px"
        allow-clear
        @change="handleSearch"
      >
        <template #prefix><SearchOutlined /></template>
      </a-input>
      <a-select
        v-model:value="filters.enabled"
        placeholder="启用状态"
        style="width: 120px; margin-left: 12px"
        allow-clear
        @change="handleSearch"
      >
        <a-select-option value="true">已启用</a-select-option>
        <a-select-option value="false">已禁用</a-select-option>
      </a-select>
    </div>

    <!-- 策略表格 -->
    <a-table
      :columns="columns"
      :data-source="policies"
      :loading="loading"
      :pagination="pagination"
      row-key="policy_id"
      @change="handleTableChange"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'name'">
          <a @click="handleDetail(record)">{{ record.name }}</a>
        </template>
        <template v-if="column.key === 'watch_paths'">
          {{ record.watch_paths?.length || 0 }} 个路径
        </template>
        <template v-if="column.key === 'exclude_paths'">
          {{ record.exclude_paths?.length || 0 }} 个路径
        </template>
        <template v-if="column.key === 'check_interval_hours'">
          {{ record.check_interval_hours }} 小时
        </template>
        <template v-if="column.key === 'target_type'">
          <a-tag v-if="record.target_type === 'all'" color="blue">所有主机</a-tag>
          <a-tag v-else-if="record.target_type === 'host_ids'" color="green">指定主机</a-tag>
          <a-tag v-else>{{ record.target_type }}</a-tag>
        </template>
        <template v-if="column.key === 'enabled'">
          <a-switch
            :checked="record.enabled"
            @change="(checked: boolean) => handleToggleEnabled(record, checked)"
            size="small"
          />
        </template>
        <template v-if="column.key === 'action'">
          <a-space>
            <a @click="handleEdit(record)">编辑</a>
            <a-popconfirm title="确认删除此策略？" @confirm="handleDelete(record.policy_id)">
              <a class="danger-link">删除</a>
            </a-popconfirm>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 策略详情弹窗 -->
    <a-modal
      v-model:open="detailVisible"
      title="策略详情"
      :width="640"
      :footer="null"
    >
      <template v-if="selectedPolicy">
        <a-descriptions :column="2" bordered size="small">
          <a-descriptions-item label="策略名称" :span="2">{{ selectedPolicy.name }}</a-descriptions-item>
          <a-descriptions-item label="描述" :span="2">{{ selectedPolicy.description || '-' }}</a-descriptions-item>
          <a-descriptions-item label="检查间隔">{{ selectedPolicy.check_interval_hours }} 小时</a-descriptions-item>
          <a-descriptions-item label="目标范围">{{ selectedPolicy.target_type }}</a-descriptions-item>
          <a-descriptions-item label="创建时间">{{ selectedPolicy.created_at }}</a-descriptions-item>
          <a-descriptions-item label="更新时间">{{ selectedPolicy.updated_at }}</a-descriptions-item>
        </a-descriptions>

        <a-divider>监控路径</a-divider>
        <a-table
          :columns="watchPathColumns"
          :data-source="selectedPolicy.watch_paths"
          :pagination="false"
          size="small"
          row-key="path"
        />

        <template v-if="selectedPolicy.exclude_paths?.length">
          <a-divider>排除路径</a-divider>
          <div class="exclude-paths">
            <a-tag v-for="p in selectedPolicy.exclude_paths" :key="p">{{ p }}</a-tag>
          </div>
        </template>
      </template>
    </a-modal>

    <!-- 创建/编辑弹窗 -->
    <PolicyModal
      v-model:open="modalVisible"
      :policy="editingPolicy"
      @success="fetchPolicies"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { PlusOutlined, SearchOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { fimApi } from '@/api/fim'
import type { FIMPolicy } from '@/api/types'
import PolicyModal from './components/PolicyModal.vue'

const loading = ref(false)
const policies = ref<FIMPolicy[]>([])
const modalVisible = ref(false)
const detailVisible = ref(false)
const editingPolicy = ref<FIMPolicy | null>(null)
const selectedPolicy = ref<FIMPolicy | null>(null)

const filters = reactive({
  name: '',
  enabled: undefined as string | undefined,
})

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  { title: '策略名称', key: 'name', dataIndex: 'name' },
  { title: '监控路径', key: 'watch_paths', width: 100, align: 'center' as const },
  { title: '排除路径', key: 'exclude_paths', width: 100, align: 'center' as const },
  { title: '检查间隔', key: 'check_interval_hours', width: 100, align: 'center' as const },
  { title: '目标范围', key: 'target_type', width: 100 },
  { title: '启用', key: 'enabled', width: 80, align: 'center' as const },
  { title: '创建时间', dataIndex: 'created_at', width: 170 },
  { title: '操作', key: 'action', width: 120 },
]

const watchPathColumns = [
  { title: '路径', dataIndex: 'path' },
  { title: '级别', dataIndex: 'level', width: 100 },
  { title: '说明', dataIndex: 'comment' },
]

const fetchPolicies = async () => {
  loading.value = true
  try {
    const res = await fimApi.listPolicies({
      page: pagination.current,
      page_size: pagination.pageSize,
      name: filters.name || undefined,
      enabled: filters.enabled,
    })
    policies.value = res.items || []
    pagination.total = res.total
  } catch {
    // API 客户端已处理错误提示
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  pagination.current = 1
  fetchPolicies()
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  fetchPolicies()
}

const showCreateModal = () => {
  editingPolicy.value = null
  modalVisible.value = true
}

const handleEdit = (policy: FIMPolicy) => {
  editingPolicy.value = policy
  modalVisible.value = true
}

const handleDetail = (policy: FIMPolicy) => {
  selectedPolicy.value = policy
  detailVisible.value = true
}

const handleToggleEnabled = async (policy: FIMPolicy, checked: boolean) => {
  try {
    await fimApi.updatePolicy(policy.policy_id, { enabled: checked })
    message.success(checked ? '策略已启用' : '策略已禁用')
    fetchPolicies()
  } catch {
    // API 客户端已处理错误提示
  }
}

const handleDelete = async (policyId: string) => {
  try {
    await fimApi.deletePolicy(policyId)
    message.success('删除成功')
    fetchPolicies()
  } catch {
    // API 客户端已处理错误提示
  }
}

onMounted(() => {
  fetchPolicies()
})
</script>

<style scoped>
.fim-policies {
  padding: 0;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
}

.filter-bar {
  display: flex;
  align-items: center;
  margin-bottom: 16px;
}

.danger-link {
  color: #F53F3F;
}

.danger-link:hover {
  color: #ff7875;
}

.exclude-paths {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
</style>
