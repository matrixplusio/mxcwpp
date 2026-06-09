<template>
  <div class="users-page">
    <div class="page-header">
      <h2>用户管理</h2>
      <a-button type="primary" @click="handleCreate">
        <template #icon>
          <PlusOutlined />
        </template>
        新建用户
      </a-button>
    </div>

    <!-- 搜索栏 -->
    <div class="filter-bar">
      <a-form layout="inline" :model="searchForm">
        <a-form-item label="用户名">
          <a-input
            v-model:value="searchForm.username"
            placeholder="请输入用户名"
            allow-clear
            style="width: 200px"
          />
        </a-form-item>
        <a-form-item label="角色">
          <a-select
            v-model:value="searchForm.role"
            placeholder="请选择角色"
            allow-clear
            style="width: 120px"
          >
            <a-select-option value="admin">管理员</a-select-option>
            <a-select-option value="user">普通用户</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="状态">
          <a-select
            v-model:value="searchForm.status"
            placeholder="请选择状态"
            allow-clear
            style="width: 120px"
          >
            <a-select-option value="active">启用</a-select-option>
            <a-select-option value="inactive">禁用</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item>
          <a-button type="primary" @click="handleSearch">查询</a-button>
          <a-button style="margin-left: 8px" @click="handleReset">重置</a-button>
        </a-form-item>
      </a-form>
    </div>

    <!-- 用户列表 -->
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
          <template v-if="column.key === 'role'">
            <a-tag :color="record.role === 'admin' ? 'red' : 'blue'">
              {{ record.role === 'admin' ? '管理员' : '普通用户' }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'status'">
            <a-tag :color="record.status === 'active' ? 'green' : 'default'">
              {{ record.status === 'active' ? '启用' : '禁用' }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'last_login'">
            {{ record.last_login ? formatDate(record.last_login) : '-' }}
          </template>
          <template v-else-if="column.key === 'actions'">
            <a-space>
              <a-button type="link" size="small" @click="handleEdit(record)">编辑</a-button>
              <a-popconfirm
                title="确定要删除这个用户吗？"
                ok-text="确定"
                cancel-text="取消"
                @confirm="handleDelete(record.id)"
              >
                <a-button type="link" size="small" danger>删除</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 用户编辑对话框 -->
    <UserModal
      v-model:open="modalVisible"
      :user="currentUser"
      @success="handleModalSuccess"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { PlusOutlined } from '@ant-design/icons-vue'
import { usersApi, type User, type ListUsersParams } from '@/api/users'
import UserModal from './components/UserModal.vue'

const loading = ref(false)
const users = ref<User[]>([])
const modalVisible = ref(false)
const currentUser = ref<User | null>(null)

const searchForm = reactive({
  username: '',
  role: undefined as string | undefined,
  status: undefined as string | undefined,
})

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  {
    title: 'ID',
    dataIndex: 'id',
    key: 'id',
    width: 80,
  },
  {
    title: '用户名',
    dataIndex: 'username',
    key: 'username',
  },
  {
    title: '邮箱',
    dataIndex: 'email',
    key: 'email',
  },
  {
    title: '角色',
    key: 'role',
    width: 100,
  },
  {
    title: '状态',
    key: 'status',
    width: 100,
  },
  {
    title: '最后登录',
    key: 'last_login',
    width: 180,
  },
  {
    title: '创建时间',
    dataIndex: 'created_at',
    key: 'created_at',
    width: 180,
  },
  {
    title: '操作',
    key: 'actions',
    width: 150,
  },
]

const loadUsers = async () => {
  loading.value = true
  try {
    const params: ListUsersParams = {
      page: pagination.current,
      page_size: pagination.pageSize,
    }
    if (searchForm.username) {
      params.username = searchForm.username
    }
    if (searchForm.role) {
      params.role = searchForm.role
    }
    if (searchForm.status) {
      params.status = searchForm.status
    }

    const response = await usersApi.list(params)
    users.value = response.items
    pagination.total = response.total
  } catch (error: any) {
    message.error('加载用户列表失败: ' + (error.message || '未知错误'))
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  pagination.current = 1
  loadUsers()
}

const handleReset = () => {
  searchForm.username = ''
  searchForm.role = undefined
  searchForm.status = undefined
  pagination.current = 1
  loadUsers()
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  loadUsers()
}

const handleCreate = () => {
  currentUser.value = null
  modalVisible.value = true
}

const handleEdit = (user: User) => {
  currentUser.value = user
  modalVisible.value = true
}

const handleDelete = async (id: number) => {
  try {
    await usersApi.delete(id)
    message.success('删除成功')
    loadUsers()
  } catch (error: any) {
    message.error('删除失败: ' + (error.message || '未知错误'))
  }
}

const handleModalSuccess = () => {
  modalVisible.value = false
  loadUsers()
}

const formatDate = (dateStr: string) => {
  if (!dateStr) return '-'
  const date = new Date(dateStr)
  return date.toLocaleString('zh-CN')
}

onMounted(() => {
  loadUsers()
})
</script>

<style scoped>
.users-page {
  width: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.filter-bar {
  margin-bottom: 16px;
  padding: 12px 16px;
  background: var(--mxsec-fill-1);
  border-radius: 6px;
  border: 1px solid var(--mxsec-border);
}
</style>
