<template>
  <div class="business-lines-page">
    <div class="page-header">
      <h2>业务线管理</h2>
    </div>

    <!-- 搜索和操作区域 -->
    <div class="filter-bar">
        <a-input
          v-model:value="filters.keyword"
          placeholder="搜索业务线名称或代码"
          style="width: 300px"
          allow-clear
          @press-enter="handleSearch"
        >
          <template #prefix>
            <SearchOutlined />
          </template>
        </a-input>
        <a-select
          v-model:value="filters.enabled"
          placeholder="状态"
          style="width: 120px"
          allow-clear
          @change="handleSearch"
        >
          <a-select-option value="true">启用</a-select-option>
          <a-select-option value="false">禁用</a-select-option>
        </a-select>
        <a-button type="primary" @click="handleSearch">
          <template #icon>
            <SearchOutlined />
          </template>
          搜索
        </a-button>
        <a-button @click="loadBusinessLines">
          <template #icon>
            <ReloadOutlined />
          </template>
        </a-button>
        <a-button type="primary" @click="handleCreate">
          <template #icon>
            <PlusOutlined />
          </template>
          新建业务线
        </a-button>
      </div>

      <!-- 业务线列表 -->
      <a-table
        :columns="columns"
        :data-source="businessLines"
        :loading="loading"
        row-key="id"
        :pagination="pagination"
        @change="handleTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'enabled'">
            <a-tag :color="record.enabled ? 'success' : 'default'">
              {{ record.enabled ? '启用' : '禁用' }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'host_count'">
            <a-button type="link" @click="handleViewHosts(record)">
              {{ record.host_count || 0 }}
            </a-button>
          </template>
          <template v-else-if="column.key === 'actions'">
            <a-space>
              <a-button type="link" size="small" @click="handleEdit(record)">编辑</a-button>
              <a-popconfirm
                title="确定要删除这个业务线吗？"
                ok-text="确定"
                cancel-text="取消"
                @confirm="handleDelete(record)"
              >
                <a-button type="link" size="small" danger>删除</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>

    <!-- 创建/编辑业务线对话框 -->
    <a-modal
      v-model:open="modalVisible"
      :title="modalTitle"
      :width="600"
      @ok="handleSubmit"
      @cancel="handleCancel"
    >
      <a-form
        ref="formRef"
        :model="formData"
        :rules="formRules"
        :label-col="{ span: 6 }"
        :wrapper-col="{ span: 18 }"
      >
        <a-form-item label="业务线名称" name="name">
          <a-input v-model:value="formData.name" placeholder="请输入业务线名称" />
        </a-form-item>
        <a-form-item label="业务线代码" name="code">
          <a-input
            v-model:value="formData.code"
            placeholder="请输入业务线代码（唯一标识）"
            :disabled="isEdit"
          />
        </a-form-item>
        <a-form-item label="描述" name="description">
          <a-textarea
            v-model:value="formData.description"
            placeholder="请输入业务线描述"
            :rows="3"
          />
        </a-form-item>
        <a-form-item label="负责人" name="owner">
          <a-input v-model:value="formData.owner" placeholder="请输入负责人" />
        </a-form-item>
        <a-form-item label="联系方式" name="contact">
          <a-input v-model:value="formData.contact" placeholder="请输入联系方式" />
        </a-form-item>
        <a-form-item label="状态" name="enabled">
          <a-switch v-model:checked="formData.enabled" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed } from 'vue'
import { message } from 'ant-design-vue'
import { SearchOutlined, ReloadOutlined, PlusOutlined } from '@ant-design/icons-vue'
import { businessLinesApi, type BusinessLine } from '@/api/business-lines'
import { useRouter } from 'vue-router'
import { formatDateTime } from '@/utils/date'

const router = useRouter()

// 数据
const loading = ref(false)
const businessLines = ref<BusinessLine[]>([])
const filters = reactive({
  keyword: '',
  enabled: undefined as string | undefined,
})

// 分页
const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

// 表格列
const columns = [
  {
    title: '业务线名称',
    dataIndex: 'name',
    key: 'name',
  },
  {
    title: '业务线代码',
    dataIndex: 'code',
    key: 'code',
  },
  {
    title: '描述',
    dataIndex: 'description',
    key: 'description',
    ellipsis: true,
  },
  {
    title: '负责人',
    dataIndex: 'owner',
    key: 'owner',
  },
  {
    title: '主机数量',
    key: 'host_count',
  },
  {
    title: '状态',
    key: 'enabled',
  },
  {
    title: '创建时间',
    dataIndex: 'created_at',
    key: 'created_at',
    customRender: ({ record }: { record: BusinessLine }) => {
      return formatDateTime(record.created_at)
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 150,
  },
]

// 对话框
const modalVisible = ref(false)
const isEdit = ref(false)
const formRef = ref()
const formData = reactive({
  name: '',
  code: '',
  description: '',
  owner: '',
  contact: '',
  enabled: true,
})

const modalTitle = computed(() => (isEdit.value ? '编辑业务线' : '新建业务线'))

// 加载业务线列表
const loadBusinessLines = async () => {
  loading.value = true
  try {
    const params: any = {
      page: pagination.current,
      page_size: pagination.pageSize,
    }
    if (filters.keyword) {
      params.keyword = filters.keyword
    }
    if (filters.enabled !== undefined) {
      params.enabled = filters.enabled
    }

    const response = await businessLinesApi.list(params)
    businessLines.value = response.items
    pagination.total = response.total
  } catch (error: any) {
    message.error(error.message || '加载业务线列表失败')
  } finally {
    loading.value = false
  }
}

// 搜索
const handleSearch = () => {
  pagination.current = 1
  loadBusinessLines()
}

// 表格变化
const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  loadBusinessLines()
}

// 创建
const handleCreate = () => {
  isEdit.value = false
  formData.name = ''
  formData.code = ''
  formData.description = ''
  formData.owner = ''
  formData.contact = ''
  formData.enabled = true
  modalVisible.value = true
}

// 编辑
const handleEdit = (record: BusinessLine) => {
  isEdit.value = true
  formData.name = record.name
  formData.code = record.code
  formData.description = record.description || ''
  formData.owner = record.owner || ''
  formData.contact = record.contact || ''
  formData.enabled = record.enabled
  modalVisible.value = true
}

// 删除
const handleDelete = async (record: BusinessLine) => {
  try {
    await businessLinesApi.delete(record.id)
    message.success('删除成功')
    loadBusinessLines()
  } catch (error: any) {
    // 错误已在拦截器中处理
  }
}

// 提交表单
const handleSubmit = async () => {
  try {
    await formRef.value?.validate()
    if (isEdit.value) {
      const record = businessLines.value.find((bl) => bl.code === formData.code)
      if (!record) {
        message.error('业务线不存在')
        return
      }
      await businessLinesApi.update(record.id, {
        name: formData.name,
        description: formData.description,
        owner: formData.owner,
        contact: formData.contact,
        enabled: formData.enabled,
      })
      message.success('更新成功')
      modalVisible.value = false
      loadBusinessLines()
    } else {
      await businessLinesApi.create({
        name: formData.name,
        code: formData.code,
        description: formData.description,
        owner: formData.owner,
        contact: formData.contact,
        enabled: formData.enabled,
      })
      message.success('创建成功')
      modalVisible.value = false
      loadBusinessLines()
    }
  } catch (error: any) {
    if (error.errorFields) {
      // 表单验证错误
      return
    }
    message.error(error.message || '操作失败')
  }
}

// 取消
const handleCancel = () => {
  modalVisible.value = false
  formRef.value?.resetFields()
}

// 查看主机
const handleViewHosts = (record: BusinessLine) => {
  router.push({
    path: '/hosts',
    query: {
      business_line: record.code,
    },
  })
}

// 表单验证规则
const formRules = {
  name: [{ required: true, message: '请输入业务线名称', trigger: 'blur' }],
  code: [{ required: true, message: '请输入业务线代码', trigger: 'blur' }],
}

onMounted(() => {
  loadBusinessLines()
})
</script>

<style scoped>
.business-lines-page {
  width: 100%;
}

.page-header {
  margin-bottom: 24px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.filter-bar {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
  padding: 12px 16px;
  background: #F7F8FA;
  border-radius: 6px;
  border: 1px solid #f0f0f0;
}
</style>
