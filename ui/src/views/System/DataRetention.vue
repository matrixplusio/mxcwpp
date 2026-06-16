<template>
  <div class="data-retention">
    <a-card :bordered="false">
      <template #title>
        <span>数据保留策略</span>
        <a-tag color="blue" style="margin-left: 8px">ClickHouse TTL</a-tag>
      </template>
      <template #extra>
        <a-button :loading="loading" @click="loadList">
          <template #icon><ReloadOutlined /></template>
          刷新
        </a-button>
      </template>

      <a-alert
        message="修改保留天数后立即下发到 ClickHouse"
        description="ALTER TABLE ... MODIFY TTL 是元数据操作秒级完成，超期数据将在下次后台 merge 时清理。范围 1-3650 天。"
        type="info"
        show-icon
        style="margin-bottom: 16px"
      />

      <a-table
        :columns="columns"
        :data-source="items"
        :pagination="false"
        :loading="loading"
        row-key="ch_table"
        size="middle"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'retention_days'">
            <a-tag :color="daysColor(record.retention_days)">{{ record.retention_days }} 天</a-tag>
          </template>
          <template v-else-if="column.key === 'updated_at'">
            <span style="color: rgba(0,0,0,0.45); font-size: 12px">{{ record.updated_at }}</span>
          </template>
          <template v-else-if="column.key === 'actions'">
            <a-button type="link" size="small" @click="openEdit(record)">编辑</a-button>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal
      v-model:open="modalVisible"
      :title="`编辑保留策略 - ${editing?.display_name}`"
      :confirm-loading="submitLoading"
      ok-text="保存"
      cancel-text="取消"
      @ok="handleSubmit"
    >
      <a-form ref="formRef" :model="form" :rules="formRules" layout="vertical">
        <a-form-item label="表名">
          <a-input :value="editing?.ch_table" disabled />
        </a-form-item>
        <a-form-item label="描述">
          <a-textarea :value="editing?.description" disabled :rows="2" />
        </a-form-item>
        <a-form-item label="保留天数" name="retention_days">
          <a-input-number
            v-model:value="form.retention_days"
            :min="1"
            :max="3650"
            style="width: 200px"
          />
          <span style="margin-left: 8px; color: rgba(0,0,0,0.45)">天 (1-3650)</span>
        </a-form-item>
        <a-alert
          v-if="editing && form.retention_days < editing.retention_days"
          message="减少保留天数会删除老数据，请谨慎操作"
          type="warning"
          show-icon
        />
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ReloadOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import type { FormInstance } from 'ant-design-vue'
import { adminDataConfigApi, type RetentionPolicy } from '@/api/admin-data-config'

const loading = ref(false)
const items = ref<RetentionPolicy[]>([])
const modalVisible = ref(false)
const submitLoading = ref(false)
const editing = ref<RetentionPolicy | null>(null)
const formRef = ref<FormInstance>()
const form = reactive({ retention_days: 30 })
const formRules = {
  retention_days: [
    { required: true, message: '请输入保留天数', trigger: 'change' },
    { type: 'number' as const, min: 1, max: 3650, message: '范围 1-3650', trigger: 'change' },
  ],
}

const columns = [
  { title: '名称', dataIndex: 'display_name', key: 'display_name', width: 200 },
  { title: '表名', dataIndex: 'ch_table', key: 'ch_table', width: 220 },
  { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
  { title: '保留天数', key: 'retention_days', width: 120, align: 'center' as const },
  { title: '修改人', dataIndex: 'updated_by', key: 'updated_by', width: 100 },
  { title: '修改时间', key: 'updated_at', width: 180 },
  { title: '操作', key: 'actions', width: 80, fixed: 'right' as const },
]

const daysColor = (d: number) => {
  if (d <= 7) return 'orange'
  if (d <= 30) return 'blue'
  if (d <= 90) return 'cyan'
  if (d <= 180) return 'green'
  return 'purple'
}

const loadList = async () => {
  loading.value = true
  try {
    const res = await adminDataConfigApi.listPolicies()
    items.value = res.items ?? []
  } catch (e) {
    console.error('加载保留策略失败', e)
  } finally {
    loading.value = false
  }
}

const openEdit = (record: RetentionPolicy) => {
  editing.value = record
  form.retention_days = record.retention_days
  modalVisible.value = true
}

const handleSubmit = async () => {
  if (!editing.value) return
  try {
    await formRef.value?.validate()
    submitLoading.value = true
    await adminDataConfigApi.updatePolicy(editing.value.ch_table, form.retention_days)
    message.success(`${editing.value.display_name} 保留天数已更新为 ${form.retention_days} 天`)
    modalVisible.value = false
    loadList()
  } catch (e) {
    console.error('更新保留策略失败:', e)
  } finally {
    submitLoading.value = false
  }
}

onMounted(loadList)
</script>

<style scoped>
.data-retention {
  padding: 0;
}
</style>
