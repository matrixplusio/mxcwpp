<template>
  <div class="feature-flags">
    <a-card :bordered="false">
      <template #title>
        <span>功能开关</span>
        <a-tag color="orange" style="margin-left: 8px">需重启服务生效</a-tag>
      </template>
      <template #extra>
        <a-button :loading="loading" @click="loadList">
          <template #icon><ReloadOutlined /></template>
          刷新
        </a-button>
      </template>

      <a-alert
        message="修改后需重启 consumer 或 manager 等相关服务才能生效"
        description="data_source.* 类 flag 控制各表数据存储位置 (mysql/ch)。切换前必须确认 CH 表已建好且历史数据已迁移 (用 ETL 工具)。"
        type="warning"
        show-icon
        style="margin-bottom: 16px"
      />

      <a-table
        :columns="columns"
        :data-source="items"
        :pagination="false"
        :loading="loading"
        row-key="key"
        size="middle"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'value'">
            <a-tag :color="record.value === 'ch' ? 'green' : 'blue'">{{ record.value }}</a-tag>
            <span
              v-if="record.value !== record.default_value"
              style="margin-left: 4px; color: rgba(0,0,0,0.45); font-size: 12px"
            >
              (默认 {{ record.default_value }})
            </span>
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
      :title="`编辑功能开关 - ${editing?.key}`"
      :confirm-loading="submitLoading"
      ok-text="保存"
      cancel-text="取消"
      @ok="handleSubmit"
    >
      <a-form ref="formRef" :model="form" :rules="formRules" layout="vertical">
        <a-form-item label="开关名">
          <a-input :value="editing?.key" disabled />
        </a-form-item>
        <a-form-item label="描述">
          <a-textarea :value="editing?.description" disabled :rows="2" />
        </a-form-item>
        <a-form-item label="当前值">
          <a-tag :color="editing?.value === 'ch' ? 'green' : 'blue'">{{ editing?.value }}</a-tag>
        </a-form-item>
        <a-form-item label="新值" name="value">
          <a-radio-group v-model:value="form.value">
            <a-radio-button value="mysql">mysql</a-radio-button>
            <a-radio-button value="ch">ch</a-radio-button>
          </a-radio-group>
        </a-form-item>
        <a-alert
          v-if="editing && form.value === 'ch' && editing.value !== 'ch'"
          message="切换到 ClickHouse 前请确认"
          description="1. CH 表已建好 (ensureSchemas 已跑) 2. 历史数据已通过 ETL 迁移 3. 准备好重启相关服务"
          type="warning"
          show-icon
        />
        <a-alert
          v-if="editing && form.value === 'mysql' && editing.value === 'ch'"
          message="回滚到 MySQL"
          description="数据切换期间产生的 CH 写入数据不会自动回填到 MySQL，可能造成数据缺失"
          type="error"
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
import { adminDataConfigApi, type FeatureFlag } from '@/api/admin-data-config'

const loading = ref(false)
const items = ref<FeatureFlag[]>([])
const modalVisible = ref(false)
const submitLoading = ref(false)
const editing = ref<FeatureFlag | null>(null)
const formRef = ref<FormInstance>()
const form = reactive({ value: 'mysql' })
const formRules = {
  value: [{ required: true, message: '请选择值', trigger: 'change' }],
}

const columns = [
  { title: '开关名', dataIndex: 'key', key: 'key', width: 280 },
  { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
  { title: '当前值', key: 'value', width: 200 },
  { title: '修改人', dataIndex: 'updated_by', key: 'updated_by', width: 100 },
  { title: '修改时间', key: 'updated_at', width: 180 },
  { title: '操作', key: 'actions', width: 80, fixed: 'right' as const },
]

const loadList = async () => {
  loading.value = true
  try {
    const res = await adminDataConfigApi.listFlags()
    items.value = res.items ?? []
  } catch (e) {
    console.error('加载功能开关失败', e)
  } finally {
    loading.value = false
  }
}

const openEdit = (record: FeatureFlag) => {
  editing.value = record
  form.value = record.value
  modalVisible.value = true
}

const handleSubmit = async () => {
  if (!editing.value) return
  try {
    await formRef.value?.validate()
    submitLoading.value = true
    await adminDataConfigApi.updateFlag(editing.value.key, form.value)
    message.success(`${editing.value.key} 已更新为 ${form.value}，请重启相关服务生效`)
    modalVisible.value = false
    loadList()
  } catch (e) {
    console.error('更新功能开关失败:', e)
  } finally {
    submitLoading.value = false
  }
}

onMounted(loadList)
</script>

<style scoped>
.feature-flags {
  padding: 0;
}
</style>
