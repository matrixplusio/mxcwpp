<template>
  <a-modal
    :open="open"
    :title="isEdit ? '编辑 FIM 策略' : '新建 FIM 策略'"
    :width="720"
    :confirm-loading="loading"
    @ok="handleSubmit"
    @cancel="$emit('update:open', false)"
  >
    <a-form :model="form" :rules="rules" ref="formRef" layout="vertical">
      <a-row :gutter="16">
        <a-col :span="12">
          <a-form-item label="策略名称" name="name">
            <a-input v-model:value="form.name" placeholder="请输入策略名称" />
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item label="检查间隔（小时）" name="check_interval_hours">
            <a-input-number
              v-model:value="form.check_interval_hours"
              :min="1"
              :max="720"
              style="width: 100%"
            />
          </a-form-item>
        </a-col>
      </a-row>

      <a-row :gutter="16">
        <a-col :span="12">
          <a-form-item label="超时升级时间（分钟）" name="escalation_timeout_min">
            <a-input-number
              v-model:value="form.escalation_timeout_min"
              :min="60"
              :max="43200"
              style="width: 100%"
              placeholder="默认 1440（24小时）"
            />
          </a-form-item>
        </a-col>
      </a-row>

      <a-form-item label="描述" name="description">
        <a-textarea v-model:value="form.description" :rows="2" placeholder="策略描述" />
      </a-form-item>

      <a-form-item label="监控路径" name="watch_paths" required>
        <div v-for="(wp, index) in form.watch_paths" :key="index" class="path-row">
          <a-input
            v-model:value="wp.path"
            placeholder="/etc/passwd"
            style="width: 40%"
          />
          <a-select v-model:value="wp.level" style="width: 20%; margin-left: 8px">
            <a-select-option value="NORMAL">NORMAL</a-select-option>
            <a-select-option value="CONTENT">CONTENT</a-select-option>
            <a-select-option value="PERMS">PERMS</a-select-option>
          </a-select>
          <a-input
            v-model:value="wp.comment"
            placeholder="说明"
            style="width: 30%; margin-left: 8px"
          />
          <a-button
            type="text"
            danger
            @click="removeWatchPath(index)"
            style="margin-left: 4px"
          >
            <DeleteOutlined />
          </a-button>
        </div>
        <a-button type="dashed" block @click="addWatchPath" style="margin-top: 8px">
          <PlusOutlined /> 添加监控路径
        </a-button>
      </a-form-item>

      <a-form-item label="排除路径">
        <div v-for="(_, index) in form.exclude_paths" :key="index" class="path-row">
          <a-input
            v-model:value="form.exclude_paths[index]"
            placeholder="/var/log"
            style="width: 90%"
          />
          <a-button
            type="text"
            danger
            @click="form.exclude_paths.splice(index, 1)"
            style="margin-left: 4px"
          >
            <DeleteOutlined />
          </a-button>
        </div>
        <a-button
          type="dashed"
          block
          @click="form.exclude_paths.push('')"
          style="margin-top: 8px"
        >
          <PlusOutlined /> 添加排除路径
        </a-button>
      </a-form-item>

      <a-row :gutter="16">
        <a-col :span="12">
          <a-form-item label="目标范围">
            <a-select v-model:value="form.target_type">
              <a-select-option value="all">所有主机</a-select-option>
              <a-select-option value="host_ids">指定主机</a-select-option>
            </a-select>
          </a-form-item>
        </a-col>
        <a-col :span="12">
          <a-form-item label="启用状态">
            <a-switch v-model:checked="form.enabled" />
          </a-form-item>
        </a-col>
      </a-row>
    </a-form>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import type { FormInstance } from 'ant-design-vue'
import { fimApi } from '@/api/fim'
import type { FIMPolicy } from '@/api/types'

const props = defineProps<{
  open: boolean
  policy?: FIMPolicy | null
}>()

const emit = defineEmits<{
  (e: 'update:open', value: boolean): void
  (e: 'success'): void
}>()

const isEdit = ref(false)
const loading = ref(false)
const formRef = ref<FormInstance>()

const getDefaultForm = () => ({
  name: '',
  description: '',
  watch_paths: [{ path: '', level: 'NORMAL', comment: '' }],
  exclude_paths: [] as string[],
  check_interval_hours: 24,
  escalation_timeout_min: 1440,
  target_type: 'all',
  enabled: true,
})

const form = ref(getDefaultForm())

const rules = {
  name: [{ required: true, message: '请输入策略名称', trigger: 'blur' }],
}

watch(
  () => props.open,
  (val) => {
    if (val) {
      if (props.policy) {
        isEdit.value = true
        form.value = {
          name: props.policy.name,
          description: props.policy.description,
          watch_paths: props.policy.watch_paths?.length
            ? props.policy.watch_paths.map((wp) => ({ ...wp }))
            : [{ path: '', level: 'NORMAL', comment: '' }],
          exclude_paths: props.policy.exclude_paths ? [...props.policy.exclude_paths] : [],
          check_interval_hours: props.policy.check_interval_hours || 24,
          escalation_timeout_min: props.policy.escalation_timeout_min || 1440,
          target_type: props.policy.target_type || 'all',
          enabled: props.policy.enabled,
        }
      } else {
        isEdit.value = false
        form.value = getDefaultForm()
      }
    }
  }
)

const addWatchPath = () => {
  form.value.watch_paths.push({ path: '', level: 'NORMAL', comment: '' })
}

const removeWatchPath = (index: number) => {
  if (form.value.watch_paths.length > 1) {
    form.value.watch_paths.splice(index, 1)
  }
}

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()
    loading.value = true

    const watchPaths = form.value.watch_paths.filter((wp) => wp.path.trim() !== '')
    if (watchPaths.length === 0) {
      message.error('至少需要一个监控路径')
      return
    }

    const excludePaths = form.value.exclude_paths.filter((p) => p.trim() !== '')

    const data = {
      name: form.value.name,
      description: form.value.description,
      watch_paths: watchPaths,
      exclude_paths: excludePaths,
      check_interval_hours: form.value.check_interval_hours,
      escalation_timeout_min: form.value.escalation_timeout_min,
      target_type: form.value.target_type,
      enabled: form.value.enabled,
    }

    if (isEdit.value && props.policy) {
      await fimApi.updatePolicy(props.policy.policy_id, data)
      message.success('策略更新成功')
    } else {
      await fimApi.createPolicy(data)
      message.success('策略创建成功')
    }

    emit('update:open', false)
    emit('success')
  } catch (error: any) {
    if (!error?.errorFields) {
      message.error('操作失败')
    }
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.path-row {
  display: flex;
  align-items: center;
  margin-bottom: 8px;
}
</style>
