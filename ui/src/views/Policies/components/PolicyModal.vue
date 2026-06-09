<template>
  <a-modal
    v-model:open="visible"
    :title="policy ? '编辑策略' : '新建策略'"
    width="900px"
    @ok="handleSubmit"
    @cancel="handleCancel"
  >
    <a-form
      ref="formRef"
      :model="formData"
      :rules="rules"
      :label-col="{ span: 5 }"
      :wrapper-col="{ span: 19 }"
    >
      <a-form-item label="策略ID" name="id">
        <a-input
          v-model:value="formData.id"
          :disabled="!!policy"
          placeholder="请输入策略ID"
        />
      </a-form-item>
      <a-form-item label="策略名称" name="name">
        <a-input v-model:value="formData.name" placeholder="请输入策略名称" />
      </a-form-item>
      <a-form-item label="所属策略组" name="group_id">
        <a-select
          v-model:value="formData.group_id"
          placeholder="选择所属策略组（可选）"
          allow-clear
          :loading="groupsLoading"
        >
          <a-select-option v-for="group in policyGroups" :key="group.id" :value="group.id">
            {{ group.name }}
          </a-select-option>
        </a-select>
      </a-form-item>
      <a-form-item label="版本" name="version">
        <a-input v-model:value="formData.version" placeholder="请输入版本号" />
      </a-form-item>
      <a-form-item label="描述" name="description">
        <a-textarea
          v-model:value="formData.description"
          :rows="3"
          placeholder="请输入策略描述"
        />
      </a-form-item>
      <a-form-item label="适用环境" name="runtime_types">
        <a-checkbox-group v-model:value="formData.runtime_types">
          <a-checkbox value="vm">主机/虚拟机</a-checkbox>
          <a-checkbox value="docker">Docker 容器</a-checkbox>
          <a-checkbox value="k8s" disabled>Kubernetes（即将支持）</a-checkbox>
        </a-checkbox-group>
        <div class="form-tip">选择此策略适用的运行环境，不选表示全部适用。规则会自动继承策略的设置。</div>
      </a-form-item>
      <a-form-item label="适用OS" name="os_family">
        <a-select
          v-model:value="formData.os_family"
          mode="multiple"
          placeholder="选择适用的操作系统"
          @change="handleOSFamilyChange"
        >
          <a-select-option
            v-for="os in osOptions"
            :key="os.value"
            :value="os.value"
          >
            {{ os.label }}
          </a-select-option>
        </a-select>
      </a-form-item>
      <a-form-item label="OS版本要求" name="os_requirements">
        <div class="os-requirements-list">
          <div
            v-for="(req, index) in formData.os_requirements"
            :key="index"
            class="os-requirement-item"
          >
            <a-tag color="blue">{{ getOSFamilyLabel(req.os_family) }}</a-tag>
            <span class="version-inputs">
              <a-input
                v-model:value="req.min_version"
                placeholder="最小版本"
                style="width: 100px"
                size="small"
              />
              <span class="version-separator">~</span>
              <a-input
                v-model:value="req.max_version"
                placeholder="最大版本"
                style="width: 100px"
                size="small"
              />
            </span>
            <a-button type="text" danger size="small" @click="removeOSRequirement(index)">
              <DeleteOutlined />
            </a-button>
          </div>
          <div v-if="formData.os_requirements.length === 0" class="no-requirements">
            请先选择适用的操作系统
          </div>
        </div>
        <div class="form-tip">配置每个OS的版本范围（留空表示不限制）</div>
      </a-form-item>
      <a-form-item label="启用状态" name="enabled">
        <a-switch v-model:checked="formData.enabled" />
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, reactive, watch, computed } from 'vue'
import { DeleteOutlined } from '@ant-design/icons-vue'
import { policiesApi } from '@/api/policies'
import { policyGroupsApi } from '@/api/policy-groups'
import type { Policy, PolicyGroup, OSRequirement } from '@/api/types'
import type { FormInstance } from 'ant-design-vue/es/form'
import { OS_OPTIONS, getOSFamilyLabel } from '@/constants/os'

const props = defineProps<{
  visible: boolean
  policy?: Policy | null
  defaultGroupId?: string
}>()

const emit = defineEmits<{
  'update:visible': [value: boolean]
  success: []
}>()

const formRef = ref<FormInstance>()
const policyGroups = ref<PolicyGroup[]>([])
const groupsLoading = ref(false)

const formData = reactive({
  id: '',
  name: '',
  group_id: '' as string | undefined,
  version: '',
  description: '',
  runtime_types: ['vm'] as string[], // 默认仅主机
  os_family: [] as string[],
  os_version: '',
  os_requirements: [] as OSRequirement[],
  enabled: true,
})

const rules = {
  id: [{ required: true, message: '请输入策略ID', trigger: 'blur' }],
  name: [{ required: true, message: '请输入策略名称', trigger: 'blur' }],
}

const osOptions = OS_OPTIONS

// 当 OS 列表变化时，更新 OS 版本要求
const handleOSFamilyChange = (selectedFamilies: string[]) => {
  // 移除已不在选中列表中的 OS 要求
  formData.os_requirements = formData.os_requirements.filter(
    req => selectedFamilies.includes(req.os_family)
  )

  // 添加新选中的 OS
  selectedFamilies.forEach(family => {
    const exists = formData.os_requirements.some(req => req.os_family === family)
    if (!exists) {
      formData.os_requirements.push({
        os_family: family,
        min_version: '',
        max_version: '',
      })
    }
  })
}

const removeOSRequirement = (index: number) => {
  const removed = formData.os_requirements[index]
  formData.os_requirements.splice(index, 1)
  // 同时从 os_family 中移除
  const familyIndex = formData.os_family.indexOf(removed.os_family)
  if (familyIndex !== -1) {
    formData.os_family.splice(familyIndex, 1)
  }
}

// 加载策略组列表
const loadPolicyGroups = async () => {
  groupsLoading.value = true
  try {
    const response = await policyGroupsApi.list() as any
    policyGroups.value = response.data?.items || response.items || []
  } catch (error) {
    console.error('加载策略组列表失败:', error)
  } finally {
    groupsLoading.value = false
  }
}

watch(
  () => props.visible,
  (visible) => {
    if (visible) {
      // 加载策略组列表
      if (policyGroups.value.length === 0) {
        loadPolicyGroups()
      }

      if (props.policy) {
        // 编辑模式，填充数据
        formData.id = props.policy.id
        formData.name = props.policy.name
        formData.group_id = props.policy.group_id || undefined
        formData.version = props.policy.version || ''
        formData.description = props.policy.description || ''
        // 兼容旧的 target_type 字段
        if (props.policy.runtime_types && props.policy.runtime_types.length > 0) {
          formData.runtime_types = [...props.policy.runtime_types]
        } else if (props.policy.target_type === 'host') {
          formData.runtime_types = ['vm']
        } else if (props.policy.target_type === 'container') {
          formData.runtime_types = ['docker']
        } else {
          formData.runtime_types = ['vm'] // 默认主机
        }
        formData.os_family = [...props.policy.os_family]
        formData.os_version = props.policy.os_version || ''
        formData.os_requirements = props.policy.os_requirements
          ? [...props.policy.os_requirements]
          : formData.os_family.map(family => ({ os_family: family, min_version: '', max_version: '' }))
        formData.enabled = props.policy.enabled
      } else {
        // 新建模式，重置表单
        formData.id = ''
        formData.name = ''
        formData.group_id = props.defaultGroupId || undefined
        formData.version = ''
        formData.description = ''
        formData.runtime_types = ['vm'] // 默认仅主机
        formData.os_family = []
        formData.os_version = ''
        formData.os_requirements = []
        formData.enabled = true
      }
    }
  },
  { immediate: true }
)

const visible = computed({
  get: () => props.visible,
  set: (value) => emit('update:visible', value),
})

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()

    // 清理空的版本要求
    const cleanedRequirements = formData.os_requirements
      .filter(req => req.min_version || req.max_version)
      .map(req => ({
        os_family: req.os_family,
        min_version: req.min_version || undefined,
        max_version: req.max_version || undefined,
      }))

    if (props.policy) {
      // 更新策略
      await policiesApi.update(props.policy.id, {
        name: formData.name,
        group_id: formData.group_id || undefined,
        version: formData.version,
        description: formData.description,
        runtime_types: formData.runtime_types.length > 0 ? formData.runtime_types : undefined,
        os_family: formData.os_family,
        os_version: formData.os_version,
        os_requirements: cleanedRequirements.length > 0 ? cleanedRequirements : undefined,
        enabled: formData.enabled,
      })
    } else {
      // 创建策略
      await policiesApi.create({
        id: formData.id,
        name: formData.name,
        group_id: formData.group_id || undefined,
        version: formData.version,
        description: formData.description,
        runtime_types: formData.runtime_types.length > 0 ? formData.runtime_types : undefined,
        os_family: formData.os_family,
        os_version: formData.os_version,
        os_requirements: cleanedRequirements.length > 0 ? cleanedRequirements : undefined,
        enabled: formData.enabled,
      })
    }
    emit('success')
  } catch (error) {
    console.error('保存策略失败:', error)
  }
}

const handleCancel = () => {
  visible.value = false
}
</script>

<style scoped>
.form-tip {
  font-size: 12px;
  color: var(--mxsec-text-3);
  margin-top: 4px;
}

.os-requirements-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.os-requirement-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 12px;
  background: var(--mxsec-fill-1);
  border-radius: 6px;
}

.version-inputs {
  display: flex;
  align-items: center;
  gap: 8px;
}

.version-separator {
  color: var(--mxsec-text-3);
}

.no-requirements {
  color: var(--mxsec-text-3);
  font-size: 13px;
  padding: 8px 0;
}
</style>
