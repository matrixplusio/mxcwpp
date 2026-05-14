<template>
  <a-modal
    v-model:open="open"
    title="新建扫描任务"
    width="800px"
    @ok="handleSubmit"
    @cancel="handleCancel"
  >
    <a-form
      ref="formRef"
      :model="formData"
      :rules="rules"
      :label-col="{ span: 6 }"
      :wrapper-col="{ span: 18 }"
    >
      <a-form-item label="任务名称" name="name">
        <a-input v-model:value="formData.name" placeholder="请输入任务名称" />
      </a-form-item>
      <a-form-item label="任务类型" name="type">
        <a-radio-group v-model:value="formData.type">
          <a-radio value="manual">手动</a-radio>
          <a-radio value="scheduled">定时</a-radio>
        </a-radio-group>
      </a-form-item>

      <!-- 运行时类型选择（主机/容器） -->
      <a-form-item label="检查类型" name="runtime_type">
        <a-radio-group v-model:value="formData.runtime_type" @change="handleRuntimeTypeChange">
          <a-radio value="vm">
            <DesktopOutlined /> 主机/虚拟机
          </a-radio>
          <a-radio value="docker">
            <ContainerOutlined /> Docker 容器
          </a-radio>
          <a-radio value="k8s" disabled>
            <CloudServerOutlined /> Kubernetes（即将支持）
          </a-radio>
        </a-radio-group>
        <div class="form-tip">
          选择要扫描的运行时类型，策略将根据类型自动筛选
        </div>
      </a-form-item>

      <!-- 策略选择（多选） -->
      <a-form-item label="检查策略" name="policy_ids">
        <a-select
          v-model:value="formData.policy_ids"
          mode="multiple"
          placeholder="选择要执行的策略（可多选）"
          :loading="policiesLoading"
          :disabled="!formData.runtime_type"
          allow-clear
        >
          <a-select-option
            v-for="policy in filteredPolicies"
            :key="policy.id"
            :value="policy.id"
          >
            {{ policy.name }}
            <a-tag v-if="policy.runtime_types && policy.runtime_types.length > 0" size="small" style="margin-left: 8px;">
              {{ getRuntimeTypesLabel(policy.runtime_types) }}
            </a-tag>
          </a-select-option>
        </a-select>
        <div class="form-tip" v-if="formData.runtime_type && filteredPolicies.length === 0">
          <WarningOutlined style="color: #FF7D00;" /> 没有找到适用于当前运行时类型的策略
        </div>
      </a-form-item>

      <a-form-item label="目标类型" name="target_type">
        <a-radio-group v-model:value="formData.target_type" @change="handleTargetTypeChange">
          <a-radio value="all">全部{{ getRuntimeTypeLabel(formData.runtime_type) }}</a-radio>
          <a-radio value="business_line">按业务线</a-radio>
          <a-radio value="tags">按标签</a-radio>
          <a-radio value="os_family">按OS筛选</a-radio>
          <a-radio value="host_ids">指定{{ getRuntimeTypeLabel(formData.runtime_type) }}</a-radio>
        </a-radio-group>
      </a-form-item>

      <!-- 业务线选择 -->
      <a-form-item
        v-if="formData.target_type === 'business_line'"
        label="选择业务线"
        name="business_lines"
      >
        <a-select
          v-model:value="formData.business_lines"
          mode="multiple"
          placeholder="选择业务线"
          :loading="businessLinesLoading"
          style="width: 100%"
        >
          <a-select-option v-for="bl in businessLines" :key="bl.code" :value="bl.code">
            {{ bl.name }} ({{ bl.host_count || 0 }}台)
          </a-select-option>
        </a-select>
      </a-form-item>

      <!-- 标签选择 -->
      <a-form-item
        v-if="formData.target_type === 'tags'"
        label="选择标签"
        name="tags"
      >
        <a-select
          v-model:value="formData.tags"
          mode="multiple"
          placeholder="选择或输入标签"
          style="width: 100%"
          :options="tagOptions"
        />
      </a-form-item>

      <a-form-item
        v-if="formData.target_type === 'os_family'"
        label="操作系统"
        name="os_family"
      >
        <a-select
          v-model:value="formData.os_family"
          mode="multiple"
          placeholder="选择操作系统"
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

      <a-form-item
        v-if="formData.target_type === 'host_ids'"
        :label="getRuntimeTypeLabel(formData.runtime_type) + '列表'"
        name="host_ids"
      >
        <a-select
          v-model:value="formData.host_ids"
          mode="multiple"
          :placeholder="'选择' + getRuntimeTypeLabel(formData.runtime_type)"
          :loading="hostsLoading"
          show-search
          :filter-option="filterHostOption"
        >
          <a-select-option
            v-for="host in filteredHosts"
            :key="host.host_id"
            :value="host.host_id"
          >
            {{ host.hostname }} ({{ host.host_id.slice(0, 8) }}...)
            <a-tag v-if="host.runtime_type" size="small" style="margin-left: 8px;">
              {{ getRuntimeTypeLabel(host.runtime_type) }}
            </a-tag>
          </a-select-option>
        </a-select>
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, reactive, watch, onMounted, computed } from 'vue'
import { message } from 'ant-design-vue'
import {
  DesktopOutlined,
  ContainerOutlined,
  CloudServerOutlined,
  WarningOutlined,
} from '@ant-design/icons-vue'
import { tasksApi } from '@/api/tasks'
import { policiesApi } from '@/api/policies'
import { hostsApi } from '@/api/hosts'
import { businessLinesApi, type BusinessLine } from '@/api/business-lines'
import type { Policy, Host } from '@/api/types'
import type { FormInstance } from 'ant-design-vue/es/form'
import { OS_OPTIONS } from '@/constants/os'

const props = defineProps<{
  open: boolean
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
  success: []
}>()

const formRef = ref<FormInstance>()
const policies = ref<Policy[]>([])
const hosts = ref<Host[]>([])
const businessLines = ref<BusinessLine[]>([])
const policiesLoading = ref(false)
const hostsLoading = ref(false)
const businessLinesLoading = ref(false)
const osOptions = OS_OPTIONS

const formData = reactive({
  name: '',
  type: 'manual' as 'manual' | 'scheduled',
  runtime_type: 'vm' as 'vm' | 'docker' | 'k8s',
  policy_ids: [] as string[],
  target_type: 'all' as 'all' | 'business_line' | 'tags' | 'os_family' | 'host_ids',
  host_ids: [] as string[],
  os_family: [] as string[],
  business_lines: [] as string[],
  tags: [] as string[],
})

const rules = {
  name: [{ required: true, message: '请输入任务名称', trigger: 'blur' }],
  runtime_type: [{ required: true, message: '请选择检查类型', trigger: 'change' }],
  policy_ids: [
    {
      validator: (_rule: any, value: string[]) => {
        if (!value || value.length === 0) {
          return Promise.reject('请至少选择一个策略')
        }
        return Promise.resolve()
      },
      trigger: 'change',
    },
  ],
  host_ids: [
    {
      validator: (_rule: any, value: string[]) => {
        if (formData.target_type === 'host_ids' && (!value || value.length === 0)) {
          return Promise.reject('请至少选择一个目标')
        }
        return Promise.resolve()
      },
      trigger: 'change',
    },
  ],
  os_family: [
    {
      validator: (_rule: any, value: string[]) => {
        if (formData.target_type === 'os_family' && (!value || value.length === 0)) {
          return Promise.reject('请至少选择一个操作系统')
        }
        return Promise.resolve()
      },
      trigger: 'change',
    },
  ],
  business_lines: [
    {
      validator: (_rule: any, value: string[]) => {
        if (formData.target_type === 'business_line' && (!value || value.length === 0)) {
          return Promise.reject('请至少选择一个业务线')
        }
        return Promise.resolve()
      },
      trigger: 'change',
    },
  ],
  tags: [
    {
      validator: (_rule: any, value: string[]) => {
        if (formData.target_type === 'tags' && (!value || value.length === 0)) {
          return Promise.reject('请至少选择一个标签')
        }
        return Promise.resolve()
      },
      trigger: 'change',
    },
  ],
}

const open = computed({
  get: () => props.open,
  set: (value) => emit('update:open', value),
})

// 根据运行时类型筛选策略
const filteredPolicies = computed(() => {
  if (!formData.runtime_type) return []
  return policies.value.filter(policy => {
    // 如果策略没有设置 runtime_types，默认只适用于主机（vm）
    if (!policy.runtime_types || policy.runtime_types.length === 0) {
      return formData.runtime_type === 'vm'
    }
    return policy.runtime_types.includes(formData.runtime_type)
  })
})

// 标签选项（从主机中提取）
const tagOptions = computed(() => {
  const tags = new Set<string>()
  filteredHosts.value.forEach(h => {
    if (h.tags) {
      h.tags.forEach((t: string) => tags.add(t))
    }
  })
  return Array.from(tags).sort().map(t => ({ label: t, value: t }))
})

// 主机搜索过滤
const filterHostOption = (input: string, option: any) => {
  return option.children?.[0]?.children?.toLowerCase?.()?.includes(input.toLowerCase()) ?? false
}

// 根据运行时类型筛选主机
const filteredHosts = computed(() => {
  if (!formData.runtime_type) return hosts.value
  return hosts.value.filter(host => {
    // 根据运行时类型筛选
    if (formData.runtime_type === 'vm') {
      return host.runtime_type === 'vm' || !host.runtime_type
    }
    if (formData.runtime_type === 'docker') {
      return host.runtime_type === 'docker' || host.is_container
    }
    return true
  })
})

// 获取运行时类型标签
const getRuntimeTypeLabel = (runtimeType: string) => {
  const labels: Record<string, string> = {
    vm: '主机',
    docker: '容器',
    k8s: 'Pod',
  }
  return labels[runtimeType] || runtimeType
}

// 获取运行时类型列表标签
const getRuntimeTypesLabel = (runtimeTypes: string[]) => {
  if (!runtimeTypes || runtimeTypes.length === 0) return '通用'
  return runtimeTypes.map(rt => getRuntimeTypeLabel(rt)).join('/')
}

const loadPolicies = async () => {
  policiesLoading.value = true
  try {
    const response = await policiesApi.list({ enabled: true })
    policies.value = response.items
  } catch (error) {
    console.error('加载策略列表失败:', error)
  } finally {
    policiesLoading.value = false
  }
}

const loadHosts = async () => {
  hostsLoading.value = true
  try {
    const response = await hostsApi.list({ page_size: 500 })
    hosts.value = response.items
  } catch (error) {
    console.error('加载主机列表失败:', error)
  } finally {
    hostsLoading.value = false
  }
}

const loadBusinessLines = async () => {
  businessLinesLoading.value = true
  try {
    const response = await businessLinesApi.list({ page_size: 1000 }) as any
    businessLines.value = response.items || []
  } catch (error) {
    console.error('加载业务线列表失败:', error)
  } finally {
    businessLinesLoading.value = false
  }
}

const handleRuntimeTypeChange = () => {
  // 清空策略选择
  formData.policy_ids = []
  // 清空主机选择
  formData.host_ids = []
}

const handleTargetTypeChange = () => {
  formData.host_ids = []
  formData.os_family = []
  formData.business_lines = []
  formData.tags = []
}

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()

    // 根据目标类型构建目标配置（业务线/标签在前端转成 host_ids）
    let targetType: string = formData.target_type
    let targetHostIds: string[] | undefined
    let targetOsFamily: string[] | undefined

    if (formData.target_type === 'host_ids') {
      targetType = 'host_ids'
      targetHostIds = formData.host_ids
    } else if (formData.target_type === 'os_family') {
      targetType = 'os_family'
      targetOsFamily = formData.os_family
    } else if (formData.target_type === 'business_line') {
      targetType = 'host_ids'
      targetHostIds = filteredHosts.value
        .filter(h => h.business_line && formData.business_lines.includes(h.business_line))
        .map(h => h.host_id)
      if (targetHostIds.length === 0) {
        message.warning('所选业务线下没有符合检查类型的主机')
        return
      }
    } else if (formData.target_type === 'tags') {
      targetType = 'host_ids'
      targetHostIds = filteredHosts.value
        .filter(h => h.tags && h.tags.some((t: string) => formData.tags.includes(t)))
        .map(h => h.host_id)
      if (targetHostIds.length === 0) {
        message.warning('所选标签下没有符合检查类型的主机')
        return
      }
    }

    const targets: any = {
      type: targetType,
      host_ids: targetHostIds,
      os_family: targetOsFamily,
      runtime_type: formData.runtime_type,
    }

    await tasksApi.create({
      name: formData.name,
      type: formData.type,
      targets,
      policy_ids: formData.policy_ids,
    })
    message.success('任务创建成功')
    emit('success')
  } catch (error) {
    console.error('创建任务失败:', error)
  }
}

const handleCancel = () => {
  open.value = false
  // 重置表单
  formData.name = ''
  formData.type = 'manual'
  formData.runtime_type = 'vm'
  formData.policy_ids = []
  formData.target_type = 'all'
  formData.host_ids = []
  formData.os_family = []
  formData.business_lines = []
  formData.tags = []
}

watch(
  () => props.open,
  (open) => {
    if (open) {
      loadPolicies()
      loadHosts()
      loadBusinessLines()
    }
  }
)

onMounted(() => {
  loadPolicies()
  loadHosts()
  loadBusinessLines()
})
</script>

<style scoped>
.form-tip {
  font-size: 12px;
  color: #86909C;
  margin-top: 4px;
}
</style>
