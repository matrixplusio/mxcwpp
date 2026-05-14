<template>
  <a-modal
    :open="open"
    title="表达式模板管理"
    @cancel="$emit('update:open', false)"
    width="900px"
    :footer="null"
  >
    <div style="margin-bottom: 12px; display: flex; justify-content: flex-end;">
      <a-button type="primary" size="small" @click="handleAdd">新增模板</a-button>
    </div>

    <a-table
      :columns="columns"
      :data-source="templates"
      :loading="loading"
      size="small"
      row-key="id"
      :pagination="false"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'matchPolicy'">
          {{ record.matchPolicy === 'no_match_fail' ? '无匹配则失败' : '任一匹配则失败' }}
        </template>
        <template v-if="column.key === 'builtin'">
          <a-tag v-if="record.builtin" color="blue" :bordered="false">内置</a-tag>
          <a-tag v-else color="default" :bordered="false">自定义</a-tag>
        </template>
        <template v-if="column.key === 'action'">
          <a-space>
            <a-button type="link" size="small" @click="handleEdit(record)">编辑</a-button>
            <a-popconfirm title="确定删除此模板？" @confirm="handleDelete(record)">
              <a-button type="link" size="small" danger>删除</a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 编辑/新增子弹�� -->
    <a-modal
      :open="editVisible"
      :title="editingTemplate ? '编辑模板' : '新增模板'"
      :confirm-loading="saving"
      @ok="handleSave"
      @cancel="editVisible = false"
      width="700px"
    >
      <a-form :model="form" :label-col="{ span: 5 }" :wrapper-col="{ span: 18 }" style="margin-top: 16px">
        <a-form-item label="模板名称" :rules="[{ required: true }]">
          <a-input v-model:value="form.name" placeholder="模板名称" />
        </a-form-item>
        <a-form-item label="描述">
          <a-input v-model:value="form.description" placeholder="模板描述" />
        </a-form-item>
        <a-form-item label="资源类型" :rules="[{ required: true }]">
          <a-select v-model:value="form.resourceType" placeholder="选择 K8s 资源类型" @change="onResourceTypeChange">
            <a-select-opt-group label="Core">
              <a-select-option value="pods">Pods</a-select-option>
              <a-select-option value="services">Services</a-select-option>
              <a-select-option value="namespaces">Namespaces</a-select-option>
              <a-select-option value="nodes">Nodes</a-select-option>
              <a-select-option value="secrets">Secrets</a-select-option>
              <a-select-option value="configmaps">ConfigMaps</a-select-option>
              <a-select-option value="serviceaccounts">ServiceAccounts</a-select-option>
              <a-select-option value="persistentvolumes">PersistentVolumes</a-select-option>
            </a-select-opt-group>
            <a-select-opt-group label="Apps">
              <a-select-option value="deployments">Deployments</a-select-option>
              <a-select-option value="statefulsets">StatefulSets</a-select-option>
              <a-select-option value="daemonsets">DaemonSets</a-select-option>
            </a-select-opt-group>
            <a-select-opt-group label="RBAC">
              <a-select-option value="clusterroles">ClusterRoles</a-select-option>
              <a-select-option value="clusterrolebindings">ClusterRoleBindings</a-select-option>
              <a-select-option value="roles">Roles</a-select-option>
              <a-select-option value="rolebindings">RoleBindings</a-select-option>
            </a-select-opt-group>
            <a-select-opt-group label="Networking">
              <a-select-option value="networkpolicies">NetworkPolicies</a-select-option>
              <a-select-option value="ingresses">Ingresses</a-select-option>
            </a-select-opt-group>
            <a-select-opt-group label="Batch">
              <a-select-option value="cronjobs">CronJobs</a-select-option>
              <a-select-option value="jobs">Jobs</a-select-option>
            </a-select-opt-group>
            <a-select-opt-group label="Storage">
              <a-select-option value="storageclasses">StorageClasses</a-select-option>
            </a-select-opt-group>
            <a-select-opt-group label="Autoscaling">
              <a-select-option value="horizontalpodautoscalers">HorizontalPodAutoscalers</a-select-option>
            </a-select-opt-group>
            <a-select-opt-group label="Admission">
              <a-select-option value="validatingwebhookconfigurations">ValidatingWebhookConfigurations</a-select-option>
              <a-select-option value="mutatingwebhookconfigurations">MutatingWebhookConfigurations</a-select-option>
            </a-select-opt-group>
          </a-select>
        </a-form-item>
        <a-form-item label="命名空间">
          <a-radio-group v-model:value="form.namespace">
            <a-radio value="*">全部</a-radio>
            <a-radio value="!system">排除系统</a-radio>
            <a-radio value="">集群级</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="CEL 表达式" :rules="[{ required: true }]">
          <a-textarea
            v-model:value="form.expression"
            placeholder="输入 CEL 表达式"
            :rows="4"
            style="font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace; font-size: 13px;"
          />
        </a-form-item>
        <a-form-item label="匹配策略">
          <a-radio-group v-model:value="form.matchPolicy">
            <a-radio value="any_match_fail">任一匹配则失败</a-radio>
            <a-radio value="no_match_fail">无匹配则失败</a-radio>
          </a-radio-group>
        </a-form-item>
      </a-form>
    </a-modal>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { message } from 'ant-design-vue'
import { getExpressionTemplates, createExpressionTemplate, updateExpressionTemplate, deleteExpressionTemplate } from '@/api/kubeBaselineRules'
import type { ExpressionTemplate } from '@/api/kubeBaselineRules'

const apiGroupMap: Record<string, string> = {
  pods: '', services: '', namespaces: '', nodes: '', secrets: '', configmaps: '', serviceaccounts: '', persistentvolumes: '',
  deployments: 'apps', statefulsets: 'apps', daemonsets: 'apps',
  clusterroles: 'rbac.authorization.k8s.io', clusterrolebindings: 'rbac.authorization.k8s.io',
  roles: 'rbac.authorization.k8s.io', rolebindings: 'rbac.authorization.k8s.io',
  networkpolicies: 'networking.k8s.io', ingresses: 'networking.k8s.io',
  cronjobs: 'batch', jobs: 'batch',
  storageclasses: 'storage.k8s.io',
  horizontalpodautoscalers: 'autoscaling',
  validatingwebhookconfigurations: 'admissionregistration.k8s.io', mutatingwebhookconfigurations: 'admissionregistration.k8s.io',
}

const clusterScopedResources = new Set(['nodes', 'namespaces', 'clusterroles', 'clusterrolebindings', 'persistentvolumes', 'storageclasses', 'validatingwebhookconfigurations', 'mutatingwebhookconfigurations'])

const props = defineProps<{ open: boolean }>()
defineEmits<{ 'update:open': [value: boolean] }>()

const loading = ref(false)
const templates = ref<ExpressionTemplate[]>([])
const editVisible = ref(false)
const saving = ref(false)
const editingTemplate = ref<ExpressionTemplate | null>(null)

const form = ref({
  name: '',
  description: '',
  resourceType: '' as string | undefined,
  apiGroup: '',
  namespace: '!system',
  expression: '',
  matchPolicy: 'any_match_fail',
})

const columns = [
  { title: '名称', dataIndex: 'name', key: 'name', width: 160 },
  { title: '资源类型', dataIndex: 'resourceType', key: 'resourceType', width: 130 },
  { title: '匹配策略', key: 'matchPolicy', width: 130 },
  { title: '类型', key: 'builtin', width: 80 },
  { title: '操作', key: 'action', width: 120 },
]

const loadTemplates = async () => {
  loading.value = true
  try {
    templates.value = await getExpressionTemplates()
  } catch { /* handled */ }
  finally { loading.value = false }
}

watch(() => props.open, (val) => {
  if (val) loadTemplates()
})

function onResourceTypeChange(val: string) {
  if (val) {
    form.value.apiGroup = apiGroupMap[val] ?? ''
    form.value.namespace = clusterScopedResources.has(val) ? '' : '!system'
  }
}

function handleAdd() {
  editingTemplate.value = null
  form.value = { name: '', description: '', resourceType: undefined, apiGroup: '', namespace: '!system', expression: '', matchPolicy: 'any_match_fail' }
  editVisible.value = true
}

function handleEdit(record: ExpressionTemplate) {
  editingTemplate.value = record
  form.value = {
    name: record.name,
    description: record.description,
    resourceType: record.resourceType,
    apiGroup: record.apiGroup,
    namespace: record.namespace,
    expression: record.expression,
    matchPolicy: record.matchPolicy,
  }
  editVisible.value = true
}

async function handleSave() {
  if (!form.value.name || !form.value.resourceType || !form.value.expression) {
    message.warning('请填写必填字段')
    return
  }
  saving.value = true
  try {
    if (editingTemplate.value) {
      await updateExpressionTemplate(editingTemplate.value.id, {
        name: form.value.name,
        description: form.value.description,
        resourceType: form.value.resourceType,
        apiGroup: form.value.apiGroup,
        namespace: form.value.namespace,
        expression: form.value.expression,
        matchPolicy: form.value.matchPolicy,
      })
      message.success('模板已更新')
    } else {
      await createExpressionTemplate({
        name: form.value.name,
        description: form.value.description,
        resourceType: form.value.resourceType!,
        apiGroup: form.value.apiGroup,
        namespace: form.value.namespace,
        expression: form.value.expression,
        matchPolicy: form.value.matchPolicy,
      })
      message.success('模板已创建')
    }
    editVisible.value = false
    loadTemplates()
  } catch { /* handled */ }
  finally { saving.value = false }
}

async function handleDelete(record: ExpressionTemplate) {
  try {
    await deleteExpressionTemplate(record.id)
    message.success('模板已删除')
    loadTemplates()
  } catch { /* handled */ }
}
</script>
