<template>
  <a-modal
    :open="open"
    :title="isEdit ? '编辑基线规则' : '新增基线规则'"
    :confirm-loading="loading"
    @ok="handleOk"
    @cancel="$emit('update:open', false)"
    width="800px"
  >
    <a-form :model="form" :label-col="{ span: 5 }" :wrapper-col="{ span: 18 }" style="margin-top: 16px">
      <a-form-item label="检查编号" :rules="[{ required: true }]">
        <a-input v-model:value="form.checkId" placeholder="例如 CUSTOM-001" :disabled="isEdit && editRule?.builtin" />
      </a-form-item>
      <a-form-item label="检查名称" :rules="[{ required: true }]">
        <a-input v-model:value="form.checkName" placeholder="检查项名称" />
      </a-form-item>
      <a-form-item label="检查分类" :rules="[{ required: true }]">
        <a-select v-model:value="form.category" placeholder="选择分类">
          <a-select-option value="RBAC">RBAC</a-select-option>
          <a-select-option value="Pod Security">Pod Security</a-select-option>
          <a-select-option value="Network">Network</a-select-option>
          <a-select-option value="Secrets & Config">Secrets & Config</a-select-option>
          <a-select-option value="Workload">Workload</a-select-option>
          <a-select-option value="Node">Node</a-select-option>
          <a-select-option value="Cluster Config">Cluster Config</a-select-option>
          <a-select-option value="Supply Chain">Supply Chain</a-select-option>
          <a-select-option value="Runtime">Runtime</a-select-option>
        </a-select>
      </a-form-item>
      <a-form-item label="严重级别" :rules="[{ required: true }]">
        <a-select v-model:value="form.severity" placeholder="选择级别">
          <a-select-option value="critical">紧急</a-select-option>
          <a-select-option value="high">高危</a-select-option>
          <a-select-option value="medium">中危</a-select-option>
          <a-select-option value="low">低危</a-select-option>
        </a-select>
      </a-form-item>
      <a-form-item label="描述">
        <a-textarea v-model:value="form.description" placeholder="检查项描述" :rows="2" />
      </a-form-item>
      <a-form-item label="修复建议">
        <a-textarea v-model:value="form.remediation" placeholder="修复建议" :rows="2" />
      </a-form-item>
      <a-form-item label="参考标准">
        <a-input v-model:value="form.benchmark" placeholder="例如 CIS Kubernetes Benchmark 1.8" />
      </a-form-item>
    </a-form>

    <!-- CEL 检查配置 -->
    <a-divider>检查配置</a-divider>

    <a-alert v-if="isEdit && editRule?.builtin && editRule?.hasCheckFunc" type="info" message="此规则有内置检查函数，如同时配置 CEL 表达式，执行时内置函数优先" show-icon style="margin-bottom: 16px;" :banner="true" />

      <a-form :label-col="{ span: 5 }" :wrapper-col="{ span: 18 }">
        <a-form-item label="资源类型">
          <a-select v-model:value="checkConfig.resourceType" placeholder="选择 K8s 资源类型" allow-clear @change="onResourceTypeChange">
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
          <a-radio-group v-model:value="checkConfig.namespace">
            <a-radio value="*">全部</a-radio>
            <a-radio value="!system">排除系统</a-radio>
            <a-radio value="">集群级</a-radio>
          </a-radio-group>
        </a-form-item>

        <a-form-item label="CEL 表达式">
          <div style="display: flex; gap: 8px; margin-bottom: 8px;">
            <a-dropdown :trigger="['click']">
              <a-button size="small">表达式模板</a-button>
              <template #overlay>
                <a-menu @click="onSelectTemplate">
                  <a-menu-item v-for="(t, idx) in templates" :key="idx">
                    <div>{{ t.name }}</div>
                    <div style="font-size: 12px; color: #86909C;">{{ t.description }}</div>
                  </a-menu-item>
                </a-menu>
              </template>
            </a-dropdown>
            <a-button size="small" @click="handleValidate" :loading="validating">验证表达式</a-button>
            <a-button size="small" @click="templateModalVisible = true">管理模板</a-button>
          </div>
          <a-textarea
            v-model:value="checkConfig.expression"
            placeholder='例如: resource.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true)'
            :rows="4"
            style="font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace; font-size: 13px;"
          />
          <a-alert v-if="validateResult !== null" :type="validateResult.valid ? 'success' : 'error'" :message="validateResult.valid ? '表达式语法正确' : validateResult.error" show-icon style="margin-top: 8px;" :banner="true" />
        </a-form-item>

        <a-form-item label="匹配策略">
          <a-radio-group v-model:value="checkConfig.matchPolicy">
            <a-radio value="any_match_fail">任一匹配则失败（检测违规资源）</a-radio>
            <a-radio value="no_match_fail">无匹配则失败（检测必需资源）</a-radio>
          </a-radio-group>
        </a-form-item>

        <a-form-item :wrapper-col="{ offset: 5, span: 18 }">
          <div style="font-size: 12px; color: #86909C; line-height: 1.8;">
            可用变量：<code>resource</code>（资源对象）、<code>name</code>、<code>namespace</code>、<code>labels</code>、<code>annotations</code><br/>
            使用 <code>has(field)</code> 检查可选字段是否存在，使用 <code>.exists()</code> 遍历数组
          </div>
        </a-form-item>
      </a-form>

    <!-- 模板管理弹窗 -->
    <KubeExpressionTemplateModal v-model:open="templateModalVisible" @update:open="onTemplateModalClose" />
  </a-modal>
</template>

<script setup lang="ts">
import { ref, watch, reactive, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import KubeExpressionTemplateModal from './KubeExpressionTemplateModal.vue'
import { createRule, updateRule, validateExpression, getExpressionTemplates } from '@/api/kubeBaselineRules'
import type { KubeBaselineRule, ExpressionTemplate, ValidateResult } from '@/api/kubeBaselineRules'

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

const props = defineProps<{
  open: boolean
  editRule: KubeBaselineRule | null
}>()

const emit = defineEmits<{
  'update:open': [value: boolean]
  'saved': []
}>()

const isEdit = ref(false)
const loading = ref(false)
const validating = ref(false)
const validateResult = ref<ValidateResult | null>(null)
const templates = ref<ExpressionTemplate[]>([])
const templateModalVisible = ref(false)

const form = reactive({
  checkId: '',
  checkName: '',
  category: '' as string | undefined,
  severity: '' as string | undefined,
  description: '',
  remediation: '',
  benchmark: '',
})

const checkConfig = reactive({
  resourceType: '' as string | undefined,
  apiGroup: '',
  namespace: '!system',
  expression: '',
  matchPolicy: 'any_match_fail' as string,
})

watch(() => props.open, (val) => {
  if (val) {
    validateResult.value = null
    if (props.editRule) {
      isEdit.value = true
      form.checkId = props.editRule.checkId
      form.checkName = props.editRule.checkName
      form.category = props.editRule.category
      form.severity = props.editRule.severity
      form.description = props.editRule.description
      form.remediation = props.editRule.remediation
      form.benchmark = props.editRule.benchmark
      // 加载 CheckConfig
      if (props.editRule.checkConfig) {
        checkConfig.resourceType = props.editRule.checkConfig.resourceType
        checkConfig.apiGroup = props.editRule.checkConfig.apiGroup
        checkConfig.namespace = props.editRule.checkConfig.namespace
        checkConfig.expression = props.editRule.checkConfig.expression
        checkConfig.matchPolicy = props.editRule.checkConfig.matchPolicy
      } else {
        resetCheckConfig()
      }
    } else {
      isEdit.value = false
      form.checkId = ''
      form.checkName = ''
      form.category = undefined
      form.severity = undefined
      form.description = ''
      form.remediation = ''
      form.benchmark = ''
      resetCheckConfig()
    }
  }
})

function resetCheckConfig() {
  checkConfig.resourceType = undefined
  checkConfig.apiGroup = ''
  checkConfig.namespace = '!system'
  checkConfig.expression = ''
  checkConfig.matchPolicy = 'any_match_fail'
}

function onResourceTypeChange(val: string) {
  if (val) {
    checkConfig.apiGroup = apiGroupMap[val] ?? ''
    checkConfig.namespace = clusterScopedResources.has(val) ? '' : '!system'
  }
}

function onSelectTemplate(info: { key: string }) {
  const t = templates.value[Number(info.key)]
  if (t) {
    checkConfig.resourceType = t.resourceType
    checkConfig.apiGroup = t.apiGroup || apiGroupMap[t.resourceType] || ''
    checkConfig.namespace = t.namespace || '!system'
    checkConfig.expression = t.expression
    checkConfig.matchPolicy = t.matchPolicy || 'any_match_fail'
    validateResult.value = null
  }
}

async function onTemplateModalClose(val: boolean) {
  templateModalVisible.value = val
  if (!val) {
    // 模板管理弹窗关闭时刷新模板列表
    try { templates.value = await getExpressionTemplates() } catch { /* ignore */ }
  }
}

const handleValidate = async () => {
  if (!checkConfig.expression.trim()) {
    message.warning('请先输入 CEL 表达式')
    return
  }
  validating.value = true
  try {
    const res = await validateExpression(checkConfig.expression)
    validateResult.value = res
  } catch {
    validateResult.value = { valid: false, error: '验证请求失败' }
  } finally {
    validating.value = false
  }
}

const handleOk = async () => {
  if (!form.checkId || !form.checkName || !form.category || !form.severity) {
    message.warning('请填写必填字段')
    return
  }

  // 构建 checkConfig（仅在有表达式时包含）
  const hasExpression = checkConfig.resourceType && checkConfig.expression.trim()
  const configPayload = hasExpression ? {
    resourceType: checkConfig.resourceType!,
    apiGroup: checkConfig.apiGroup,
    namespace: checkConfig.namespace,
    expression: checkConfig.expression.trim(),
    matchPolicy: checkConfig.matchPolicy as 'any_match_fail' | 'no_match_fail',
  } : null

  loading.value = true
  try {
    if (isEdit.value && props.editRule) {
      await updateRule(props.editRule.id, {
        checkName: form.checkName,
        category: form.category,
        severity: form.severity,
        description: form.description,
        remediation: form.remediation,
        benchmark: form.benchmark,
        checkConfig: configPayload,
      })
      message.success('规则已更新')
    } else {
      await createRule({
        checkId: form.checkId,
        checkName: form.checkName,
        category: form.category!,
        severity: form.severity!,
        description: form.description,
        remediation: form.remediation,
        benchmark: form.benchmark,
        checkConfig: configPayload,
      })
      message.success('规则已创建')
    }
    emit('update:open', false)
    emit('saved')
  } catch {
    // apiClient 已处理错误提示
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  try {
    templates.value = await getExpressionTemplates()
  } catch { /* ignore */ }
})
</script>
