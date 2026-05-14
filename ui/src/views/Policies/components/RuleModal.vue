<template>
  <a-modal
    v-model:open="visible"
    :title="rule ? '编辑检查规则' : '新建检查规则'"
    width="900px"
    @ok="handleSubmit"
    @cancel="handleCancel"
    :confirm-loading="loading"
  >
    <a-form
      ref="formRef"
      :model="formData"
      :rules="rules"
      :label-col="{ span: 5 }"
      :wrapper-col="{ span: 19 }"
    >
      <!-- 基本信息 -->
      <a-divider orientation="left">基本信息</a-divider>

      <a-form-item label="规则ID" name="rule_id">
        <a-input
          v-model:value="formData.rule_id"
          :disabled="!!rule"
          placeholder="例如: LINUX_SSH_001"
        />
        <template #extra>
          <span class="form-tip">建议格式: LINUX_类别_序号</span>
        </template>
      </a-form-item>

      <a-form-item label="规则标题" name="title">
        <a-input
          v-model:value="formData.title"
          placeholder="简短描述检查内容，例如：禁止 root 远程登录"
        />
      </a-form-item>

      <a-form-item label="分类" name="category">
        <a-select v-model:value="formData.category" placeholder="选择规则分类">
          <a-select-option value="ssh">SSH 配置</a-select-option>
          <a-select-option value="password">密码策略</a-select-option>
          <a-select-option value="account">账户安全</a-select-option>
          <a-select-option value="file">文件权限</a-select-option>
          <a-select-option value="kernel">内核参数</a-select-option>
          <a-select-option value="service">服务状态</a-select-option>
          <a-select-option value="audit">审计日志</a-select-option>
          <a-select-option value="network">网络安全</a-select-option>
          <a-select-option value="other">其他</a-select-option>
        </a-select>
      </a-form-item>

      <a-form-item label="严重级别" name="severity">
        <a-select v-model:value="formData.severity" placeholder="选择严重级别">
          <a-select-option value="critical">
            <a-tag color="red">严重</a-tag> 可能导致系统被完全控制
          </a-select-option>
          <a-select-option value="high">
            <a-tag color="orange">高危</a-tag> 可能导致数据泄露或权限提升
          </a-select-option>
          <a-select-option value="medium">
            <a-tag color="gold">中危</a-tag> 可能导致信息泄露或拒绝服务
          </a-select-option>
          <a-select-option value="low">
            <a-tag color="blue">低危</a-tag> 安全加固建议
          </a-select-option>
        </a-select>
      </a-form-item>

      <a-form-item label="规则描述" name="description">
        <a-textarea
          v-model:value="formData.description"
          :rows="2"
          placeholder="详细描述检查内容和不合规的风险"
        />
      </a-form-item>

      <a-form-item label="适用环境" name="runtime_types">
        <a-checkbox-group v-model:value="formData.runtime_types">
          <a-checkbox value="vm">物理机/虚拟机</a-checkbox>
          <a-checkbox value="docker">Docker 容器</a-checkbox>
          <a-checkbox value="k8s">K8s Pod</a-checkbox>
        </a-checkbox-group>
        <template #extra>
          <span class="form-tip">留空表示继承策略设置；勾选后仅在对应环境执行此规则</span>
        </template>
      </a-form-item>

      <!-- 检查配置 -->
      <a-divider orientation="left">检查配置</a-divider>

      <a-form-item label="条件逻辑" name="condition">
        <a-radio-group v-model:value="formData.check_config.condition">
          <a-radio value="all">全部满足 (AND)</a-radio>
          <a-radio value="any">任一满足 (OR)</a-radio>
        </a-radio-group>
      </a-form-item>

      <a-form-item label="检查项" :wrapper-col="{ span: 24 }">
        <div class="check-rules-container">
          <div
            v-for="(checkRule, index) in formData.check_config.rules"
            :key="index"
            class="check-rule-item"
          >
            <div class="check-rule-header">
              <span class="check-rule-index">检查项 {{ index + 1 }}</span>
              <a-button
                type="text"
                danger
                size="small"
                @click="removeCheckRule(index)"
                :disabled="formData.check_config.rules.length === 1"
              >
                <DeleteOutlined />
              </a-button>
            </div>

            <a-row :gutter="12">
              <a-col :span="8">
                <a-form-item label="检查类型" :label-col="{ span: 8 }" :wrapper-col="{ span: 16 }">
                  <a-select
                    v-model:value="checkRule.type"
                    placeholder="选择类型"
                    @change="handleCheckTypeChange(index)"
                  >
                    <a-select-option value="file_kv">配置文件键值对</a-select-option>
                    <a-select-option value="file_exists">文件存在检查</a-select-option>
                    <a-select-option value="file_permission">文件权限检查</a-select-option>
                    <a-select-option value="file_owner">文件属主检查</a-select-option>
                    <a-select-option value="file_line_match">文件行匹配</a-select-option>
                    <a-select-option value="sysctl">内核参数检查</a-select-option>
                    <a-select-option value="service_status">服务状态检查</a-select-option>
                    <a-select-option value="command_exec">命令执行检查</a-select-option>
                    <a-select-option value="package_installed">软件包检查</a-select-option>
                  </a-select>
                </a-form-item>
              </a-col>
              <a-col :span="16">
                <a-form-item label="参数" :label-col="{ span: 4 }" :wrapper-col="{ span: 20 }">
                  <!-- 根据检查类型显示不同的参数输入 -->
                  <template v-if="checkRule.type === 'file_kv'">
                    <a-space direction="vertical" style="width: 100%">
                      <a-input v-model:value="checkRule.param[0]" placeholder="文件路径，如 /etc/ssh/sshd_config" />
                      <a-input v-model:value="checkRule.param[1]" placeholder="配置项名称，如 PermitRootLogin" />
                      <a-input v-model:value="checkRule.param[2]" placeholder="期望值，如 no（支持正则）" />
                    </a-space>
                  </template>

                  <template v-else-if="checkRule.type === 'file_exists'">
                    <a-input v-model:value="checkRule.param[0]" placeholder="文件路径，如 /etc/passwd" />
                  </template>

                  <template v-else-if="checkRule.type === 'file_permission'">
                    <a-space direction="vertical" style="width: 100%">
                      <a-input v-model:value="checkRule.param[0]" placeholder="文件路径，如 /etc/shadow" />
                      <a-input v-model:value="checkRule.param[1]" placeholder="期望权限，如 0640" />
                    </a-space>
                  </template>

                  <template v-else-if="checkRule.type === 'file_owner'">
                    <a-space direction="vertical" style="width: 100%">
                      <a-input v-model:value="checkRule.param[0]" placeholder="文件路径，如 /etc/passwd" />
                      <a-input v-model:value="checkRule.param[1]" placeholder="期望用户，如 root" />
                      <a-input v-model:value="checkRule.param[2]" placeholder="期望用户组，如 root" />
                    </a-space>
                  </template>

                  <template v-else-if="checkRule.type === 'file_line_match'">
                    <a-space direction="vertical" style="width: 100%">
                      <a-input v-model:value="checkRule.param[0]" placeholder="文件路径" />
                      <a-input v-model:value="checkRule.param[1]" placeholder="正则表达式" />
                      <a-select v-model:value="checkRule.param[2]" placeholder="匹配模式" style="width: 100%">
                        <a-select-option value="match">期望匹配 (存在则通过)</a-select-option>
                        <a-select-option value="not_match">期望不匹配 (不存在则通过)</a-select-option>
                      </a-select>
                    </a-space>
                  </template>

                  <template v-else-if="checkRule.type === 'sysctl'">
                    <a-space direction="vertical" style="width: 100%">
                      <a-input v-model:value="checkRule.param[0]" placeholder="参数名，如 net.ipv4.ip_forward" />
                      <a-input v-model:value="checkRule.param[1]" placeholder="期望值，如 0" />
                    </a-space>
                  </template>

                  <template v-else-if="checkRule.type === 'service_status'">
                    <a-space direction="vertical" style="width: 100%">
                      <a-input v-model:value="checkRule.param[0]" placeholder="服务名，如 firewalld" />
                      <a-select v-model:value="checkRule.param[1]" placeholder="期望状态" style="width: 100%">
                        <a-select-option value="active">运行中 (active)</a-select-option>
                        <a-select-option value="inactive">未运行 (inactive)</a-select-option>
                        <a-select-option value="enabled">开机自启 (enabled)</a-select-option>
                        <a-select-option value="disabled">未自启 (disabled)</a-select-option>
                      </a-select>
                    </a-space>
                  </template>

                  <template v-else-if="checkRule.type === 'command_exec'">
                    <a-space direction="vertical" style="width: 100%">
                      <a-input v-model:value="checkRule.param[0]" placeholder="Shell 命令" />
                      <a-input v-model:value="checkRule.param[1]" placeholder="期望输出（支持正则）" />
                    </a-space>
                  </template>

                  <template v-else-if="checkRule.type === 'package_installed'">
                    <a-space direction="vertical" style="width: 100%">
                      <a-input v-model:value="checkRule.param[0]" placeholder="软件包名，如 telnet" />
                      <a-select v-model:value="checkRule.param[1]" placeholder="期望状态" style="width: 100%">
                        <a-select-option value="installed">已安装</a-select-option>
                        <a-select-option value="not_installed">未安装</a-select-option>
                      </a-select>
                    </a-space>
                  </template>

                  <template v-else>
                    <a-input v-model:value="checkRule.param[0]" placeholder="请先选择检查类型" disabled />
                  </template>
                </a-form-item>
              </a-col>
            </a-row>
          </div>

          <a-button type="dashed" block @click="addCheckRule">
            <PlusOutlined /> 添加检查项
          </a-button>
        </div>
      </a-form-item>

      <!-- 修复建议 -->
      <a-divider orientation="left">修复建议</a-divider>

      <a-form-item label="修复说明" name="fix_suggestion">
        <a-textarea
          v-model:value="formData.fix_config.suggestion"
          :rows="2"
          placeholder="描述如何修复此问题"
        />
      </a-form-item>

      <a-form-item label="修复命令" name="fix_command">
        <a-textarea
          v-model:value="formData.fix_config.command"
          :rows="2"
          placeholder="可选：自动修复命令（谨慎使用）"
        />
        <template #extra>
          <span class="form-tip warning">
            <ExclamationCircleOutlined /> 自动修复命令会在主机上直接执行，请确保命令安全可靠
          </span>
        </template>
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, reactive, watch, computed } from 'vue'
import { message } from 'ant-design-vue'
import {
  PlusOutlined,
  DeleteOutlined,
  ExclamationCircleOutlined,
} from '@ant-design/icons-vue'
import { rulesApi } from '@/api/rules'
import type { Rule, CheckRule, RuntimeType } from '@/api/types'
import type { FormInstance } from 'ant-design-vue'

const props = defineProps<{
  visible: boolean
  rule?: Rule | null
  policyId: string
}>()

const emit = defineEmits<{
  'update:visible': [value: boolean]
  success: []
}>()

const formRef = ref<FormInstance>()
const loading = ref(false)

interface CheckRuleForm {
  type: string
  param: string[]
  result?: string
}

const formData = reactive({
  rule_id: '',
  title: '',
  category: 'other',
  severity: 'medium' as 'critical' | 'high' | 'medium' | 'low',
  description: '',
  runtime_types: [] as RuntimeType[],
  check_config: {
    condition: 'all' as 'all' | 'any',
    rules: [{ type: '', param: ['', '', ''], result: '' }] as CheckRuleForm[],
  },
  fix_config: {
    suggestion: '',
    command: '',
  },
})

const rules = {
  rule_id: [{ required: true, message: '请输入规则ID', trigger: 'blur' }],
  title: [{ required: true, message: '请输入规则标题', trigger: 'blur' }],
  category: [{ required: true, message: '请选择规则分类', trigger: 'change' }],
  severity: [{ required: true, message: '请选择严重级别', trigger: 'change' }],
}

const visible = computed({
  get: () => props.visible,
  set: (value) => emit('update:visible', value),
})

// 监听对话框打开，初始化表单数据
watch(
  () => props.visible,
  (newVisible) => {
    if (newVisible) {
      if (props.rule) {
        // 编辑模式
        formData.rule_id = props.rule.rule_id
        formData.title = props.rule.title
        formData.category = props.rule.category || 'other'
        formData.severity = props.rule.severity || 'medium'
        formData.description = props.rule.description || ''
        formData.runtime_types = props.rule.runtime_types ? [...props.rule.runtime_types] : []

        // 处理 check_config
        if (props.rule.check_config) {
          formData.check_config.condition = props.rule.check_config.condition || 'all'
          if (props.rule.check_config.rules && props.rule.check_config.rules.length > 0) {
            formData.check_config.rules = props.rule.check_config.rules.map((r: CheckRule) => ({
              type: r.type,
              param: [...(r.param || ['', '', ''])],
              result: r.result || '',
            }))
          } else {
            formData.check_config.rules = [{ type: '', param: ['', '', ''], result: '' }]
          }
        }

        // 处理 fix_config
        if (props.rule.fix_config) {
          formData.fix_config.suggestion = props.rule.fix_config.suggestion || ''
          formData.fix_config.command = props.rule.fix_config.command || ''
        }
      } else {
        // 新建模式，重置表单
        resetForm()
      }
    }
  },
  { immediate: true }
)

const resetForm = () => {
  formData.rule_id = ''
  formData.title = ''
  formData.category = 'other'
  formData.severity = 'medium'
  formData.description = ''
  formData.runtime_types = []
  formData.check_config = {
    condition: 'all',
    rules: [{ type: '', param: ['', '', ''], result: '' }],
  }
  formData.fix_config = {
    suggestion: '',
    command: '',
  }
  formRef.value?.resetFields()
}

const addCheckRule = () => {
  formData.check_config.rules.push({ type: '', param: ['', '', ''], result: '' })
}

const removeCheckRule = (index: number) => {
  if (formData.check_config.rules.length > 1) {
    formData.check_config.rules.splice(index, 1)
  }
}

const handleCheckTypeChange = (index: number) => {
  // 重置参数
  formData.check_config.rules[index].param = ['', '', '']
}

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()

    // 验证检查项
    const validRules = formData.check_config.rules.filter(
      (r) => r.type && r.param[0]
    )
    if (validRules.length === 0) {
      message.warning('请至少添加一个有效的检查项')
      return
    }

    loading.value = true

    // 构建请求数据
    const checkConfig = {
      condition: formData.check_config.condition,
      rules: validRules.map((r) => ({
        type: r.type,
        param: r.param.filter((p) => p !== ''),
        result: r.result || undefined,
      })),
    }

    const fixConfig = {
      suggestion: formData.fix_config.suggestion || undefined,
      command: formData.fix_config.command || undefined,
    }

    if (props.rule) {
      // 更新规则
      await rulesApi.update(props.rule.rule_id, {
        category: formData.category,
        title: formData.title,
        description: formData.description,
        severity: formData.severity,
        runtime_types: formData.runtime_types.length > 0 ? [...formData.runtime_types] : undefined,
        check_config: checkConfig,
        fix_config: fixConfig,
      })
      message.success('规则更新成功')
    } else {
      // 创建规则
      await rulesApi.create(props.policyId, {
        rule_id: formData.rule_id,
        category: formData.category,
        title: formData.title,
        description: formData.description,
        severity: formData.severity,
        runtime_types: formData.runtime_types.length > 0 ? [...formData.runtime_types] : undefined,
        check_config: checkConfig,
        fix_config: fixConfig,
      })
      message.success('规则创建成功')
    }

    emit('success')
    visible.value = false
  } catch (error: any) {
    if (error?.errorFields) {
      return
    }
    console.error('保存规则失败:', error)
    if (error.response?.status === 409) {
      message.error('规则 ID 已存在')
    } else {
      message.error('保存规则失败')
    }
  } finally {
    loading.value = false
  }
}

const handleCancel = () => {
  visible.value = false
}
</script>

<style scoped>
.check-rules-container {
  background: #F7F8FA;
  padding: 16px;
  border-radius: 8px;
}

.check-rule-item {
  background: #fff;
  padding: 12px;
  border-radius: 6px;
  margin-bottom: 12px;
  border: 1px solid #e8e8e8;
}

.check-rule-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px dashed #e8e8e8;
}

.check-rule-index {
  font-weight: 500;
  color: #165DFF;
}

.form-tip {
  font-size: 12px;
  color: #999;
}

.form-tip.warning {
  color: #FF7D00;
}
</style>
