<template>
  <div class="mode-panel">
    <a-page-header
      title="运行模式管理"
      sub-title="observe (观察) / protect (阻断) + 6 闸门 admission"
    />

    <a-row :gutter="16" class="cards-row">
      <a-col :span="8">
        <a-card title="全局模式" :loading="loadingGlobal">
          <template #extra>
            <a-tag :color="modeColor(globalMode?.mode)">
              {{ globalMode?.mode || '—' }}
            </a-tag>
          </template>
          <p class="meta">最近更新者: {{ globalMode?.updated_by || '—' }}</p>
          <p class="meta">更新时间: {{ globalMode?.updated_at || '—' }}</p>
          <a-divider />
          <a-button
            type="primary"
            danger
            block
            :disabled="globalMode?.mode === 'protect'"
            @click="onSwitchGlobal('protect')"
          >
            切换到 protect (走 6 闸门)
          </a-button>
          <a-button
            block
            style="margin-top: 8px"
            :disabled="globalMode?.mode === 'observe'"
            @click="onSwitchGlobal('observe')"
          >
            回退到 observe
          </a-button>
        </a-card>
      </a-col>

      <a-col :span="16">
        <a-card title="6 闸门 admission 检查" :loading="loadingGates">
          <template #extra>
            <a-tag :color="admission?.ready ? 'success' : 'error'">
              {{ admission?.ready ? '全部通过' : '阻塞中' }}
            </a-tag>
            <a-button size="small" style="margin-left: 8px" @click="refreshGates">刷新</a-button>
          </template>
          <a-table
            size="small"
            :columns="gateColumns"
            :data-source="admission?.gates || []"
            :pagination="false"
            row-key="id"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.dataIndex === 'status'">
                <a-tag :color="gateStatusColor(record.status)">{{ record.status }}</a-tag>
              </template>
              <template v-else-if="column.dataIndex === 'last_checked_at'">
                {{ formatTime(record.last_checked_at) }}
              </template>
            </template>
          </a-table>
          <a-alert
            v-if="admission && !admission.ready"
            type="warning"
            show-icon
            style="margin-top: 12px"
            :message="`阻塞原因 (${admission.blocking_reasons.length})`"
            :description="admission.blocking_reasons.join('; ')"
          />
        </a-card>
      </a-col>
    </a-row>

    <a-row :gutter="16" class="cards-row">
      <a-col :span="12">
        <a-card title="host_label 覆盖">
          <template #extra>
            <a-button size="small" type="primary" @click="onAddLabelOverride">新增</a-button>
          </template>
          <a-table
            size="small"
            :columns="labelColumns"
            :data-source="labelOverrides"
            row-key="id"
          />
        </a-card>
      </a-col>
      <a-col :span="12">
        <a-card title="规则级覆盖 (rule_id)">
          <template #extra>
            <a-button size="small" type="primary" @click="onAddRuleOverride">新增</a-button>
          </template>
          <a-table
            size="small"
            :columns="ruleColumns"
            :data-source="ruleOverrides"
            row-key="id"
          />
        </a-card>
      </a-col>
    </a-row>

    <a-modal
      v-model:open="confirmVisible"
      title="确认切换运行模式"
      ok-text="确认切换"
      cancel-text="取消"
      @ok="onConfirmSwitch"
    >
      <a-alert
        v-if="targetMode === 'protect'"
        type="warning"
        show-icon
        message="切换到 protect 后, 命中规则将自动阻断业务进程/网络/IO"
        description="确认全部 6 闸门通过、变更窗口已批准、有完整回滚预案"
        style="margin-bottom: 12px"
      />
      <a-form layout="vertical">
        <a-form-item label="目标模式" required>
          <a-input :value="targetMode" disabled />
        </a-form-item>
        <a-form-item label="变更理由 (必填, 审计落库)" required>
          <a-textarea v-model:value="switchReason" :rows="3" placeholder="变更工单号 / 风险评估摘要" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message, Modal } from 'ant-design-vue'
import dayjs from 'dayjs'
import {
  ModeAPI,
  type GlobalMode,
  type AdmissionSummary,
  type HostLabelOverride,
  type RuleOverride,
  type RunningMode,
} from '@/api/mode'

const loadingGlobal = ref(false)
const loadingGates = ref(false)
const globalMode = ref<GlobalMode | null>(null)
const admission = ref<AdmissionSummary | null>(null)
const labelOverrides = ref<HostLabelOverride[]>([])
const ruleOverrides = ref<RuleOverride[]>([])

const confirmVisible = ref(false)
const targetMode = ref<RunningMode>('observe')
const switchReason = ref('')

const gateColumns = [
  { title: '闸门', dataIndex: 'id', width: 60 },
  { title: '名称', dataIndex: 'name', width: 180 },
  { title: '状态', dataIndex: 'status', width: 90 },
  { title: '说明', dataIndex: 'description' },
  { title: '最近检查', dataIndex: 'last_checked_at', width: 160 },
]
const labelColumns = [
  { title: 'label_selector', dataIndex: 'label_selector' },
  { title: '模式', dataIndex: 'mode', width: 100 },
  { title: '理由', dataIndex: 'reason' },
  { title: '到期', dataIndex: 'expires_at', width: 160 },
]
const ruleColumns = [
  { title: 'rule_id', dataIndex: 'rule_id' },
  { title: '模式', dataIndex: 'mode', width: 100 },
  { title: '理由', dataIndex: 'reason' },
]

function modeColor(m?: string) {
  if (m === 'protect') return 'red'
  if (m === 'observe') return 'blue'
  return 'default'
}
function gateStatusColor(s: string) {
  return s === 'pass' ? 'success' : s === 'fail' ? 'error' : 'warning'
}
function formatTime(t?: string) {
  return t ? dayjs(t).format('YYYY-MM-DD HH:mm') : '—'
}

async function loadGlobal() {
  loadingGlobal.value = true
  try {
    const res = await ModeAPI.getGlobal()
    globalMode.value = res.data
  } catch (e) {
    console.error('加载全局模式失败:', e)
  } finally {
    loadingGlobal.value = false
  }
}

async function refreshGates() {
  loadingGates.value = true
  try {
    const res = await ModeAPI.checkAdmission('protect')
    admission.value = res.data
  } catch (e) {
    console.error('加载闸门状态失败:', e)
  } finally {
    loadingGates.value = false
  }
}

async function loadOverrides() {
  try {
    const [labels, rules] = await Promise.all([
      ModeAPI.listHostLabelOverrides(),
      ModeAPI.listRuleOverrides(),
    ])
    labelOverrides.value = labels.data || []
    ruleOverrides.value = rules.data || []
  } catch (e) {
    console.error('加载覆盖配置失败:', e)
  }
}

function onSwitchGlobal(target: RunningMode) {
  if (target === 'protect' && (!admission.value || !admission.value.ready)) {
    Modal.warning({
      title: '6 闸门未通过',
      content: '切换到 protect 前必须 G1-G6 全部 pass; 请按面板提示先补齐。',
    })
    return
  }
  targetMode.value = target
  switchReason.value = ''
  confirmVisible.value = true
}

async function onConfirmSwitch() {
  if (!switchReason.value.trim()) {
    message.warning('请填写变更理由 (审计要求)')
    return
  }
  try {
    await ModeAPI.setGlobal(targetMode.value, switchReason.value.trim())
    message.success('全局模式已切换为 ' + targetMode.value)
    confirmVisible.value = false
    await loadGlobal()
  } catch (e) {
    console.error('切换模式失败:', e)
  }
}

function onAddLabelOverride() {
  // 占位: 下一 PR 走完整对话框
  message.info('host_label 覆盖编辑器在下一 PR 接入')
}
function onAddRuleOverride() {
  message.info('rule 覆盖编辑器在下一 PR 接入')
}

onMounted(async () => {
  await Promise.all([loadGlobal(), refreshGates(), loadOverrides()])
})
</script>

<style scoped>
.mode-panel {
  padding: 16px;
}
.cards-row {
  margin-top: 16px;
}
.meta {
  color: rgba(0, 0, 0, 0.55);
  font-size: 13px;
  margin-bottom: 4px;
}
</style>
