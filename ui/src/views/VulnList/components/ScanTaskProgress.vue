<template>
  <a-alert
    v-if="task"
    :type="alertType"
    :show-icon="true"
    closable
    style="margin-bottom: 12px"
    @close="$emit('close')"
  >
    <template #message>
      漏洞扫描任务 {{ task.taskId.slice(0, 8) }}... · {{ scopeLabel }} · {{ statusLabel }}
    </template>
    <template #description>
      <a-progress
        v-if="task.status === 'running' || task.status === 'pending'"
        :percent="progressPercent"
        status="active"
      />
      <div v-if="task.status === 'success' || task.status === 'failed'">
        <span>新发现 <strong>{{ task.newVulns }}</strong></span>
        · <span>已修复 <strong>{{ task.patchedCount }}</strong></span>
        · <span>包消失 <strong>{{ task.vanishedCount }}</strong></span>
        · <span>回归 <strong>{{ task.resurfacedCount }}</strong></span>
        <span v-if="task.errorMsg" style="color: #ff4d4f; margin-left: 8px">
          错误: {{ task.errorMsg }}
        </span>
      </div>
    </template>
  </a-alert>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { vulnerabilitiesApi, type VulnScanTask } from '@/api/vulnerabilities'

const props = defineProps<{ taskId: string }>()
const emit = defineEmits<{ (e: 'close'): void; (e: 'done'): void }>()

const task = ref<VulnScanTask | null>(null)
let timer: ReturnType<typeof setInterval> | null = null

const alertType = computed<'info' | 'success' | 'warning' | 'error'>(() => {
  if (!task.value) return 'info'
  if (task.value.status === 'success') return 'success'
  if (task.value.status === 'failed') return 'error'
  return 'info'
})

const statusLabel = computed(() => {
  const map: Record<string, string> = {
    pending: '等待中', running: '扫描中', success: '完成', failed: '失败',
  }
  return map[task.value?.status || 'pending']
})

const scopeLabel = computed(() => {
  if (!task.value) return ''
  const map: Record<string, string> = {
    global: '全量', hosts: '指定主机',
    business_line: `业务线 ${task.value.businessLine || ''}`,
  }
  return map[task.value.scope] || task.value.scope
})

const progressPercent = computed(() => {
  if (!task.value || task.value.progressTotal === 0) return 0
  return Math.min(100, Math.round((task.value.progressScanned / task.value.progressTotal) * 100))
})

async function poll() {
  if (!props.taskId) return
  try {
    const resp = await vulnerabilitiesApi.getScanTask(props.taskId)
    task.value = resp
    if (task.value?.status === 'success' || task.value?.status === 'failed') {
      stopPoll()
      emit('done')
    }
  } catch (e) {
    console.error('查询扫描任务失败', e)
  }
}

function startPoll() {
  poll()
  timer = setInterval(poll, 5000)
}

function stopPoll() {
  if (timer) { clearInterval(timer); timer = null }
}

watch(() => props.taskId, () => { stopPoll(); startPoll() })
onMounted(() => startPoll())
onUnmounted(() => stopPoll())
</script>
