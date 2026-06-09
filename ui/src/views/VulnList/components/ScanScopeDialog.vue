<template>
  <a-modal
    :open="open"
    title="立即扫描"
    :confirm-loading="submitting"
    ok-text="开始扫描"
    cancel-text="取消"
    @update:open="(v) => $emit('update:open', v)"
    @ok="handleSubmit"
    @cancel="$emit('update:open', false)"
  >
    <a-form layout="vertical" :model="form">
      <a-form-item label="扫描范围" required>
        <a-radio-group v-model:value="form.scope">
          <a-radio value="business_line">按业务线</a-radio>
          <a-radio value="hosts">选择主机</a-radio>
          <a-radio value="global">全量扫描</a-radio>
        </a-radio-group>
      </a-form-item>

      <a-form-item v-if="form.scope === 'business_line'" label="业务线" required>
        <a-select
          v-model:value="form.business_line"
          placeholder="选择业务线"
          :options="businessLineOptions"
          allow-clear
          show-search
          :loading="loadingBL"
        />
      </a-form-item>

      <a-form-item v-if="form.scope === 'hosts'" label="主机（最多 200 台）" required>
        <a-select
          v-model:value="form.host_ids"
          mode="multiple"
          placeholder="按主机名/host_id 搜索"
          :options="hostOptions"
          :loading="loadingHosts"
          :filter-option="false"
          show-search
          @search="handleHostSearch"
        />
        <div v-if="form.host_ids.length > 200" style="color: #ff4d4f; margin-top: 4px">
          已选 {{ form.host_ids.length }} 台，超过上限 200 台
        </div>
      </a-form-item>

      <a-form-item label="选项">
        <a-checkbox v-model:checked="form.reconcile_stale">
          自动清陈旧漏洞关联（推荐）
        </a-checkbox>
        <br />
        <a-checkbox v-if="form.scope === 'global'" v-model:checked="form.sync_db">
          同步漏洞库（耗时 +10 min）
        </a-checkbox>
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { vulnerabilitiesApi } from '@/api/vulnerabilities'
import { businessLinesApi } from '@/api/business-lines'
import { hostsApi } from '@/api/hosts'

defineProps<{ open: boolean }>()
const emit = defineEmits<{
  (e: 'update:open', v: boolean): void
  (e: 'success', taskId: string): void
}>()

const form = reactive({
  scope: 'business_line' as 'business_line' | 'hosts' | 'global',
  business_line: '',
  host_ids: [] as string[],
  reconcile_stale: true,
  sync_db: false,
})

const businessLineOptions = ref<{ label: string; value: string }[]>([])
const loadingBL = ref(false)
const hostOptions = ref<{ label: string; value: string }[]>([])
const loadingHosts = ref(false)
const submitting = ref(false)

let hostSearchTimer: ReturnType<typeof setTimeout> | null = null

onMounted(async () => {
  loadingBL.value = true
  try {
    const resp = await businessLinesApi.list({ page_size: 200, enabled: 'true' })
    businessLineOptions.value = (resp.data?.items || []).map((l) => ({
      label: l.name,
      value: l.name,
    }))
  } catch (e) {
    console.error('加载业务线失败', e)
  } finally {
    loadingBL.value = false
  }
})

function handleHostSearch(keyword: string) {
  if (hostSearchTimer) clearTimeout(hostSearchTimer)
  hostSearchTimer = setTimeout(async () => {
    if (!keyword) {
      hostOptions.value = []
      return
    }
    loadingHosts.value = true
    try {
      const resp = await hostsApi.list({ page_size: 50, search: keyword })
      hostOptions.value = (resp.data?.items || []).map((h: any) => ({
        label: `${h.hostname} (${h.host_id?.slice(0, 8)})`,
        value: h.host_id,
      }))
    } catch (e) {
      console.error('搜索主机失败', e)
    } finally {
      loadingHosts.value = false
    }
  }, 300)
}

async function handleSubmit() {
  if (form.scope === 'business_line' && !form.business_line) {
    message.error('请选择业务线')
    return
  }
  if (form.scope === 'hosts' && form.host_ids.length === 0) {
    message.error('请至少选择 1 台主机')
    return
  }
  if (form.scope === 'hosts' && form.host_ids.length > 200) {
    message.error('主机数超过上限 200 台')
    return
  }

  submitting.value = true
  try {
    const params: any = { scope: form.scope, reconcile_stale: form.reconcile_stale }
    if (form.scope === 'business_line') params.business_line = form.business_line
    if (form.scope === 'hosts') params.host_ids = form.host_ids
    if (form.scope === 'global') params.sync_db = form.sync_db

    const resp = await vulnerabilitiesApi.triggerScopedScan(params)
    const data = resp.data
    message.success(`扫描已启动，任务 ID: ${data.task_id.slice(0, 8)}...，预计 ${data.estimated_seconds}s`)
    emit('success', data.task_id)
    emit('update:open', false)
  } catch (e: any) {
    message.error(e?.response?.data?.message || e?.message || '触发失败')
  } finally {
    submitting.value = false
  }
}
</script>
