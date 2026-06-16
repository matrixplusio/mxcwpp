<script setup lang="ts">
/**
 * MSSP 控制台首页 (P4-11)
 *
 * 服务商 NOC 视图: 横跨所有子租户的健康度 + 告警态势
 */
import { onMounted, ref } from 'vue'
import { message } from 'ant-design-vue'
import { MSSPApi, type ChildTenant, type MSSPDashboardSummary } from '@/api/mssp'
import StatCard from '@/components/StatCard.vue'

const loading = ref(false)
const summary = ref<MSSPDashboardSummary | null>(null)
const tenants = ref<ChildTenant[]>([])
const search = ref('')
const statusFilter = ref<string>('')

const columns = [
  { title: '租户 ID', dataIndex: 'id', width: 160 },
  { title: '名称', dataIndex: 'name', width: 180 },
  { title: '状态', dataIndex: 'status', width: 100, slots: { customRender: 'status' } },
  { title: '联系邮箱', dataIndex: 'contact_email', width: 200 },
  { title: '主机数 / 配额', dataIndex: 'hosts', width: 140, slots: { customRender: 'hosts' } },
  { title: '7d 告警', dataIndex: 'alert_count_7d', width: 100, sorter: true },
  { title: '7d 严重', dataIndex: 'critical_alert_count_7d', width: 100, sorter: true },
  { title: '模式', dataIndex: 'mode', width: 100 },
  { title: '创建时间', dataIndex: 'created_at', width: 160 },
  { title: '操作', dataIndex: 'actions', width: 200, slots: { customRender: 'actions' } },
]

async function loadDashboard() {
  try {
    const r = await MSSPApi.dashboard()
    summary.value = r.data
  } catch (error) {
    console.error('加载汇总失败:', error)
  }
}

async function loadTenants() {
  loading.value = true
  try {
    const r = await MSSPApi.listChildTenants({
      status: statusFilter.value || undefined,
      search: search.value || undefined,
      page: 1,
      page_size: 100,
    })
    tenants.value = r.data.items
  } catch (error) {
    console.error('加载子租户失败:', error)
  } finally {
    loading.value = false
  }
}

async function onSuspend(t: ChildTenant) {
  const reason = window.prompt('停用原因 (会写入审计)', '')
  if (!reason) return
  try {
    await MSSPApi.suspendChildTenant(t.id, reason)
    message.success(`${t.name} 已暂停`)
    loadTenants()
  } catch (error) {
    console.error('暂停子租户失败:', error)
  }
}

async function onResume(t: ChildTenant) {
  try {
    await MSSPApi.resumeChildTenant(t.id)
    message.success(`${t.name} 已恢复`)
    loadTenants()
  } catch (error) {
    console.error('恢复子租户失败:', error)
  }
}

onMounted(() => {
  loadDashboard()
  loadTenants()
})
</script>

<template>
  <div class="mssp-console">
    <a-page-header title="MSSP 控制台" sub-title="多租户托管 / NOC 视图" />

    <a-row :gutter="16" class="kpi-row">
      <a-col :span="6"><StatCard title="管理的子租户" :value="(summary?.total_child_tenants ?? 0) as any" color="#3B82F6" /></a-col>
      <a-col :span="6"><StatCard title="活跃" :value="(summary?.active_child_tenants ?? 0) as any" color="#22C55E" /></a-col>
      <a-col :span="6"><StatCard title="托管主机数" :value="(summary?.total_hosts_managed ?? 0) as any" color="#06B6D4" /></a-col>
      <a-col :span="6"><StatCard title="7d 严重告警" :value="(summary?.critical_alerts_7d ?? 0) as any" color="#EF4444" /></a-col>
    </a-row>

    <a-card title="子租户" class="tenants-card">
      <template #extra>
        <a-space>
          <a-input v-model:value="search" placeholder="按名称/ID 搜索" style="width:200px" @press-enter="loadTenants" />
          <a-select v-model:value="statusFilter" placeholder="状态" style="width:120px" allow-clear @change="loadTenants">
            <a-select-option value="active">活跃</a-select-option>
            <a-select-option value="suspended">已停</a-select-option>
            <a-select-option value="pending">待审</a-select-option>
          </a-select>
          <a-button type="primary" @click="loadTenants">刷新</a-button>
        </a-space>
      </template>

      <a-table
        :columns="columns"
        :data-source="tenants"
        :loading="loading"
        row-key="id"
        :pagination="{ pageSize: 20 }"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.dataIndex === 'status'">
            <a-tag :color="record.status === 'active' ? 'green' : record.status === 'suspended' ? 'red' : 'orange'">
              {{ record.status }}
            </a-tag>
          </template>
          <template v-if="column.dataIndex === 'hosts'">
            {{ record.host_count }} / {{ record.host_quota }}
            <a-progress
              :percent="Math.round((record.host_count / Math.max(1, record.host_quota)) * 100)"
              size="small"
              :show-info="false"
            />
          </template>
          <template v-if="column.dataIndex === 'actions'">
            <a-button
              v-if="record.status === 'active'"
              size="small"
              danger
              @click="onSuspend(record)"
            >暂停</a-button>
            <a-button
              v-else-if="record.status === 'suspended'"
              size="small"
              type="primary"
              @click="onResume(record)"
            >恢复</a-button>
          </template>
        </template>
      </a-table>
    </a-card>
  </div>
</template>

<style scoped>
.mssp-console {
  padding: 16px;
}
.kpi-row {
  margin: 16px 0;
}
.tenants-card {
  margin-top: 16px;
}
</style>
