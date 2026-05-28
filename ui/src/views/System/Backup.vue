<template>
  <div class="backup-page">
    <div class="page-header">
      <h2>配置备份</h2>
      <span class="page-header-hint">管理系统配置备份与恢复</span>
    </div>

    <!-- 操作区 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="12">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">创建备份</span>
          </div>
          <div class="card-body">
            <a-form layout="vertical">
              <a-form-item label="备份范围">
                <a-checkbox-group v-model:value="backupScope" :options="scopeOptions" />
              </a-form-item>
              <a-form-item label="备份说明">
                <a-input v-model:value="backupRemark" placeholder="备份描述 (可选)" />
              </a-form-item>
              <a-button type="primary" :loading="backupLoading" @click="handleCreateBackup">
                立即备份
              </a-button>
            </a-form>
          </div>
        </div>
      </a-col>
      <a-col :span="12">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">自动备份设置</span>
          </div>
          <div class="card-body">
            <a-form layout="vertical">
              <a-form-item label="自动备份">
                <a-switch v-model:checked="autoBackup.enabled" checked-children="启用" un-checked-children="禁用" />
              </a-form-item>
              <a-form-item label="备份频率" v-if="autoBackup.enabled">
                <a-select v-model:value="autoBackup.frequency" style="width: 200px">
                  <a-select-option value="daily">每天</a-select-option>
                  <a-select-option value="weekly">每周</a-select-option>
                  <a-select-option value="monthly">每月</a-select-option>
                </a-select>
              </a-form-item>
              <a-form-item label="保留份数" v-if="autoBackup.enabled">
                <a-input-number v-model:value="autoBackup.retention" :min="1" :max="30" />
                <span style="margin-left: 8px; color: #86909C">最多保留备份数量</span>
              </a-form-item>
              <a-button type="primary" @click="saveAutoBackupConfig" :loading="saveLoading">保存设置</a-button>
            </a-form>
          </div>
        </div>
      </a-col>
    </a-row>

    <!-- 备份列表 -->
    <div class="dashboard-card">
      <div class="card-header">
        <span class="card-title">备份历史</span>
      </div>
      <div class="card-body">
        <a-table
          :columns="columns"
          :data-source="backups"
          :loading="loading"
          :pagination="pagination"
          @change="handleTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'type'">
              <a-tag :color="record.type === 'auto' ? 'blue' : 'default'" :bordered="false">
                {{ record.type === 'auto' ? '自动' : '手动' }}
              </a-tag>
            </template>
            <template v-if="column.key === 'status'">
              <a-tag :color="record.status === 'completed' ? 'green' : record.status === 'failed' ? 'red' : 'default'" :bordered="false">
                {{ statusTextMap[record.status] }}
              </a-tag>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="handleDownload(record)">下载</a-button>
                <a-popconfirm title="确定恢复此备份? 当前配置将被覆盖!" @confirm="handleRestore(record)">
                  <a-button type="link" size="small">恢复</a-button>
                </a-popconfirm>
                <a-popconfirm title="确定删除此备份?" @confirm="handleDelete(record.id)">
                  <a-button type="link" size="small" danger>删除</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import apiClient from '@/api/client'

const loading = ref(false)
const backupLoading = ref(false)
const saveLoading = ref(false)
const backups = ref<any[]>([])
const backupScope = ref(['policies', 'users', 'notifications', 'settings'])
const backupRemark = ref('')

const scopeOptions = [
  { label: '策略配置', value: 'policies' },
  { label: '用户数据', value: 'users' },
  { label: '通知配置', value: 'notifications' },
  { label: '系统设置', value: 'settings' },
  { label: '业务线', value: 'business_lines' },
  { label: 'FIM 策略', value: 'fim_policies' },
]

const autoBackup = ref({ enabled: false, frequency: 'daily', retention: 7 })

const statusTextMap: Record<string, string> = { completed: '完成', failed: '失败', creating: '创建中' }

const pagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const columns = [
  { title: '备份名称', dataIndex: 'name', key: 'name', width: 240 },
  { title: '类型', key: 'type', width: 80 },
  { title: '大小', dataIndex: 'size', key: 'size', width: 100 },
  { title: '备份范围', dataIndex: 'scopeText', key: 'scopeText', ellipsis: true },
  { title: '备注', dataIndex: 'remark', key: 'remark', width: 200 },
  { title: '状态', key: 'status', width: 100 },
  { title: '创建时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
  { title: '操作', key: 'action', width: 200 },
]

const loadBackups = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/system/backups', {
      params: { page: pagination.value.current, page_size: pagination.value.pageSize },
    })
    backups.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch { backups.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadBackups() }

const handleCreateBackup = async () => {
  backupLoading.value = true
  try {
    await apiClient.post('/system/backups', { scope: backupScope.value, remark: backupRemark.value })
    message.success('备份任务已创建')
    backupRemark.value = ''
    loadBackups()
  } catch { message.error('创建备份失败') }
  finally { backupLoading.value = false }
}

const saveAutoBackupConfig = async () => {
  saveLoading.value = true
  try {
    await apiClient.put('/system/backup-config', autoBackup.value)
    message.success('设置已保存')
  } catch { message.error('保存失败') }
  finally { saveLoading.value = false }
}

const handleDownload = (record: any) => {
  window.open(`/api/v1/system/backups/${record.id}/download`, '_blank')
}

const handleRestore = async (record: any) => {
  try {
    await apiClient.post(`/system/backups/${record.id}/restore`)
    message.success('恢复操作已开始')
  } catch { message.error('恢复失败') }
}

const handleDelete = async (id: string) => {
  try { await apiClient.delete(`/system/backups/${id}`); message.success('已删除'); loadBackups() }
  catch { message.error('删除失败') }
}

const loadAutoBackupConfig = async () => {
  try {
    const res = await apiClient.get<any>('/system/backup-config')
    if (res) {
      autoBackup.value = { enabled: res.enabled ?? false, frequency: res.frequency ?? 'daily', retention: res.retention ?? 7 }
    }
  } catch { /* 使用默认值 */ }
}

onMounted(() => { loadBackups(); loadAutoBackupConfig() })
</script>

<style scoped>
.backup-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
}
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 20px;
  border-bottom: 1px solid var(--mxsec-border-light);
}
.card-title { font-size: 14px; font-weight: 600; color: var(--mxsec-text-1); }
.card-body { padding: 20px; }
</style>
