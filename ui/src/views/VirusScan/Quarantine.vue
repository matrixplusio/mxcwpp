<template>
  <div class="quarantine-page">
    <div class="page-header">
      <h2>文件隔离箱</h2>
      <span class="page-header-hint">被隔离的可疑文件, 可恢复或永久删除</span>
    </div>

    <!-- 统计 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="8">
        <div class="q-stat-card">
          <div class="q-stat-value">{{ stats.total }}</div>
          <div class="q-stat-label">隔离文件总数</div>
        </div>
      </a-col>
      <a-col :span="8">
        <div class="q-stat-card">
          <div class="q-stat-value">{{ stats.totalSize }}</div>
          <div class="q-stat-label">占用空间</div>
        </div>
      </a-col>
      <a-col :span="8">
        <div class="q-stat-card">
          <div class="q-stat-value" style="color: #22C55E">{{ stats.restored }}</div>
          <div class="q-stat-label">已恢复</div>
        </div>
      </a-col>
    </a-row>

    <!-- 列表 -->
    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search
            v-model:value="searchText"
            placeholder="搜索文件名或路径"
            style="width: 280px"
            allow-clear
            @search="loadFiles"
          />
          <a-select v-model:value="filterType" style="width: 140px" placeholder="威胁类型" allow-clear @change="loadFiles">
            <a-select-option value="virus">病毒</a-select-option>
            <a-select-option value="trojan">木马</a-select-option>
            <a-select-option value="worm">蠕虫</a-select-option>
            <a-select-option value="ransomware">勒索</a-select-option>
            <a-select-option value="backdoor">后门</a-select-option>
          </a-select>
          <div style="flex: 1"></div>
          <a-popconfirm title="确定清空隔离箱? 此操作不可恢复!" @confirm="handleClearAll" ok-text="确定清空" ok-type="danger">
            <a-button danger>清空隔离箱</a-button>
          </a-popconfirm>
        </div>

        <a-table
          :columns="columns"
          :data-source="files"
          :loading="loading"
          :pagination="pagination"
          @change="handleTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'threatType'">
              <a-tag color="red" :bordered="false">{{ record.threatType }}</a-tag>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-popconfirm title="确定恢复该文件? 请确保文件安全!" @confirm="handleRestore(record)">
                  <a-button type="link" size="small">恢复</a-button>
                </a-popconfirm>
                <a-popconfirm title="确定永久删除? 此操作不可恢复!" @confirm="handleDelete(record)">
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

const searchText = ref('')
const filterType = ref<string>()
const loading = ref(false)
const files = ref<any[]>([])
const stats = ref({ total: 0, totalSize: '0 B', restored: 0 })

const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  { title: '文件名', dataIndex: 'fileName', key: 'fileName', width: 200 },
  { title: '原始路径', dataIndex: 'originalPath', key: 'originalPath', ellipsis: true },
  { title: '主机名', dataIndex: 'hostname', key: 'hostname', width: 160 },
  { title: '威胁类型', key: 'threatType', width: 100 },
  { title: '威胁名称', dataIndex: 'threatName', key: 'threatName', width: 200 },
  { title: '文件大小', dataIndex: 'fileSize', key: 'fileSize', width: 100 },
  { title: 'MD5', dataIndex: 'md5', key: 'md5', width: 280 },
  { title: '隔离时间', dataIndex: 'quarantinedAt', key: 'quarantinedAt', width: 180 },
  { title: '操作', key: 'action', width: 140 },
]

const loadFiles = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/virus/quarantine', {
      params: {
        page: pagination.value.current,
        page_size: pagination.value.pageSize,
        search: searchText.value || undefined,
        threat_type: filterType.value || undefined,
      },
    })
    files.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    if (res.stats) stats.value = res.stats
  } catch { files.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadFiles()
}

const handleRestore = async (record: any) => {
  try {
    await apiClient.post(`/virus/quarantine/${record.id}/restore`)
    message.success('文件已恢复')
    loadFiles()
  } catch (error) { console.error('恢复文件失败:', error) }
}

const handleDelete = async (record: any) => {
  try {
    await apiClient.delete(`/virus/quarantine/${record.id}`)
    message.success('已永久删除')
    loadFiles()
  } catch (error) { console.error('删除文件失败:', error) }
}

const handleClearAll = async () => {
  try {
    await apiClient.delete('/virus/quarantine/all')
    message.success('隔离箱已清空')
    loadFiles()
  } catch (error) { console.error('清空隔离箱失败:', error) }
}

onMounted(() => { loadFiles() })
</script>

<style scoped>
.quarantine-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.q-stat-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}
.q-stat-value { font-size: 28px; font-weight: 700; color: var(--mxsec-text-1); line-height: 1.2; }
.q-stat-label { font-size: 13px; color: var(--mxsec-text-3); margin-top: 4px; }

.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
}
.card-body { padding: 20px; }

.filter-bar {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 16px;
  padding: 12px 16px;
  background: var(--mxsec-fill-1);
  border-radius: 4px;
  border: 1px solid var(--mxsec-border);
}
</style>
