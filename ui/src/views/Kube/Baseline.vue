<template>
  <div class="kube-baseline-page">
    <div class="page-header">
      <h2>容器集群基线检查</h2>
      <span class="page-header-hint">Kubernetes 集群安全基线合规检查 (CIS Benchmark)</span>
    </div>

    <!-- 合规概览 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="6">
        <StatCard
          title="整体合规率"
          :value="stats.passRate || 0"
          suffix="%"
          :color="stats.passRate >= 80 ? '#22C55E' : stats.passRate >= 60 ? '#F59E0B' : '#EF4444'"
          :progress="stats.passRate || 0"
        />
      </a-col>
      <a-col :span="6">
        <StatCard title="检查项总数" :value="stats.totalChecks || 0" color="#3B82F6" />
      </a-col>
      <a-col :span="6">
        <StatCard title="通过" :value="stats.passed || 0" color="#22C55E" />
      </a-col>
      <a-col :span="6">
        <StatCard title="未通过" :value="stats.failed || 0" color="#EF4444" />
      </a-col>
    </a-row>

    <!-- 基线检查列表 -->
    <div class="dashboard-card">
      <div class="card-header">
        <span class="card-title">基线检查项</span>
        <a-button type="primary" @click="handleRunCheck" :loading="checkLoading">立即检查</a-button>
      </div>
      <div class="card-body">
        <div class="filter-bar">
          <a-select v-model:value="filterCluster" style="width: 200px" placeholder="全部集群" allow-clear @change="handleClusterChange">
            <a-select-option v-for="c in clusterOptions" :key="c.value" :value="c.value">{{ c.label }}</a-select-option>
          </a-select>
          <a-input-search v-model:value="searchText" placeholder="搜索检查项" style="width: 240px" allow-clear @search="loadBaseline" />
          <a-select v-model:value="filterCategory" style="width: 180px" placeholder="检查分类" allow-clear @change="loadBaseline">
            <a-select-option value="RBAC">RBAC</a-select-option>
            <a-select-option value="Pod Security">Pod 安全</a-select-option>
            <a-select-option value="Network">网络策略</a-select-option>
            <a-select-option value="Secrets & Config">密钥与配置</a-select-option>
            <a-select-option value="Workload">工作负载</a-select-option>
            <a-select-option value="Node">节点安全</a-select-option>
            <a-select-option value="Cluster Config">集群配置</a-select-option>
            <a-select-option value="Supply Chain">供应链</a-select-option>
            <a-select-option value="Runtime">运行时</a-select-option>
          </a-select>
          <a-select v-model:value="filterResult" style="width: 120px" placeholder="结果" allow-clear @change="loadBaseline">
            <a-select-option value="pass">通过</a-select-option>
            <a-select-option value="fail">未通过</a-select-option>
            <a-select-option value="warn">警告</a-select-option>
            <a-select-option value="error">错误</a-select-option>
          </a-select>
        </div>

        <a-table
          :columns="columns"
          :data-source="checks"
          :loading="loading"
          :pagination="pagination"
          @change="handleTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'result'">
              <a-tag v-if="record.result" :color="({ pass: 'green', fail: 'red', warn: 'orange', error: 'default' } as Record<string, string>)[record.result] || 'default'" :bordered="false">
                {{ resultTextMap[record.result] || record.result }}
              </a-tag>
              <span v-else style="color: #86909C">-</span>
            </template>
            <template v-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity]" :bordered="false">{{ severityTextMap[record.severity] }}</a-tag>
            </template>
            <template v-if="column.key === 'action'">
              <a-button type="link" size="small" @click="showCheckDetail(record)">详情</a-button>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 检查项详情 Drawer -->
    <a-drawer v-model:open="showDetail" title="基线检查详情" width="640">
      <template v-if="detailRecord">
        <a-descriptions :column="1" bordered size="small">
          <a-descriptions-item label="检查编号">{{ detailRecord.checkId }}</a-descriptions-item>
          <a-descriptions-item label="检查分类">{{ detailRecord.category }}</a-descriptions-item>
          <a-descriptions-item label="检查项">{{ detailRecord.title }}</a-descriptions-item>
          <a-descriptions-item label="结果">
            <a-tag :color="detailRecord.result === 'pass' ? 'green' : 'red'" :bordered="false">{{ resultTextMap[detailRecord.result] }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="严重级别">
            <a-tag :color="severityColorMap[detailRecord.severity]" :bordered="false">{{ severityTextMap[detailRecord.severity] }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="描述">{{ detailRecord.description }}</a-descriptions-item>
          <a-descriptions-item label="修复建议">{{ detailRecord.remediation }}</a-descriptions-item>
          <a-descriptions-item label="参考标准">{{ detailRecord.benchmark }}</a-descriptions-item>
        </a-descriptions>
        <a-divider v-if="detailRecord.affectedResources?.length">受影响资源</a-divider>
        <a-table v-if="detailRecord.affectedResources?.length" :columns="resourceColumns" :data-source="detailRecord.affectedResources" :pagination="false" size="small" />
      </template>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import apiClient from '@/api/client'
import StatCard from '@/components/StatCard.vue'

const searchText = ref('')
const filterCluster = ref<string>()
const filterCategory = ref<string>()
const filterResult = ref<string>()
const loading = ref(false)
const checkLoading = ref(false)
const checks = ref<any[]>([])
const clusterOptions = ref<any[]>([])
const showDetail = ref(false)
const detailRecord = ref<any>(null)
const stats = ref({ passRate: 0, totalChecks: 0, passed: 0, failed: 0 })

const pagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const severityColorMap: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityTextMap: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }
const resultTextMap: Record<string, string> = { pass: '通过', fail: '未通过', warn: '警告', error: '错误' }

const columns = [
  { title: '编号', dataIndex: 'checkId', key: 'checkId', width: 100 },
  { title: '分类', dataIndex: 'category', key: 'category', width: 120 },
  { title: '检查项', dataIndex: 'title', key: 'title', ellipsis: true },
  { title: '级别', key: 'severity', width: 80 },
  { title: '集群', dataIndex: 'clusterName', key: 'clusterName', width: 140 },
  { title: '结果', key: 'result', width: 100 },
  { title: '检查时间', dataIndex: 'checkedAt', key: 'checkedAt', width: 180 },
  { title: '操作', key: 'action', width: 80 },
]

const resourceColumns = [
  { title: '类型', dataIndex: 'kind', key: 'kind', width: 120 },
  { title: '名称', dataIndex: 'name', key: 'name' },
  { title: 'Namespace', dataIndex: 'namespace', key: 'namespace', width: 140 },
]

const loadBaseline = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/kube/baseline', {
      params: { page: pagination.value.current, page_size: pagination.value.pageSize, search: searchText.value || undefined, cluster_id: filterCluster.value || undefined, category: filterCategory.value || undefined, result: filterResult.value || undefined },
    })
    checks.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    if (res.stats) stats.value = res.stats
  } catch { checks.value = [] }
  finally { loading.value = false }
}

const handleClusterChange = () => { pagination.value.current = 1; loadBaseline() }
const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadBaseline() }
const showCheckDetail = (record: any) => { detailRecord.value = record; showDetail.value = true }

const handleRunCheck = async () => {
  if (!filterCluster.value) { message.warning('请先在筛选栏选择目标集群'); return }
  checkLoading.value = true
  try { await apiClient.post('/kube/baseline/detect', { cluster_id: Number(filterCluster.value) }); message.success('基线检查任务已创建'); loadBaseline() }
  catch (error) { console.error('创建基线检查任务失败:', error) }
  finally { checkLoading.value = false }
}

const loadClusters = async () => {
  try {
    const res = await apiClient.get<any>('/kube/clusters', { params: { page_size: 100 } })
    clusterOptions.value = (res.items ?? []).map((c: any) => ({ value: String(c.id), label: c.name }))
  } catch { /* ignore */ }
}

onMounted(() => { loadClusters(); loadBaseline() })
</script>

<style scoped>
.kube-baseline-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.baseline-stat-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; padding: 20px; text-align: center; }
.baseline-stat-value { font-size: 28px; font-weight: 700; color: var(--mxsec-text-1); line-height: 1.2; }
.baseline-stat-label { font-size: 13px; color: var(--mxsec-text-3); margin-top: 4px; }

.dashboard-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; }
.card-header { display: flex; align-items: center; justify-content: space-between; padding: 14px 20px; border-bottom: 1px solid var(--mxsec-border-light); }
.card-title { font-size: 14px; font-weight: 600; color: var(--mxsec-text-1); }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 16px; padding: 12px 16px; background: var(--mxsec-fill-1); border-radius: 4px; border: 1px solid var(--mxsec-border); }
</style>
