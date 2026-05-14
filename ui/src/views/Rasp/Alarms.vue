<template>
  <div class="rasp-alarms-page">
    <div class="page-header">
      <h2>RASP 告警</h2>
      <span class="page-header-hint">应用运行时安全告警 — SQL 注入、XSS、命令注入、反序列化等</span>
    </div>

    <!-- 统计 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="4" v-for="item in attackTypes" :key="item.key">
        <div class="attack-stat" :class="{ active: filterType === item.key }" @click="filterType = filterType === item.key ? undefined : item.key; loadAlarms()">
          <div class="attack-stat-value">{{ item.count }}</div>
          <div class="attack-stat-label">{{ item.label }}</div>
        </div>
      </a-col>
    </a-row>

    <!-- 告警列表 -->
    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search v-model:value="searchText" placeholder="搜索告警内容" style="width: 240px" allow-clear @search="loadAlarms" />
          <a-select v-model:value="filterSeverity" style="width: 120px" placeholder="级别" allow-clear @change="loadAlarms">
            <a-select-option value="critical">紧急</a-select-option>
            <a-select-option value="high">高危</a-select-option>
            <a-select-option value="medium">中危</a-select-option>
            <a-select-option value="low">低危</a-select-option>
          </a-select>
          <a-select v-model:value="filterAction" style="width: 120px" placeholder="动作" allow-clear @change="loadAlarms">
            <a-select-option value="blocked">已阻断</a-select-option>
            <a-select-option value="detected">仅检测</a-select-option>
          </a-select>
          <a-range-picker v-model:value="dateRange" style="width: 240px" @change="loadAlarms" />
        </div>

        <a-table :columns="columns" :data-source="alarms" :loading="loading" :pagination="pagination" @change="handleTableChange" size="middle" row-key="id">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity]" :bordered="false">{{ severityTextMap[record.severity] }}</a-tag>
            </template>
            <template v-if="column.key === 'attackType'">
              <a-tag :bordered="false" color="red">{{ record.attackType }}</a-tag>
            </template>
            <template v-if="column.key === 'actionTaken'">
              <a-tag :color="record.actionTaken === 'blocked' ? 'red' : 'blue'" :bordered="false">
                {{ record.actionTaken === 'blocked' ? '已阻断' : '仅检测' }}
              </a-tag>
            </template>
            <template v-if="column.key === 'action'">
              <a-button type="link" size="small" @click="showAlarmDetail(record)">详情</a-button>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 告警详情 Drawer -->
    <a-drawer v-model:open="showDetail" title="RASP 告警详情" width="700">
      <template v-if="detailRecord">
        <a-descriptions :column="2" bordered size="small">
          <a-descriptions-item label="告警 ID">{{ detailRecord.id }}</a-descriptions-item>
          <a-descriptions-item label="告警时间">{{ detailRecord.createdAt }}</a-descriptions-item>
          <a-descriptions-item label="攻击类型"><a-tag :bordered="false" color="red">{{ detailRecord.attackType }}</a-tag></a-descriptions-item>
          <a-descriptions-item label="严重级别"><a-tag :color="severityColorMap[detailRecord.severity]" :bordered="false">{{ severityTextMap[detailRecord.severity] }}</a-tag></a-descriptions-item>
          <a-descriptions-item label="应用">{{ detailRecord.appName }}</a-descriptions-item>
          <a-descriptions-item label="主机">{{ detailRecord.hostname }}</a-descriptions-item>
          <a-descriptions-item label="请求 URL" :span="2">{{ detailRecord.requestUrl }}</a-descriptions-item>
          <a-descriptions-item label="请求方法">{{ detailRecord.requestMethod }}</a-descriptions-item>
          <a-descriptions-item label="来源 IP">{{ detailRecord.sourceIp }}</a-descriptions-item>
          <a-descriptions-item label="攻击载荷" :span="2">
            <pre class="payload-text">{{ detailRecord.payload }}</pre>
          </a-descriptions-item>
          <a-descriptions-item label="匹配规则">{{ detailRecord.ruleName }}</a-descriptions-item>
          <a-descriptions-item label="执行动作">
            <a-tag :color="detailRecord.actionTaken === 'blocked' ? 'red' : 'blue'" :bordered="false">
              {{ detailRecord.actionTaken === 'blocked' ? '已阻断' : '仅检测' }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="调用栈" :span="2">
            <pre class="stack-trace">{{ detailRecord.stackTrace }}</pre>
          </a-descriptions-item>
        </a-descriptions>
      </template>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import type { Dayjs } from 'dayjs'
import apiClient from '@/api/client'

const searchText = ref('')
const filterType = ref<string>()
const filterSeverity = ref<string>()
const filterAction = ref<string>()
const dateRange = ref<[Dayjs, Dayjs]>()
const loading = ref(false)
const alarms = ref<any[]>([])
const showDetail = ref(false)
const detailRecord = ref<any>(null)

const pagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const attackTypes = ref([
  { key: 'sqli', label: 'SQL 注入', count: 0 },
  { key: 'xss', label: 'XSS', count: 0 },
  { key: 'rce', label: '命令注入', count: 0 },
  { key: 'ssrf', label: 'SSRF', count: 0 },
  { key: 'deserialization', label: '反序列化', count: 0 },
  { key: 'path_traversal', label: '路径穿越', count: 0 },
])

const severityColorMap: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
const severityTextMap: Record<string, string> = { critical: '紧急', high: '高危', medium: '中危', low: '低危' }

const columns = [
  { title: '告警时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
  { title: '级别', key: 'severity', width: 80 },
  { title: '攻击类型', key: 'attackType', width: 110 },
  { title: '应用', dataIndex: 'appName', key: 'appName', width: 140 },
  { title: '主机', dataIndex: 'hostname', key: 'hostname', width: 140 },
  { title: '请求 URL', dataIndex: 'requestUrl', key: 'requestUrl', ellipsis: true },
  { title: '来源 IP', dataIndex: 'sourceIp', key: 'sourceIp', width: 130 },
  { title: '动作', key: 'actionTaken', width: 100 },
  { title: '操作', key: 'action', width: 80 },
]

const loadAlarms = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/rasp/alarms', {
      params: { page: pagination.value.current, page_size: pagination.value.pageSize, search: searchText.value || undefined, attack_type: filterType.value || undefined, severity: filterSeverity.value || undefined, action_taken: filterAction.value || undefined },
    })
    alarms.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    if (res.attackStats) {
      attackTypes.value.forEach(at => { at.count = res.attackStats[at.key] ?? 0 })
    }
  } catch { alarms.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadAlarms() }
const showAlarmDetail = (record: any) => { detailRecord.value = record; showDetail.value = true }

onMounted(() => { loadAlarms() })
</script>

<style scoped>
.rasp-alarms-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.attack-stat { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; padding: 16px; text-align: center; cursor: pointer; transition: all 0.2s; }
.attack-stat:hover { border-color: #165DFF; }
.attack-stat.active { border-color: #165DFF; background: #E8F3FF; }
.attack-stat-value { font-size: 22px; font-weight: 700; color: #1D2129; }
.attack-stat-label { font-size: 12px; color: #86909C; margin-top: 4px; }

.dashboard-card { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 16px; padding: 12px 16px; background: #F7F8FA; border-radius: 4px; border: 1px solid #E5E8EF; flex-wrap: wrap; }

.payload-text, .stack-trace { background: #F7F8FA; padding: 8px; border-radius: 4px; font-size: 11px; font-family: 'SF Mono', 'Consolas', monospace; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; margin: 0; color: #1D2129; }
</style>
