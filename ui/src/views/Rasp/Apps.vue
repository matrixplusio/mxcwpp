<template>
  <div class="rasp-apps-page">
    <div class="page-header">
      <h2>应用列表</h2>
      <span class="page-header-hint">RASP (运行时应用自我保护) 监控的应用进程</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="6">
        <div class="rasp-stat-card">
          <div class="rasp-stat-value">{{ stats.total }}</div>
          <div class="rasp-stat-label">监控应用总数</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="rasp-stat-card">
          <div class="rasp-stat-value" style="color: #00B42A">{{ stats.protected }}</div>
          <div class="rasp-stat-label">防护中</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="rasp-stat-card">
          <div class="rasp-stat-value" style="color: #F53F3F">{{ stats.alarms }}</div>
          <div class="rasp-stat-label">待处理告警</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="rasp-stat-card">
          <div class="rasp-stat-value" style="color: #FF7D00">{{ stats.vulns }}</div>
          <div class="rasp-stat-label">运行时漏洞</div>
        </div>
      </a-col>
    </a-row>

    <!-- 应用列表 -->
    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search v-model:value="searchText" placeholder="搜索应用名称或进程" style="width: 240px" allow-clear @search="loadApps" />
          <a-select v-model:value="filterLanguage" style="width: 140px" placeholder="语言/框架" allow-clear @change="loadApps">
            <a-select-option value="java">Java</a-select-option>
            <a-select-option value="python">Python</a-select-option>
            <a-select-option value="nodejs">Node.js</a-select-option>
            <a-select-option value="php">PHP</a-select-option>
            <a-select-option value="golang">Go</a-select-option>
          </a-select>
          <a-select v-model:value="filterStatus" style="width: 120px" placeholder="状态" allow-clear @change="loadApps">
            <a-select-option value="protected">防护中</a-select-option>
            <a-select-option value="monitoring">监控中</a-select-option>
            <a-select-option value="offline">离线</a-select-option>
          </a-select>
        </div>

        <a-table :columns="columns" :data-source="apps" :loading="loading" :pagination="pagination" @change="handleTableChange" size="middle" row-key="id">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'language'">
              <a-tag :bordered="false">{{ record.language }}</a-tag>
            </template>
            <template v-if="column.key === 'status'">
              <span class="status-dot" :class="`dot-${record.status}`"></span>
              {{ raspStatusText[record.status] }}
            </template>
            <template v-if="column.key === 'mode'">
              <a-tag :color="record.mode === 'block' ? 'red' : record.mode === 'monitor' ? 'blue' : 'default'" :bordered="false">
                {{ modeTextMap[record.mode] }}
              </a-tag>
            </template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="showAppDetail(record)">详情</a-button>
                <a-button type="link" size="small" @click="handleConfigure(record)">配置</a-button>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 应用详情 Drawer -->
    <a-drawer v-model:open="showDetail" :title="detailRecord?.appName" width="640">
      <template v-if="detailRecord">
        <a-descriptions :column="2" bordered size="small">
          <a-descriptions-item label="应用名称">{{ detailRecord.appName }}</a-descriptions-item>
          <a-descriptions-item label="语言/框架">{{ detailRecord.language }}</a-descriptions-item>
          <a-descriptions-item label="进程名">{{ detailRecord.processName }}</a-descriptions-item>
          <a-descriptions-item label="PID">{{ detailRecord.pid }}</a-descriptions-item>
          <a-descriptions-item label="主机">{{ detailRecord.hostname }}</a-descriptions-item>
          <a-descriptions-item label="监听端口">{{ detailRecord.listenPorts }}</a-descriptions-item>
          <a-descriptions-item label="RASP 版本">{{ detailRecord.raspVersion }}</a-descriptions-item>
          <a-descriptions-item label="防护模式"><a-tag :color="detailRecord.mode === 'block' ? 'red' : 'blue'" :bordered="false">{{ modeTextMap[detailRecord.mode] }}</a-tag></a-descriptions-item>
          <a-descriptions-item label="接入时间">{{ detailRecord.createdAt }}</a-descriptions-item>
          <a-descriptions-item label="最后心跳">{{ detailRecord.lastHeartbeat }}</a-descriptions-item>
        </a-descriptions>

        <a-divider>防护规则</a-divider>
        <a-table :columns="ruleColumns" :data-source="detailRecord.rules ?? []" :pagination="false" size="small">
          <template #bodyCell="{ column, record: rule }">
            <template v-if="column.key === 'enabled'">
              <a-tag :color="rule.enabled ? 'green' : 'default'" :bordered="false">{{ rule.enabled ? '启用' : '禁用' }}</a-tag>
            </template>
          </template>
        </a-table>
      </template>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import apiClient from '@/api/client'

const router = useRouter()
const searchText = ref('')
const filterLanguage = ref<string>()
const filterStatus = ref<string>()
const loading = ref(false)
const apps = ref<any[]>([])
const showDetail = ref(false)
const detailRecord = ref<any>(null)
const stats = ref({ total: 0, protected: 0, alarms: 0, vulns: 0 })

const pagination = ref({ current: 1, pageSize: 20, total: 0, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` })

const raspStatusText: Record<string, string> = { protected: '防护中', monitoring: '监控中', offline: '离线' }
const modeTextMap: Record<string, string> = { block: '阻断模式', monitor: '监控模式', off: '已关闭' }

const columns = [
  { title: '应用名称', dataIndex: 'appName', key: 'appName', width: 180 },
  { title: '语言/框架', key: 'language', width: 120 },
  { title: '进程名', dataIndex: 'processName', key: 'processName', width: 140 },
  { title: '主机', dataIndex: 'hostname', key: 'hostname', width: 160 },
  { title: '监听端口', dataIndex: 'listenPorts', key: 'listenPorts', width: 120 },
  { title: '防护模式', key: 'mode', width: 110 },
  { title: '状态', key: 'status', width: 100 },
  { title: '告警数', dataIndex: 'alarmCount', key: 'alarmCount', width: 80 },
  { title: '漏洞数', dataIndex: 'vulnCount', key: 'vulnCount', width: 80 },
  { title: '操作', key: 'action', width: 130 },
]

const ruleColumns = [
  { title: '规则名称', dataIndex: 'name', key: 'name' },
  { title: '类型', dataIndex: 'type', key: 'type', width: 120 },
  { title: '状态', key: 'enabled', width: 80 },
]

const loadApps = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/rasp/apps', {
      params: { page: pagination.value.current, page_size: pagination.value.pageSize, search: searchText.value || undefined, language: filterLanguage.value || undefined, status: filterStatus.value || undefined },
    })
    apps.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    if (res.stats) stats.value = res.stats
  } catch { apps.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => { pagination.value.current = pag.current; pagination.value.pageSize = pag.pageSize; loadApps() }
const showAppDetail = (record: any) => { detailRecord.value = record; showDetail.value = true }
const handleConfigure = (record: any) => { router.push({ path: '/rasp/config', query: { appId: record.id } }) }

onMounted(() => { loadApps() })
</script>

<style scoped>
.rasp-apps-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.rasp-stat-card { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; padding: 20px; text-align: center; }
.rasp-stat-value { font-size: 28px; font-weight: 700; color: #1D2129; line-height: 1.2; }
.rasp-stat-label { font-size: 13px; color: #86909C; margin-top: 4px; }

.dashboard-card { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 16px; padding: 12px 16px; background: #F7F8FA; border-radius: 4px; border: 1px solid #E5E8EF; }

.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.dot-protected { background: #00B42A; box-shadow: 0 0 0 3px rgba(0,180,42,0.15); }
.dot-monitoring { background: #165DFF; box-shadow: 0 0 0 3px rgba(22,93,255,0.15); }
.dot-offline { background: #C9CDD4; }
</style>
