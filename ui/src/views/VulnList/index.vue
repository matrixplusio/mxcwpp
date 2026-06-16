<template>
  <div class="vuln-list-page">
    <div class="page-header">
      <h2>漏洞列表</h2>
      <span class="page-header-hint">主机漏洞扫描结果、CVE 明细与受影响主机</span>
    </div>

    <a-alert
      v-if="activeContextText"
      type="info"
      show-icon
      :message="activeContextText"
      style="margin-bottom: 16px"
    />

    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="12" :md="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value">{{ stats.total }}</div>
          <div class="vuln-stat-label">未修复漏洞</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value critical">{{ stats.critical }}</div>
          <div class="vuln-stat-label">紧急漏洞</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value high">{{ stats.high }}</div>
          <div class="vuln-stat-label">高危漏洞</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="vuln-stat-card">
          <div class="vuln-stat-value primary">{{ stats.affectedHosts }}</div>
          <div class="vuln-stat-label">受影响主机</div>
        </div>
      </a-col>
    </a-row>

    <!-- 扫描状态栏 -->
    <div class="scan-status-bar section-row">
      <div class="scan-status-left">
        <span class="scan-status-label">漏洞库同步</span>
        <template v-if="scanStatus && 'version' in scanStatus">
          <a-tag :color="scanStatusColor(scanStatus.status)" :bordered="false">
            {{ scanStatusText(scanStatus.status) }}
          </a-tag>
          <span v-if="scanStatus.version" class="scan-status-info">
            版本 {{ scanStatus.version }}
          </span>
          <span class="scan-status-info">
            {{ formatDateTime(scanStatus.startedAt) }}
          </span>
          <span v-if="scanStatus.duration" class="scan-status-info">
            耗时 {{ scanStatus.duration }}s
          </span>
          <template v-if="scanStatus.errorMsg">
            <template v-if="parsedSourceResults.length > 0">
              <a-tag
                v-for="src in parsedSourceResults"
                :key="src.name"
                :color="src.status === 'success' ? 'green' : src.status === 'skipped' ? 'default' : 'red'"
                :bordered="false"
                size="small"
                style="margin-left: 4px"
              >
                <a-tooltip v-if="src.error" :title="src.error">
                  {{ src.name }}: {{ src.status === 'success' ? '成功' : src.status === 'skipped' ? '跳过' : '失败' }}
                </a-tooltip>
                <template v-else>
                  {{ src.name }}: {{ src.status === 'success' ? '成功' : src.status === 'skipped' ? '跳过' : '失败' }}
                </template>
              </a-tag>
            </template>
            <a-tooltip v-else :title="scanStatus.errorMsg">
              <span class="scan-status-error">{{ scanStatus.errorMsg }}</span>
            </a-tooltip>
          </template>
        </template>
        <span v-else class="scan-status-info">尚未执行过扫描</span>
      </div>
      <div class="scan-status-actions">
        <a-button size="small" @click="showScanHistory">历史记录</a-button>
        <a-button size="small" type="primary" @click="handleSync">手动同步</a-button>
        <a-button size="small" type="primary" @click="scanDialogOpen = true">立即扫描</a-button>
      </div>
    </div>

    <!-- 定向扫描进度（targeted scan v1） -->
    <ScanTaskProgress
      v-if="activeTaskId"
      :task-id="activeTaskId"
      @done="onScanDone"
      @close="activeTaskId = ''"
    />

    <ScanScopeDialog v-model:open="scanDialogOpen" @success="onScanStarted" />

    <div class="dashboard-card">
      <div class="card-body">
        <!-- subscope tab 切换:业务 / 云厂商组件 / 监控探针 / 安全平台 / 系统库 / OS 包 / 全部 -->
        <a-tabs v-model:active-key="subscopeTab" @change="handleSubscopeTabChange" style="margin-bottom: 12px">
          <a-tab-pane key="" tab="全部" />
          <a-tab-pane key="business_binary,business_jar" tab="🟢 业务" />
          <a-tab-pane key="cloud_agent" tab="☁️ 云厂商组件" />
          <a-tab-pane key="monitoring_agent" tab="📊 监控探针" />
          <a-tab-pane key="security_agent" tab="🛡 安全平台" />
          <a-tab-pane key="system_tool" tab="🔨 系统工具" />
          <a-tab-pane key="os_package" tab="📦 OS 包" />
          <a-tab-pane key="system_lib" tab="🔧 系统库" />
          <a-tab-pane key="unknown" tab="❓ 未分类" />
        </a-tabs>

        <div class="filter-bar">
          <a-input-search
            v-model:value="searchText"
            placeholder="搜索 CVE / CNVD / CNNVD / 组件 / 主机"
            style="width: 320px"
            allow-clear
            @search="handleFilterChange"
          />

          <a-input
            v-model:value="filterComponent"
            placeholder="组件 / 软件包"
            style="width: 220px"
            allow-clear
            @change="handleFilterChange"
          />

          <a-select
            v-model:value="filterSeverity"
            style="width: 140px"
            placeholder="严重级别"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="critical">紧急</a-select-option>
            <a-select-option value="high">高危</a-select-option>
            <a-select-option value="medium">中危</a-select-option>
            <a-select-option value="low">低危</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterStatus"
            style="width: 140px"
            placeholder="修复状态"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="unpatched">未修复</a-select-option>
            <a-select-option value="patched">已修复</a-select-option>
            <a-select-option value="ignored">已忽略</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterExploitStatus"
            style="width: 140px"
            placeholder="利用状态"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="in_kev">在野利用</a-select-option>
            <a-select-option value="has_exploit">有 Exploit</a-select-option>
            <a-select-option value="none">无 Exploit</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterPriority"
            style="width: 140px"
            placeholder="优先级"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="high">高</a-select-option>
            <a-select-option value="medium-high">中高</a-select-option>
            <a-select-option value="medium">中</a-select-option>
            <a-select-option value="low">低</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterVulnCategory"
            style="width: 150px"
            placeholder="类别"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="kernel">内核</a-select-option>
            <a-select-option value="critical_shared_lib">关键共享库</a-select-option>
            <a-select-option value="shared_lib">共享库</a-select-option>
            <a-select-option value="system_daemon">系统服务</a-select-option>
            <a-select-option value="cli_tool">CLI 工具</a-select-option>
            <a-select-option value="web_service">Web 服务</a-select-option>
            <a-select-option value="db_service">数据库</a-select-option>
            <a-select-option value="container_runtime">容器运行时</a-select-option>
            <a-select-option value="virtualization">虚拟化</a-select-option>
            <a-select-option value="language_dep">语言依赖</a-select-option>
            <a-select-option value="other">其他</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterRestartAction"
            style="width: 170px"
            placeholder="重启影响"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="reboot_host">🔴 需重启主机</a-select-option>
            <a-select-option value="restart_dependent_services">🟠 需重启依赖</a-select-option>
            <a-select-option value="restart_specific_service">🟡 需重启服务</a-select-option>
            <a-select-option value="no_action">🟢 无需重启</a-select-option>
            <a-select-option value="rebuild_app">🔵 需重 build</a-select-option>
            <a-select-option value="unknown">⚪ 影响未知</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterAssetType"
            style="width: 150px"
            placeholder="资产类型"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="os">🖥 OS 主机</a-select-option>
            <a-select-option value="middleware">⚙️ 中间件</a-select-option>
            <a-select-option value="app">📦 应用依赖</a-select-option>
            <a-select-option value="container">🐳 容器</a-select-option>
            <a-select-option value="image">🖼 镜像</a-select-option>
            <a-select-option value="unknown">❓ 未分类</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterFixOwner"
            style="width: 150px"
            placeholder="责任方"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="ops">运维</a-select-option>
            <a-select-option value="sre">SRE</a-select-option>
            <a-select-option value="dba">DBA</a-select-option>
            <a-select-option value="dev">研发</a-select-option>
            <a-select-option value="image_maintainer">镜像维护</a-select-option>
            <a-select-option value="unknown">未分配</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterCWECategory"
            style="width: 160px"
            placeholder="攻击类型 CWE"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="rce">远程代码执行</a-select-option>
            <a-select-option value="privesc">权限提升</a-select-option>
            <a-select-option value="sqli">SQL 注入</a-select-option>
            <a-select-option value="xss">跨站脚本</a-select-option>
            <a-select-option value="info_disclosure">信息泄露</a-select-option>
            <a-select-option value="path_traversal">路径遍历</a-select-option>
            <a-select-option value="ssrf">SSRF</a-select-option>
            <a-select-option value="dos">拒绝服务</a-select-option>
            <a-select-option value="other">其他</a-select-option>
          </a-select>

          <a-select
            v-model:value="filterSort"
            style="width: 160px"
            placeholder="排序方式"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="priority_score">按优先级</a-select-option>
            <a-select-option value="cvss_score">按 CVSS</a-select-option>
          </a-select>

          <div class="filter-actions">
            <a-button @click="handleReset">重置</a-button>
            <a-button @click="handleExport">导出当前结果</a-button>
            <a-button
              v-if="isAdmin"
              :loading="preCheckAllOnlineLoading"
              @click="handlePreCheckAllOnline"
            >
              全集群 Pre-check
            </a-button>
            <a-dropdown>
              <a-button type="primary">立即扫描 <DownOutlined /></a-button>
              <template #overlay>
                <a-menu @click="handleScanMenu">
                  <a-menu-item key="full_scan">全量扫描</a-menu-item>
                  <a-menu-item key="incremental_scan">增量扫描</a-menu-item>
                </a-menu>
              </template>
            </a-dropdown>
          </div>
        </div>

        <div v-if="selectedRowKeys.length > 0" class="batch-action-bar">
          <span>已选择 {{ selectedRowKeys.length }} 项</span>
          <a-button type="primary" size="small" :loading="batchLoading" @click="handleBatchRemediate">
            批量创建修复任务
          </a-button>
          <a-button size="small" @click="selectedRowKeys = []">取消选择</a-button>
        </div>

        <a-table
          :columns="columns"
          :data-source="vulns"
          :loading="loading"
          :pagination="pagination"
          size="middle"
          row-key="id"
          :row-selection="{ selectedRowKeys, onChange: onSelectChange, getCheckboxProps: (record: Vulnerability) => ({ disabled: record.status !== 'unpatched' }) }"
          @change="handleTableChange"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'cve'">
              <RouterLink :to="`/vuln-list/${record.id}`">{{ record.cveId }}</RouterLink>
              <a-tag v-if="!record.cveId?.startsWith('CVE-')" color="orange" :bordered="false" style="margin-left: 4px; font-size: 10px; line-height: 16px">Advisory</a-tag>
            </template>

            <template v-else-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity] || 'default'" :bordered="false">
                {{ severityTextMap[record.severity] || record.severity }}
              </a-tag>
            </template>

            <template v-else-if="column.key === 'cvss'">
              <span :class="cvssClass(record.cvssScore)">{{ record.cvssScore }}</span>
            </template>

            <template v-else-if="column.key === 'exploit'">
              <a-tag v-if="record.inKev" color="red" :bordered="false">在野利用</a-tag>
              <a-tag v-else-if="record.hasExploit" color="orange" :bordered="false">有 Exploit</a-tag>
            </template>

            <template v-else-if="column.key === 'priority'">
              <a-tag :color="priorityColor(record.priorityScore)" :bordered="false">
                {{ priorityText(record.priorityScore) }}
              </a-tag>
              <span style="margin-left: 4px; font-size: 12px; color: #86909C">
                {{ (record.priorityScore ?? 0).toFixed(2) }}
              </span>
            </template>

            <template v-else-if="column.key === 'status'">
              <a-tag :color="statusColor(record.status)" :bordered="false">
                {{ statusTextMap[record.status] || record.status }}
              </a-tag>
            </template>

            <template v-else-if="column.key === 'component'">
              <div style="line-height: 1.4">
                <a-tooltip :title="purlTypeFromComponent(record.component || '').tip">
                  <a-tag :color="purlTypeFromComponent(record.component || '').color" :bordered="false" style="font-size: 10px; margin-right: 4px">
                    {{ purlTypeFromComponent(record.component || '').type }}
                  </a-tag>
                </a-tooltip>
                <span style="font-size: 12px">{{ record.component || '-' }}</span>
              </div>
            </template>

            <template v-else-if="column.key === 'category'">
              <a-tag :color="safeVulnCat(effectiveCategory(record)).color" :bordered="false">
                {{ safeVulnCat(effectiveCategory(record)).text }}
              </a-tag>
              <span v-if="record.vulnCategoryOverride" style="margin-left:4px;font-size:11px;color:#86909C">(manual)</span>
            </template>

            <template v-else-if="column.key === 'cwe'">
              <a-tooltip :title="record.cweId || ''">
                <a-tag :color="safeCWE(record.cweCategory || 'other').color" :bordered="false">
                  {{ safeCWE(record.cweCategory || 'other').text }}
                </a-tag>
              </a-tooltip>
            </template>

            <template v-else-if="column.key === 'assetType'">
              <a-tag :color="safeAssetType(firstHostAssetType(record) || 'unknown').color" :bordered="false">
                {{ safeAssetType(firstHostAssetType(record) || 'unknown').icon }} {{ safeAssetType(firstHostAssetType(record) || 'unknown').text }}
              </a-tag>
            </template>

            <template v-else-if="column.key === 'fixOwner'">
              <a-tag :color="safeFixOwner(firstHostFixOwner(record) || 'unknown').color" :bordered="false">
                {{ safeFixOwner(firstHostFixOwner(record) || 'unknown').text }}
              </a-tag>
            </template>

            <template v-else-if="column.key === 'subscope'">
              <a-tooltip :title="safeSubscope(firstHostSubscope(record) || 'unknown').text">
                <a-tag :color="safeSubscope(firstHostSubscope(record) || 'unknown').color" :bordered="false">
                  {{ safeSubscope(firstHostSubscope(record) || 'unknown').icon }} {{ safeSubscope(firstHostSubscope(record) || 'unknown').text }}
                </a-tag>
              </a-tooltip>
            </template>

            <template v-else-if="column.key === 'source'">
              <a-tooltip :title="record.hostBinaryPath || record.hosts?.[0]?.hostBinaryPath || '-'">
                <span style="font-family: monospace; font-size: 12px; color: #595959">
                  {{ shortBinary(record.hostBinaryPath || record.hosts?.[0]?.hostBinaryPath) || '—' }}
                </span>
              </a-tooltip>
            </template>

            <template v-else-if="column.key === 'restart'">
              <a-tooltip :title="`修复影响：${safeRestart(effectiveRestartAction(record)).text}`">
                <a-tag :color="safeRestart(effectiveRestartAction(record)).color" :bordered="false">
                  {{ safeRestart(effectiveRestartAction(record)).text }}
                </a-tag>
              </a-tooltip>
            </template>

            <template v-else-if="column.key === 'hosts'">
              <span>{{ hostSummary(record) }}</span>
            </template>

            <template v-else-if="column.key === 'action'">
              <a-space>
                <RouterLink :to="`/vuln-list/${record.id}`">
                  <a-button type="link" size="small">详情</a-button>
                </RouterLink>
                <a-button
                  v-if="record.status === 'unpatched'"
                  type="link"
                  size="small"
                  @click="handleIgnore(record)"
                >
                  忽略
                </a-button>
                <a-button
                  v-if="record.status === 'ignored'"
                  type="link"
                  size="small"
                  @click="handleUnignore(record)"
                >
                  取消忽略
                </a-button>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 扫描历史抽屉 -->
    <a-drawer
      v-model:open="scanHistoryVisible"
      title="漏洞扫描历史"
      width="1080"
      placement="right"
    >
      <a-table
        :columns="scanHistoryColumns"
        :data-source="scanHistoryData"
        :loading="scanHistoryLoading"
        :pagination="scanHistoryPagination"
        size="small"
        row-key="id"
        @change="handleScanHistoryTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'">
            <a-tag :color="scanStatusColor(record.status)" :bordered="false">
              {{ scanStatusText(record.status) }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'errorMsg'">
            <template v-if="record.errorMsg && record.errorMsg.startsWith('[')">
              <a-tag
                v-for="src in JSON.parse(record.errorMsg)"
                :key="src.name"
                :color="src.status === 'success' ? 'green' : src.status === 'skipped' ? 'default' : 'red'"
                :bordered="false"
                size="small"
                style="margin-right: 4px"
              >
                <a-tooltip v-if="src.error" :title="src.error">{{ src.name }}</a-tooltip>
                <template v-else>{{ src.name }}</template>
              </a-tag>
            </template>
            <a-tooltip v-else-if="record.errorMsg" :title="record.errorMsg">
              <span style="color: #EF4444; font-size: 12px; cursor: pointer">{{ record.errorMsg }}</span>
            </a-tooltip>
            <span v-else>-</span>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-button
              type="link"
              size="small"
              @click="goScanHistoryDetail(record.id)"
            >
              详情
            </a-button>
          </template>
        </template>
      </a-table>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { message, Modal } from 'ant-design-vue'
import { DownOutlined } from '@ant-design/icons-vue'
import { vulnerabilitiesApi } from '@/api/vulnerabilities'
import { remediationTasksApi } from '@/api/remediation-tasks'
import { hostVulnPreCheckApi } from '@/api/host-vuln-precheck'
import { useAuthStore } from '@/stores/auth'
import type { SecurityDBSyncRecord } from '@/api/antivirus'
import type { Vulnerability, VulnerabilityStats } from '@/api/types'
import { formatDateTime } from '@/utils/date'
import ScanScopeDialog from './components/ScanScopeDialog.vue'
import ScanTaskProgress from './components/ScanTaskProgress.vue'

const route = useRoute()
const router = useRouter()

// 定向扫描状态
const scanDialogOpen = ref(false)
const activeTaskId = ref('')
function onScanStarted(taskId: string) {
  activeTaskId.value = taskId
}
function onScanDone() {
  // 任务完成后由 onMounted 的 fetchVulnList/loadStats 等已有逻辑刷新（保持 toast 显示统计）
}
// 主机列表点击"扫此机"跳过来后自动显示进度
if (route.query.task_id) {
  activeTaskId.value = String(route.query.task_id)
}
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

const preCheckAllOnlineLoading = ref(false)
const handlePreCheckAllOnline = () => {
  Modal.confirm({
    title: '全集群 Pre-check',
    content:
      '将对所有 online 主机的未修复漏洞触发本机 dnf/apt 实测校验。集群规模大时会消耗包管理器与仓库源带宽，通常需要数十分钟到数小时。是否继续？',
    okText: '确认下发',
    okType: 'primary',
    cancelText: '取消',
    onOk: async () => {
      preCheckAllOnlineLoading.value = true
      try {
        const r = await hostVulnPreCheckApi.triggerAllOnline()
        message.success(
          `已下发：${r.hosts_dispatched}/${r.hosts_total} 主机，共 ${r.scheduled} 条任务（失败 ${r.failed}），结果数十分钟内陆续回报`,
        )
      } catch (error) {
        console.error('全集群 Pre-check 失败:', error)
      } finally {
        preCheckAllOnlineLoading.value = false
      }
    },
  })
}

const searchText = ref('')
const filterSeverity = ref<string>()
const filterStatus = ref<string>()
const filterVulnCategory = ref<string>()
const filterRestartAction = ref<string>()
const filterAssetType = ref<string>()
const filterSubscope = ref<string>()
const filterFixOwner = ref<string>()
const filterCWECategory = ref<string>()
const filterComponent = ref('')
const filterExploitStatus = ref<string>()
const filterPriority = ref<string>()
const filterSort = ref<string>()
const filterHostId = ref<string>()
const subscopeTab = ref<string>('')

const handleSubscopeTabChange = (key: string) => {
  // tab key 可能含多个 subscope (业务=binary+jar) 用逗号分隔,filter 用单值时取首个
  filterSubscope.value = key ? key.split(',')[0] : undefined
  pagination.value.current = 1
  loadVulns()
}

const loading = ref(false)
const vulns = ref<Vulnerability[]>([])
const stats = ref<VulnerabilityStats>({ total: 0, critical: 0, high: 0, affectedHosts: 0 })
const selectedRowKeys = ref<number[]>([])
const batchLoading = ref(false)

const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const severityColorMap: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'blue',
}

const severityTextMap: Record<string, string> = {
  critical: '紧急',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const statusTextMap: Record<string, string> = {
  unpatched: '未修复',
  patched: '已修复',
  ignored: '已忽略',
}

const activeContextText = computed(() => {
  const parts: string[] = []
  if (filterHostId.value) parts.push(`当前已按主机过滤: ${filterHostId.value}`)
  if (filterComponent.value) parts.push(`当前已按组件过滤: ${filterComponent.value}`)
  return parts.join(' | ')
})

const columns = [
  { title: '漏洞编号', key: 'cve', width: 180 },
  { title: '严重级别', key: 'severity', width: 90 },
  { title: 'CVSS', key: 'cvss', width: 70 },
  { title: '攻击类型', key: 'cwe', width: 110 },
  { title: '资产类型', key: 'assetType', width: 110 },
  { title: '细分', key: 'subscope', width: 130 },
  { title: '责任方', key: 'fixOwner', width: 100 },
  { title: '来源', key: 'source', width: 200 },
  { title: '优先级', key: 'priority', width: 130 },
  { title: '利用状态', key: 'exploit', width: 100 },
  { title: '影响组件', dataIndex: 'component', key: 'component', width: 220 },
  { title: '类别', key: 'category', width: 110 },
  { title: '重启影响', key: 'restart', width: 130 },
  { title: '受影响主机', key: 'hosts', width: 140 },
  { title: '状态', key: 'status', width: 90 },
  { title: '发现时间', dataIndex: 'discoveredAt', key: 'discoveredAt', width: 160 },
  { title: '操作', key: 'action', width: 120, fixed: 'right' },
]

// Subscope 显示配置
const subscopeConfig: Record<string, { color: string; text: string; icon: string }> = {
  cloud_agent:      { color: 'geekblue', text: '云厂商组件',   icon: '☁️' },
  monitoring_agent: { color: 'cyan',     text: '监控探针',     icon: '📊' },
  security_agent:   { color: 'purple',   text: '安全平台',     icon: '🛡' },
  system_tool:      { color: 'magenta',  text: '系统工具',     icon: '🔨' },
  system_lib:       { color: 'orange',   text: '系统库',       icon: '🔧' },
  os_package:       { color: 'blue',     text: 'OS 包',        icon: '📦' },
  business_binary:  { color: 'green',    text: '业务 binary',  icon: '🟢' },
  business_jar:     { color: 'green',    text: '业务 jar',     icon: '🟢' },
  unknown:          { color: 'default',  text: '未分类',       icon: '❓' },
}

// PURL 前缀 → 包类型徽章
const purlTypeFromComponent = (comp: string): { type: string; color: string; tip: string } => {
  if (!comp) return { type: 'pkg', color: 'default', tip: '' }
  if (comp.startsWith('pkg:')) {
    const t = comp.split('/')[0].replace('pkg:', '')
    return { type: t, color: 'blue', tip: 'PURL: ' + comp }
  }
  if (comp.includes('/')) {
    // Go module / GitHub path
    if (comp.startsWith('github.com/') || comp.startsWith('golang.org/') || comp.includes('go-')) {
      return { type: 'Go 模块', color: 'cyan', tip: `Go module path: ${comp} (源码 import 路径,非主机服务)` }
    }
    return { type: '模块', color: 'cyan', tip: comp }
  }
  if (comp.includes(':') && (comp.startsWith('io.') || comp.startsWith('org.') || comp.startsWith('com.'))) {
    return { type: 'Java jar', color: 'orange', tip: `Maven GAV: ${comp}` }
  }
  return { type: 'OS 包', color: 'blue', tip: comp }
}

// host_binary_path 截短显示
const shortBinary = (path?: string): string => {
  if (!path) return ''
  const parts = path.split('/')
  if (parts.length <= 3) return path
  return '…/' + parts.slice(-2).join('/')
}

// 资产类型显示配置
const assetTypeConfig: Record<string, { color: string; text: string; icon: string }> = {
  os:         { color: 'blue',     text: 'OS 主机',   icon: '🖥' },
  middleware: { color: 'cyan',     text: '中间件',    icon: '⚙️' },
  app:        { color: 'purple',   text: '应用依赖',  icon: '📦' },
  container:  { color: 'geekblue', text: '容器',      icon: '🐳' },
  image:      { color: 'magenta',  text: '镜像',      icon: '🖼' },
  unknown:    { color: 'default',  text: '未分类',    icon: '❓' },
}

// 修复责任方显示配置
const fixOwnerConfig: Record<string, { color: string; text: string }> = {
  ops:              { color: 'green',    text: '运维' },
  sre:              { color: 'cyan',     text: 'SRE' },
  dba:              { color: 'geekblue', text: 'DBA' },
  dev:              { color: 'purple',   text: '研发' },
  image_maintainer: { color: 'magenta',  text: '镜像维护' },
  cloud_provider:   { color: 'orange',   text: '云厂商' },
  apm_vendor:       { color: 'cyan',     text: 'APM 厂商' },
  platform_team:    { color: 'purple',   text: '平台团队' },
  unknown:          { color: 'default',  text: '未分配' },
}

// 通用 fallback helper(避免某天 backend 加新枚举值 UI 未同步导致 undefined.color 抛错)
const safeFixOwner = (k: string) => fixOwnerConfig[k] || fixOwnerConfig.unknown
const safeAssetType = (k: string) => assetTypeConfig[k] || assetTypeConfig.unknown
const safeSubscope = (k: string) => subscopeConfig[k] || subscopeConfig.unknown
const safeCWE = (k: string) => cweCategoryConfig[k] || cweCategoryConfig.other
const safeVulnCat = (k: string) => vulnCategoryConfig[k] || vulnCategoryConfig.other
const safeRestart = (k: string) => restartActionConfig[k] || restartActionConfig.unknown

// CWE 高级分类显示配置
const cweCategoryConfig: Record<string, { color: string; text: string }> = {
  rce:             { color: 'red',     text: 'RCE 远程执行' },
  privesc:         { color: 'volcano', text: '权限提升' },
  sqli:            { color: 'orange',  text: 'SQL 注入' },
  xss:             { color: 'gold',    text: 'XSS 跨站' },
  info_disclosure: { color: 'cyan',    text: '信息泄露' },
  path_traversal:  { color: 'blue',    text: '路径遍历' },
  ssrf:            { color: 'geekblue',text: 'SSRF' },
  dos:             { color: 'purple',  text: '拒绝服务' },
  other:           { color: 'default', text: '其他' },
}

// 9 类 vuln_category 显示
const vulnCategoryConfig: Record<string, { color: string; text: string }> = {
  kernel:              { color: 'red',     text: '内核' },
  critical_shared_lib: { color: 'volcano', text: '关键共享库' },
  shared_lib:          { color: 'orange',  text: '共享库' },
  system_daemon:       { color: 'gold',    text: '系统服务' },
  cli_tool:            { color: 'green',   text: 'CLI 工具' },
  web_service:         { color: 'cyan',    text: 'Web 服务' },
  db_service:          { color: 'geekblue',text: '数据库' },
  container_runtime:   { color: 'purple',  text: '容器运行时' },
  virtualization:      { color: 'magenta', text: '虚拟化' },
  language_dep:        { color: 'blue',    text: '语言依赖' },
  other:               { color: 'default', text: '其他' },
}

// 5 动作 restart_action 显示
const restartActionConfig: Record<string, { color: string; text: string }> = {
  reboot_host:                { color: 'red',     text: '🔴 需重启主机' },
  restart_dependent_services: { color: 'orange',  text: '🟠 需重启依赖' },
  restart_specific_service:   { color: 'gold',    text: '🟡 需重启服务' },
  no_action:                  { color: 'green',   text: '🟢 无需重启' },
  rebuild_app:                { color: 'blue',    text: '🔵 需重 build' },
  unknown:                    { color: 'default', text: '⚪ 影响未知' },
}

const effectiveCategory = (v: Vulnerability) => v.vulnCategoryOverride || v.vulnCategory || 'other'
const effectiveRestartAction = (v: Vulnerability) => v.restartActionOverride || v.restartAction || 'unknown'

// 优先用 vulnerability 顶层聚合字段(后端从 host_vulnerabilities GROUP BY 算的);
// 没聚合字段时 fallback 到 hosts[0](host_id filter 场景);
// 都没就 unknown
const firstHostAssetType = (v: Vulnerability) => v.assetType || v.hosts?.[0]?.assetType || 'unknown'
const firstHostFixOwner = (v: Vulnerability) => v.fixOwner || v.hosts?.[0]?.fixOwner || 'unknown'
const firstHostSubscope = (v: Vulnerability) => v.subscope || v.hosts?.[0]?.subscope || 'unknown'

// === 扫描状态 ===
const scanStatus = ref<SecurityDBSyncRecord | null>(null)

// 解析 errorMsg 中的数据源同步结果 JSON
const parsedSourceResults = computed(() => {
  const msg = scanStatus.value?.errorMsg
  if (!msg || !msg.startsWith('[')) return []
  try {
    return JSON.parse(msg) as { name: string; status: string; error?: string }[]
  } catch {
    return []
  }
})

const scanHistoryVisible = ref(false)
const scanHistoryLoading = ref(false)
const scanHistoryData = ref<SecurityDBSyncRecord[]>([])
const scanHistoryPagination = ref({
  current: 1,
  pageSize: 10,
  total: 0,
  showSizeChanger: false,
  showTotal: (total: number) => `共 ${total} 条`,
})

const scanHistoryColumns = [
  {
    title: '类型', dataIndex: 'dbType', width: 120,
    customRender: ({ text }: { text: string }) => {
      const m: Record<string, string> = { osv: '全量扫描', 'osv-incremental': '增量扫描', 'vuln-sync': '漏洞库同步' }
      return m[text] || text
    },
  },
  { title: '版本', dataIndex: 'version', width: 140 },
  { title: '状态', key: 'status', width: 80 },
  { title: '耗时(秒)', dataIndex: 'duration', width: 80 },
  { title: '开始时间', dataIndex: 'startedAt', width: 170, customRender: ({ text }: { text: string }) => formatDateTime(text) },
  { title: '扫描摘要', key: 'errorMsg', ellipsis: true },
  { title: '操作', key: 'action', width: 80, fixed: 'right' as const },
]

const scanStatusColor = (status: string) => {
  if (status === 'success') return 'success'
  if (status === 'failed') return 'error'
  if (status === 'running') return 'processing'
  return 'default'
}

const scanStatusText = (status: string) => {
  const map: Record<string, string> = { success: '成功', failed: '失败', running: '扫描中' }
  return map[status] || status
}

const loadScanStatus = async () => {
  try {
    const res = await vulnerabilitiesApi.getScanStatus()
    if ('version' in res) {
      scanStatus.value = res as SecurityDBSyncRecord
    } else {
      scanStatus.value = null
    }
  } catch {
    scanStatus.value = null
  }
}

const showScanHistory = async () => {
  scanHistoryVisible.value = true
  await loadScanHistory()
}

const loadScanHistory = async () => {
  scanHistoryLoading.value = true
  try {
    const res = await vulnerabilitiesApi.getScanHistory({
      page: scanHistoryPagination.value.current,
      page_size: scanHistoryPagination.value.pageSize,
    })
    scanHistoryData.value = res.items ?? []
    scanHistoryPagination.value.total = res.total ?? 0
  } catch {
    scanHistoryData.value = []
  } finally {
    scanHistoryLoading.value = false
  }
}

const goScanHistoryDetail = (id: number) => {
  scanHistoryVisible.value = false
  router.push({ name: 'ScanHistoryDetail', params: { id } })
}

const handleScanHistoryTableChange = (pag: any) => {
  scanHistoryPagination.value.current = pag.current
  loadScanHistory()
}

const syncFiltersFromRoute = () => {
  searchText.value = typeof route.query.search === 'string' ? route.query.search : ''
  filterSeverity.value = typeof route.query.severity === 'string' ? route.query.severity : undefined
  filterStatus.value = typeof route.query.status === 'string' ? route.query.status : undefined
  filterComponent.value = typeof route.query.component === 'string' ? route.query.component : ''
  filterHostId.value = typeof route.query.host_id === 'string' ? route.query.host_id : undefined
}

const syncRouteQuery = () => {
  router.replace({
    query: {
      ...route.query,
      search: searchText.value || undefined,
      severity: filterSeverity.value || undefined,
      status: filterStatus.value || undefined,
      component: filterComponent.value || undefined,
      host_id: filterHostId.value || undefined,
    },
  })
}

const loadVulns = async () => {
  loading.value = true
  try {
    const res = await vulnerabilitiesApi.list({
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      host_id: filterHostId.value || undefined,
      search: searchText.value || undefined,
      severity: filterSeverity.value || undefined,
      status: filterStatus.value || undefined,
      component: filterComponent.value || undefined,
      exploit_status: filterExploitStatus.value || undefined,
      priority: filterPriority.value || undefined,
      vuln_category: filterVulnCategory.value || undefined,
      restart_action: filterRestartAction.value || undefined,
      asset_type: filterAssetType.value || undefined,
      subscope: filterSubscope.value || undefined,
      fix_owner: filterFixOwner.value || undefined,
      cwe_category: filterCWECategory.value || undefined,
      sort: filterSort.value || undefined,
    })
    vulns.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    stats.value = res.stats ?? { total: 0, critical: 0, high: 0, affectedHosts: 0 }
  } catch {
    vulns.value = []
  } finally {
    loading.value = false
  }
}

const handleFilterChange = () => {
  pagination.value.current = 1
  syncRouteQuery()
  loadVulns()
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadVulns()
}

const handleIgnore = async (record: Vulnerability) => {
  try {
    await vulnerabilitiesApi.ignore(record.id)
    message.success('已忽略该漏洞')
    loadVulns()
  } catch (error) {
    console.error('忽略漏洞失败:', error)
  }
}

const handleUnignore = async (record: Vulnerability) => {
  try {
    await vulnerabilitiesApi.unignore(record.id)
    message.success('已取消忽略')
    loadVulns()
  } catch (error) {
    console.error('取消忽略失败:', error)
  }
}

const handleBatchRemediate = async () => {
  if (selectedRowKeys.value.length === 0) {
    message.warning('请先选择要修复的漏洞')
    return
  }
  batchLoading.value = true
  try {
    const res = await remediationTasksApi.batchCreate(selectedRowKeys.value)
    let msg = `已为 ${res.vulnCount} 个漏洞、${res.hostCount} 台主机创建 ${res.created} 个修复任务`
    if (res.skipped > 0) {
      msg += `，跳过 ${res.skipped} 个（已有进行中任务）`
    }
    msg += '，请前往修复任务页面确认执行'
    message.success(msg)
    selectedRowKeys.value = []
  } catch (error) {
    console.error('批量创建修复任务失败:', error)
  } finally {
    batchLoading.value = false
  }
}

const onSelectChange = (keys: number[]) => {
  selectedRowKeys.value = keys
}

const handleSync = async () => {
  try {
    await vulnerabilitiesApi.triggerSync()
    message.success('漏洞库同步任务已启动（NVD + Red Hat）')
    setTimeout(() => loadScanStatus(), 2000)
  } catch (error) {
    console.error('启动漏洞库同步失败:', error)
  }
}

const handleScanMenu = async ({ key }: { key: string }) => {
  const scanType = key as 'full_scan' | 'incremental_scan'
  const label = scanType === 'incremental_scan' ? '增量扫描' : '全量扫描'
  try {
    await vulnerabilitiesApi.triggerScan(scanType)
    message.success(`${label}任务已启动`)
    setTimeout(() => loadScanStatus(), 2000)
  } catch (error) {
    console.error(`${label}任务启动失败:`, error)
  }
}

const handleExport = () => {
  if (vulns.value.length === 0) {
    message.warning('当前没有可导出的漏洞数据')
    return
  }

  const rows = [
    ['CVE', 'CNVD', 'CNNVD', 'Severity', 'CVSS', 'PriorityScore', 'ExploitStatus', 'Component', 'AffectedHosts', 'Status', 'DiscoveredAt'],
    ...vulns.value.map((item) => [
      item.cveId,
      item.cnvdId || '',
      item.cnnvdId || '',
      item.severity,
      String(item.cvssScore ?? ''),
      String(item.priorityScore ?? ''),
      item.inKev ? '在野利用' : item.hasExploit ? '有Exploit' : '',
      item.component || '',
      String(item.affectedHosts ?? 0),
      item.status || '',
      item.discoveredAt || '',
    ]),
  ]

  const csv = rows
    .map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(','))
    .join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.setAttribute('download', `vulnerabilities_${new Date().toISOString().slice(0, 10)}.csv`)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
  message.success('已导出当前结果')
}

const handleReset = () => {
  searchText.value = ''
  filterSeverity.value = undefined
  filterStatus.value = undefined
  filterComponent.value = ''
  filterExploitStatus.value = undefined
  filterPriority.value = undefined
  filterVulnCategory.value = undefined
  filterRestartAction.value = undefined
  filterAssetType.value = undefined
  filterSubscope.value = undefined
  filterFixOwner.value = undefined
  filterCWECategory.value = undefined
  filterSort.value = undefined
  filterHostId.value = undefined
  subscopeTab.value = ''
  pagination.value.current = 1
  syncRouteQuery()
  loadVulns()
}

const hostSummary = (record: Vulnerability) => {
  // 全局视图：统一显示受影响主机数量
  if (!filterHostId.value) {
    const count = record.affectedHosts || record.hosts?.length || 0
    return `${count} 台主机`
  }
  // 按主机筛选时：显示主机名详情
  if (!record.hosts?.length) return `${record.affectedHosts || 0} 台主机`
  if (record.hosts.length === 1) {
    return `${record.hosts[0].hostname || record.hosts[0].hostId} (${record.hosts[0].ip || '-'})`
  }
  return `${record.hosts[0].hostname || record.hosts[0].hostId} 等 ${record.hosts.length} 台`
}

const statusColor = (status: string) => {
  if (status === 'patched') return 'green'
  if (status === 'ignored') return 'default'
  return 'red'
}

const cvssClass = (score: number) => {
  if (score >= 9) return 'score-critical'
  if (score >= 7) return 'score-high'
  return 'score-normal'
}

const priorityColor = (score?: number) => {
  if (!score) return 'default'
  if (score >= 0.75) return 'red'
  if (score >= 0.50) return 'orange'
  if (score >= 0.25) return 'gold'
  return 'blue'
}

const priorityText = (score?: number) => {
  if (!score) return '未评分'
  if (score >= 0.75) return '高'
  if (score >= 0.50) return '中高'
  if (score >= 0.25) return '中'
  return '低'
}

watch(
  () => route.query,
  () => {
    syncFiltersFromRoute()
    loadVulns()
  }
)

onMounted(() => {
  syncFiltersFromRoute()
  loadVulns()
  loadScanStatus()
})
</script>

<style scoped>
.vuln-list-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.vuln-stat-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}

.vuln-stat-value {
  font-size: 28px;
  font-weight: 700;
  color: var(--mxsec-text-1);
}

.vuln-stat-value.critical { color: #EF4444; }
.vuln-stat-value.high { color: #F59E0B; }
.vuln-stat-value.primary { color: var(--mxsec-primary); }

.vuln-stat-label {
  margin-top: 8px;
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
}

.card-body {
  padding: 20px;
}

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}

.filter-actions {
  display: flex;
  gap: 8px;
  margin-left: auto;
}

.score-critical {
  color: #EF4444;
  font-weight: 700;
}

.score-high {
  color: #F59E0B;
  font-weight: 700;
}

.score-normal {
  color: var(--mxsec-text-1);
  font-weight: 600;
}

.batch-action-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  margin-bottom: 12px;
  background: var(--mxsec-primary-bg);
  border: 1px solid #BEDAFF;
  border-radius: 6px;
  font-size: 13px;
}

.scan-status-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 12px 20px;
}

.scan-status-left {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.scan-status-label {
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.scan-status-info {
  color: var(--mxsec-text-3);
  font-size: 13px;
}

.scan-status-error {
  color: #EF4444;
  font-size: 13px;
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.scan-status-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}



@media (max-width: 960px) {
  .filter-actions {
    margin-left: 0;
  }
  .scan-status-bar { flex-direction: column; gap: 8px; align-items: flex-start; }
}
</style>
