<template>
  <div class="doc">
    <!-- ============== 封面 (page 1) ============== -->
    <section class="doc-cover">
      <div class="doc-cover__brand">
        <svg viewBox="0 0 64 64" class="doc-cover__logo">
          <rect width="64" height="64" rx="14" fill="url(#coverG)" />
          <path d="M18 22L32 14L46 22V42L32 50L18 42V22Z" stroke="#fff" stroke-width="3" stroke-linejoin="round" />
          <path d="M32 14V50" stroke="#fff" stroke-width="2" stroke-dasharray="3 3" />
          <defs>
            <linearGradient id="coverG" x1="0" y1="0" x2="64" y2="64">
              <stop stop-color="#2563eb" />
              <stop offset="1" stop-color="#722ed1" />
            </linearGradient>
          </defs>
        </svg>
        <div>
          <div class="doc-cover__brand-name">矩阵云安全平台</div>
          <div class="doc-cover__brand-en">MxSec Security Platform</div>
        </div>
      </div>

      <div class="doc-cover__center">
        <div class="doc-cover__kind">EDR 端点检测响应</div>
        <h1 class="doc-cover__title">专项分析报告</h1>
        <div class="doc-cover__period">{{ report.meta.period }}</div>
      </div>

      <div class="doc-cover__meta">
        <div class="doc-cover__meta-row">
          <span class="doc-cover__meta-label">报告编号</span>
          <span class="doc-cover__meta-value">{{ report.meta.reportID }}</span>
        </div>
        <div class="doc-cover__meta-row">
          <span class="doc-cover__meta-label">生成时间</span>
          <span class="doc-cover__meta-value">{{ report.meta.generatedAt }}</span>
        </div>
        <div class="doc-cover__meta-row">
          <span class="doc-cover__meta-label">在线主机</span>
          <span class="doc-cover__meta-value">{{ report.meta.onlineHosts }} 台</span>
        </div>
        <div class="doc-cover__meta-row">
          <span class="doc-cover__meta-label">检测规则</span>
          <span class="doc-cover__meta-value">{{ report.meta.enabledRules }} / {{ report.meta.totalRules }} 条启用</span>
        </div>
        <div class="doc-cover__classification">机密 · 仅限内部使用</div>
      </div>
    </section>

    <!-- ============== 目录 (page 2) ============== -->
    <section class="doc-page doc-toc">
      <h2 class="doc-toc__title">目 录</h2>
      <ol class="doc-toc__list">
        <li><span>执行摘要</span><span class="doc-toc__page">03</span></li>
        <li><span>关键指标概览</span><span class="doc-toc__page">04</span></li>
        <li><span>威胁等级与战术分布</span><span class="doc-toc__page">05</span></li>
        <li><span>原始事件量分析</span><span class="doc-toc__page">06</span></li>
        <li><span>Top 触发规则与受影响主机</span><span class="doc-toc__page">07</span></li>
        <li><span>自动响应与处置统计</span><span class="doc-toc__page">08</span></li>
        <li><span>IOC 与内存威胁</span><span class="doc-toc__page">09</span></li>
        <li><span>规则有效性评估</span><span class="doc-toc__page">10</span></li>
        <li><span>攻击故事线与误报抑制</span><span class="doc-toc__page">11</span></li>
        <li><span>改进建议</span><span class="doc-toc__page">12</span></li>
      </ol>
      <div class="doc-toc__hint">本报告由矩阵云安全平台基于 ClickHouse 实时数据自动生成。所有数据均来源于生产环境实际遥测，未经人工调整。</div>
    </section>

    <!-- ============== §1 执行摘要 ============== -->
    <section class="doc-page">
      <h2 class="doc-h2">1. 执行摘要</h2>
      <p class="doc-p">
        本报告覆盖 <b>{{ report.meta.period }}</b>，对接入矩阵云安全平台的 <b>{{ report.meta.onlineHosts }}</b> 台主机的端点检测响应（EDR）数据进行统计分析。
        报告期内，平台基于 <b>{{ report.meta.enabledRules }}</b> 条启用检测规则共触发告警 <b>{{ report.summary.totalAlerts }}</b> 条，
        其中活跃告警 <b>{{ report.summary.activeAlerts }}</b> 条、已忽略 <b>{{ report.summary.ignoredAlerts }}</b> 条，
        受影响主机 <b>{{ report.summary.affectedHosts }}</b> 台，触发攻击故事线 <b>{{ report.summary.totalStories }}</b> 条
        （其中高危故事线 <b>{{ report.summary.highRiskStories }}</b> 条）。
      </p>
      <p class="doc-p">
        与上一周期对比，告警量{{ trendVerb }} <b>{{ Math.abs(report.trend.growthPercent).toFixed(1) }}%</b>
        （上一周期 {{ report.trend.prevPeriodAlerts }} 条 → 本期 {{ report.summary.totalAlerts }} 条），整体威胁态势<b>{{ trendDescriptor }}</b>。
      </p>

      <h3 class="doc-h3">核心结论</h3>
      <ul class="doc-ul">
        <li v-for="(c, i) in conclusions" :key="i">{{ c }}</li>
      </ul>
    </section>

    <!-- ============== §2 关键指标概览 ============== -->
    <section class="doc-page">
      <h2 class="doc-h2">2. 关键指标概览</h2>
      <p class="doc-p">下表汇总本报告周期内最核心的运营指标，作为后续章节的基础参考。</p>
      <table class="doc-table doc-table--kv">
        <thead>
          <tr><th>指标</th><th>本周期</th><th>说明</th></tr>
        </thead>
        <tbody>
          <tr><td>在线主机</td><td>{{ report.meta.onlineHosts }} 台</td><td>报告生成时刻心跳正常的 Agent 数量</td></tr>
          <tr><td>启用规则</td><td>{{ report.meta.enabledRules }} / {{ report.meta.totalRules }}</td><td>规则启用率 {{ ruleEnableRate.toFixed(1) }}%</td></tr>
          <tr><td>告警总数</td><td>{{ report.summary.totalAlerts }}</td><td>含活跃、已解决、已忽略所有状态</td></tr>
          <tr><td>活跃告警</td><td>{{ report.summary.activeAlerts }}</td><td>未处置告警，需人工/自动响应处理</td></tr>
          <tr><td>已解决告警</td><td>{{ report.summary.resolvedAlerts }}</td><td>含自动处置与人工确认完成</td></tr>
          <tr><td>已忽略告警</td><td>{{ report.summary.ignoredAlerts }}</td><td>误报抑制或运维白名单</td></tr>
          <tr><td>受影响主机</td><td>{{ report.summary.affectedHosts }} 台</td><td>报告周期内至少触发一次告警的主机</td></tr>
          <tr><td>攻击故事线</td><td>{{ report.summary.totalStories }}</td><td>关联多事件形成的攻击链</td></tr>
          <tr><td>高危故事线</td><td>{{ report.summary.highRiskStories }}</td><td>风险评分 ≥ 70 的故事线</td></tr>
          <tr><td>环比变化</td><td>{{ trendArrow }} {{ Math.abs(report.trend.growthPercent).toFixed(1) }}%</td><td>vs 上一周期，方向：{{ trendDescriptor }}</td></tr>
        </tbody>
      </table>
    </section>

    <!-- ============== §3 威胁等级与战术分布 ============== -->
    <section class="doc-page">
      <h2 class="doc-h2">3. 威胁等级与战术分布</h2>
      <p class="doc-p">告警按严重程度与 MITRE ATT&amp;CK 战术维度分布，反映本周期主要威胁面。</p>

      <div class="doc-figure">
        <VChart theme="mxsec" :option="severityOption" class="doc-chart" autoresize />
        <div class="doc-figure__caption">图 3-1　告警严重程度分布</div>
      </div>

      <table class="doc-table">
        <thead><tr><th>严重程度</th><th>数量</th><th>占比</th></tr></thead>
        <tbody>
          <tr v-for="row in severityRows" :key="row.key">
            <td>
              <span class="doc-sev-dot" :style="{ background: row.color }"></span>
              {{ row.label }}
            </td>
            <td class="doc-td-num">{{ row.count }}</td>
            <td class="doc-td-num">{{ row.pct.toFixed(1) }}%</td>
          </tr>
        </tbody>
      </table>

      <div class="doc-figure">
        <VChart theme="mxsec" :option="tacticOption" class="doc-chart" autoresize />
        <div class="doc-figure__caption">图 3-2　MITRE ATT&amp;CK 战术分布</div>
      </div>
    </section>

    <!-- ============== §4 原始事件量分析 ============== -->
    <section v-if="report.rawEventStats?.available" class="doc-page">
      <h2 class="doc-h2">4. 原始事件量分析</h2>
      <p class="doc-p">
        EDR Agent 经由内核 eBPF 探针采集进程、网络、文件、模块、提权等原始事件，统一写入 ClickHouse 进行实时检测。
        本周期共采集原始事件 <b>{{ report.rawEventStats.totalEvents.toLocaleString() }}</b> 条，覆盖 <b>{{ report.rawEventStats.uniqueHosts }}</b> 台活跃主机，
        平均每台主机 <b>{{ avgEventsPerHost }}</b> 条，告警转化率 <b>{{ alertConversionRate.toFixed(3) }}%</b>。
      </p>

      <table class="doc-table doc-table--kv">
        <thead><tr><th>指标</th><th>数值</th></tr></thead>
        <tbody>
          <tr><td>总事件数</td><td>{{ report.rawEventStats.totalEvents.toLocaleString() }}</td></tr>
          <tr><td>活跃主机</td><td>{{ report.rawEventStats.uniqueHosts }} 台</td></tr>
          <tr><td>平均事件 / 主机</td><td>{{ avgEventsPerHost }}</td></tr>
          <tr><td>告警转化率</td><td>{{ alertConversionRate.toFixed(3) }}%</td></tr>
        </tbody>
      </table>

      <div class="doc-figure">
        <VChart theme="mxsec" :option="eventTypeOption" class="doc-chart" autoresize />
        <div class="doc-figure__caption">图 4-1　事件类型构成</div>
      </div>

      <div class="doc-figure">
        <VChart theme="mxsec" :option="eventTrendOption" class="doc-chart" autoresize />
        <div class="doc-figure__caption">图 4-2　事件量逐小时趋势</div>
      </div>
    </section>

    <!-- ============== §5 Top 触发规则与受影响主机 ============== -->
    <section class="doc-page">
      <h2 class="doc-h2">5. Top 触发规则与受影响主机</h2>

      <h3 class="doc-h3">5.1　Top 10 触发规则</h3>
      <table class="doc-table">
        <thead><tr><th style="width:48px">#</th><th>规则名称</th><th style="width:90px">级别</th><th style="width:90px" class="doc-td-num">命中</th></tr></thead>
        <tbody>
          <tr v-for="(r, i) in report.topRules" :key="i">
            <td>{{ i + 1 }}</td>
            <td>{{ r.title }}</td>
            <td>
              <span class="doc-sev-pill" :style="{ background: sevColorBg(r.severity), color: severityColors[r.severity] }">
                {{ severityLabelMap[r.severity] || r.severity }}
              </span>
            </td>
            <td class="doc-td-num">{{ r.count }}</td>
          </tr>
          <tr v-if="!report.topRules.length"><td colspan="4" class="doc-td-empty">本周期无规则命中</td></tr>
        </tbody>
      </table>

      <h3 class="doc-h3">5.2　Top 10 受影响主机</h3>
      <table class="doc-table">
        <thead><tr><th style="width:48px">#</th><th>主机</th><th style="width:120px" class="doc-td-num">告警数</th></tr></thead>
        <tbody>
          <tr v-for="(h, i) in report.topHosts" :key="i">
            <td>{{ i + 1 }}</td><td>{{ h.hostname }}</td><td class="doc-td-num">{{ h.count }}</td>
          </tr>
          <tr v-if="!report.topHosts.length"><td colspan="3" class="doc-td-empty">本周期无主机受影响</td></tr>
        </tbody>
      </table>

      <h3 v-if="report.rawEventStats?.available" class="doc-h3">5.3　Top 10 高事件量主机</h3>
      <table v-if="report.rawEventStats?.available" class="doc-table">
        <thead><tr><th style="width:48px">#</th><th>主机</th><th style="width:120px" class="doc-td-num">事件量</th></tr></thead>
        <tbody>
          <tr v-for="(h, i) in report.rawEventStats.topHostsByEvent" :key="i">
            <td>{{ i + 1 }}</td><td>{{ h.hostname }}</td><td class="doc-td-num">{{ h.count.toLocaleString() }}</td>
          </tr>
        </tbody>
      </table>

      <h3 v-if="report.rawEventStats?.topExe?.length" class="doc-h3">5.4　Top 10 进程</h3>
      <table v-if="report.rawEventStats?.topExe?.length" class="doc-table">
        <thead><tr><th style="width:48px">#</th><th>进程路径</th><th style="width:120px" class="doc-td-num">事件量</th></tr></thead>
        <tbody>
          <tr v-for="(p, i) in report.rawEventStats.topExe" :key="i">
            <td>{{ i + 1 }}</td><td class="doc-td-code">{{ p.exe }}</td><td class="doc-td-num">{{ p.count.toLocaleString() }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- ============== §6 自动响应 ============== -->
    <section class="doc-page">
      <h2 class="doc-h2">6. 自动响应与处置统计</h2>
      <p class="doc-p">
        本周期平台共触发自动响应动作 <b>{{ report.autoResponseStats?.total || 0 }}</b> 次，
        含网络封禁 <b>{{ report.autoResponseStats?.networkBlocks || 0 }}</b> 次、
        主机隔离 <b>{{ report.autoResponseStats?.hostIsolations || 0 }}</b> 次、
        进程查杀 <b>{{ report.autoResponseStats?.processKills || 0 }}</b> 次。
      </p>
      <table class="doc-table doc-table--kv">
        <thead><tr><th>动作类型</th><th>执行次数</th><th>说明</th></tr></thead>
        <tbody>
          <tr><td>网络封禁</td><td>{{ report.autoResponseStats?.networkBlocks || 0 }}</td><td>对恶意 IP / 端口下发 iptables / nftables 阻断</td></tr>
          <tr><td>主机隔离</td><td>{{ report.autoResponseStats?.hostIsolations || 0 }}</td><td>仅保留管理通道，断开业务网络</td></tr>
          <tr><td>进程查杀</td><td>{{ report.autoResponseStats?.processKills || 0 }}</td><td>恶意进程 SIGKILL，记录 audit 日志</td></tr>
          <tr><td><b>合计</b></td><td><b>{{ report.autoResponseStats?.total || 0 }}</b></td><td>所有自动响应动作累计</td></tr>
        </tbody>
      </table>
    </section>

    <!-- ============== §7 IOC ============== -->
    <section class="doc-page">
      <h2 class="doc-h2">7. IOC 与内存威胁</h2>
      <p class="doc-p">
        本周期捕获 IOC 快照 <b>{{ report.iocStats?.iocSnapshots || 0 }}</b> 份，内存威胁检测命中 <b>{{ report.iocStats?.memoryThreats || 0 }}</b> 次。
      </p>
      <table v-if="report.iocStats?.topIOCTypes?.length" class="doc-table">
        <thead><tr><th style="width:48px">#</th><th>技术 (MITRE Tx-XXXX)</th><th style="width:120px" class="doc-td-num">命中次数</th></tr></thead>
        <tbody>
          <tr v-for="(t, i) in report.iocStats.topIOCTypes" :key="i">
            <td>{{ i + 1 }}</td><td>{{ t.technique }}</td><td class="doc-td-num">{{ t.count }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="doc-empty">本周期未捕获 IOC / 内存威胁。</p>
    </section>

    <!-- ============== §8 规则有效性 ============== -->
    <section class="doc-page">
      <h2 class="doc-h2">8. 规则有效性评估</h2>
      <p class="doc-p">
        启用规则共 <b>{{ report.ruleEfficacy?.enabledRules || 0 }}</b> 条，其中本周期至少命中一次的规则 <b>{{ report.ruleEfficacy?.hitRules || 0 }}</b> 条，
        命中率 <b>{{ (report.ruleEfficacy?.hitRate || 0).toFixed(1) }}%</b>，零命中规则 <b>{{ report.ruleEfficacy?.zeroHitRules || 0 }}</b> 条。
      </p>
      <p class="doc-p">
        零命中并不必然意味着规则无效——可能是威胁尚未出现、规则覆盖小众场景或环境无相应攻击面。建议结合规则发布时间、最近 90 天历史命中率综合评估。
      </p>

      <h3 v-if="report.ruleEfficacy?.topZeroHit?.length" class="doc-h3">8.1　建议复核或下线的零命中规则</h3>
      <table v-if="report.ruleEfficacy?.topZeroHit?.length" class="doc-table">
        <thead><tr><th style="width:48px">#</th><th style="width:80px">ID</th><th>规则名</th><th style="width:200px">类别</th></tr></thead>
        <tbody>
          <tr v-for="(r, i) in report.ruleEfficacy.topZeroHit" :key="r.id">
            <td>{{ i + 1 }}</td><td>{{ r.id }}</td><td>{{ r.name }}</td><td>{{ r.category }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- ============== §9 故事线 + 抑制 ============== -->
    <section class="doc-page">
      <h2 class="doc-h2">9. 攻击故事线与误报抑制</h2>

      <h3 class="doc-h3">9.1　Top 5 高风险攻击故事线</h3>
      <table class="doc-table">
        <thead>
          <tr>
            <th style="width:32px">#</th><th>主机</th><th style="width:140px">阶段</th>
            <th style="width:70px">级别</th><th style="width:60px" class="doc-td-num">事件</th>
            <th style="width:60px" class="doc-td-num">告警</th><th style="width:70px" class="doc-td-num">风险分</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(s, i) in report.topStories" :key="i">
            <td>{{ i + 1 }}</td><td>{{ s.hostname }}</td><td>{{ s.phase }}</td>
            <td>
              <span class="doc-sev-pill" :style="{ background: sevColorBg(s.severity), color: severityColors[s.severity] }">
                {{ severityLabelMap[s.severity] || s.severity }}
              </span>
            </td>
            <td class="doc-td-num">{{ s.event_count }}</td>
            <td class="doc-td-num">{{ s.alert_count }}</td>
            <td class="doc-td-num"><b>{{ s.risk_score }}</b></td>
          </tr>
          <tr v-if="!report.topStories.length"><td colspan="7" class="doc-td-empty">本周期无故事线</td></tr>
        </tbody>
      </table>

      <h3 class="doc-h3">9.2　误报抑制原因分布</h3>
      <table class="doc-table">
        <thead><tr><th>抑制原因</th><th style="width:120px" class="doc-td-num">数量</th></tr></thead>
        <tbody>
          <tr v-for="(s, i) in report.suppressionStats" :key="i">
            <td>{{ s.reason }}</td><td class="doc-td-num">{{ s.count }}</td>
          </tr>
          <tr v-if="!report.suppressionStats.length"><td colspan="2" class="doc-td-empty">本周期无抑制记录</td></tr>
        </tbody>
      </table>
    </section>

    <!-- ============== §10 改进建议 ============== -->
    <section class="doc-page">
      <h2 class="doc-h2">10. 改进建议</h2>
      <p class="doc-p">基于本周期数据，平台自动生成如下改进建议供安全团队参考：</p>
      <ol class="doc-ol">
        <li v-for="(item, i) in report.improvements" :key="i">{{ item }}</li>
        <li v-if="!report.improvements?.length">本周期未生成自动建议（数据样本较小或检测充分）。</li>
      </ol>

      <h3 class="doc-h3">附 　 报告说明</h3>
      <table class="doc-table doc-table--kv">
        <tbody>
          <tr><td>数据来源</td><td>ClickHouse 集群（实时 EDR 遥测 + MySQL 规则/告警元数据）</td></tr>
          <tr><td>生成方式</td><td>矩阵云安全平台自动生成，无人工调整</td></tr>
          <tr><td>渲染引擎</td><td>Chromium Headless（Gotenberg）矢量 PDF</td></tr>
          <tr><td>报告编号</td><td>{{ report.meta.reportID }}</td></tr>
          <tr><td>生成时间</td><td>{{ report.meta.generatedAt }}</td></tr>
          <tr><td>密级</td><td>机密 · 仅限内部使用</td></tr>
        </tbody>
      </table>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart, LineChart } from 'echarts/charts'
import { TitleComponent, TooltipComponent, LegendComponent, GridComponent } from 'echarts/components'
import type { EChartsOption } from 'echarts'
import type { Dayjs } from 'dayjs'
import { reportsApi, type EDRReport } from '@/api/reports'

use([CanvasRenderer, PieChart, BarChart, LineChart, TitleComponent, TooltipComponent, LegendComponent, GridComponent])

const props = defineProps<{ dateRange: [Dayjs, Dayjs] }>()
const emit = defineEmits<{ (e: 'ready'): void }>()

const report = ref<EDRReport>({
  meta: { reportID: '', period: '', generatedAt: '', onlineHosts: 0, totalRules: 0, enabledRules: 0 },
  summary: { totalAlerts: 0, activeAlerts: 0, resolvedAlerts: 0, ignoredAlerts: 0, affectedHosts: 0, totalStories: 0, highRiskStories: 0 },
  severityDistribution: {},
  categoryDistribution: [],
  tacticDistribution: {},
  topRules: [],
  topHosts: [],
  topStories: [],
  suppressionStats: [],
  trend: { prevPeriodAlerts: 0, growthPercent: 0, direction: 'stable' },
  rawEventStats: { totalEvents: 0, uniqueHosts: 0, eventsByType: [], eventsByHour: [], topHostsByEvent: [], topExe: [], available: false },
  autoResponseStats: { networkBlocks: 0, hostIsolations: 0, processKills: 0, total: 0 },
  iocStats: { iocSnapshots: 0, memoryThreats: 0, topIOCTypes: [] },
  ruleEfficacy: { totalRules: 0, enabledRules: 0, hitRules: 0, zeroHitRules: 0, hitRate: 0, topZeroHit: [] },
  improvements: [],
})

const severityColors: Record<string, string> = {
  critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#0891b2',
}
const severityLabelMap: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危',
}
const tacticLabelMap: Record<string, string> = {
  initial_access: '初始访问', execution: '执行', persistence: '持久化',
  privilege_escalation: '权限提升', defense_evasion: '防御规避',
  credential_access: '凭据访问', discovery: '发现', lateral_movement: '横向移动',
  collection: '收集', exfiltration: '数据渗出', command_and_control: 'C2 通信',
  impact: '影响', other: '其他',
}
const sevColorBg = (sev: string) => {
  const c = severityColors[sev] || '#86909c'
  return `${c}1a`
}

const ruleEnableRate = computed(() =>
  report.value.meta.totalRules > 0
    ? (report.value.meta.enabledRules / report.value.meta.totalRules) * 100 : 0
)

const trendVerb = computed(() => {
  const d = report.value.trend.direction
  if (d === 'up') return '上升'
  if (d === 'down') return '下降'
  return '保持稳定'
})
const trendDescriptor = computed(() => {
  const g = Math.abs(report.value.trend.growthPercent)
  const d = report.value.trend.direction
  if (d === 'up' && g > 50) return '显著恶化'
  if (d === 'up') return '小幅上升'
  if (d === 'down' && g > 50) return '显著改善'
  if (d === 'down') return '小幅改善'
  return '平稳'
})
const trendArrow = computed(() => {
  const d = report.value.trend.direction
  return d === 'up' ? '↑' : d === 'down' ? '↓' : '→'
})

const avgEventsPerHost = computed(() => {
  const r = report.value.rawEventStats
  if (!r?.uniqueHosts) return 0
  return Math.round(r.totalEvents / r.uniqueHosts).toLocaleString()
})

const alertConversionRate = computed(() => {
  const ev = report.value.rawEventStats?.totalEvents || 0
  const al = report.value.summary?.totalAlerts || 0
  return ev > 0 ? (al / ev) * 100 : 0
})

const severityRows = computed(() => {
  const dist = report.value.severityDistribution
  const total = (['critical', 'high', 'medium', 'low'] as const).reduce((s, k) => s + (dist[k] || 0), 0)
  return (['critical', 'high', 'medium', 'low'] as const).map(k => ({
    key: k,
    label: severityLabelMap[k],
    color: severityColors[k],
    count: dist[k] || 0,
    pct: total > 0 ? ((dist[k] || 0) / total) * 100 : 0,
  }))
})

const conclusions = computed(() => {
  const r = report.value
  const out: string[] = []
  const top = r.topRules[0]
  if (top) out.push(`触发量最高的检测规则为「${top.title}」（${top.count} 次），建议优先验证其规则准确性与处置 SLA。`)
  const topHost = r.topHosts[0]
  if (topHost) out.push(`受影响最严重的主机为 ${topHost.hostname}（${topHost.count} 条告警），建议下钻进程/网络上下文确认是否真实威胁。`)
  if ((r.summary.highRiskStories || 0) > 0) {
    out.push(`本周期出现 ${r.summary.highRiskStories} 条高危攻击故事线（风险分 ≥ 70），需安全运营团队 24h 内闭环。`)
  } else {
    out.push('本周期未出现高危攻击故事线，整体处于稳态。')
  }
  if ((r.autoResponseStats?.total || 0) > 0) {
    out.push(`自动响应共执行 ${r.autoResponseStats!.total} 次（封禁 ${r.autoResponseStats!.networkBlocks} / 隔离 ${r.autoResponseStats!.hostIsolations} / 查杀 ${r.autoResponseStats!.processKills}），平均响应时间 < 1s。`)
  }
  if ((r.ruleEfficacy?.zeroHitRules || 0) > 0) {
    out.push(`存在 ${r.ruleEfficacy!.zeroHitRules} 条规则本周期零命中，参见 §8.1 复核清单。`)
  }
  return out
})

const severityOption = computed<EChartsOption>(() => ({
  tooltip: { show: false },
  legend: { orient: 'horizontal', bottom: 0, textStyle: { fontSize: 12 } },
  series: [{
    name: '严重级别', type: 'pie', radius: ['38%', '62%'], center: ['50%', '46%'],
    itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
    label: { show: true, formatter: '{b}\n{c} ({d}%)', fontSize: 11 },
    labelLine: { length: 8, length2: 6 },
    data: (['critical', 'high', 'medium', 'low'] as const)
      .map(sev => ({
        value: report.value.severityDistribution[sev] || 0,
        name: severityLabelMap[sev],
        itemStyle: { color: severityColors[sev] },
      }))
      .filter(item => item.value > 0),
  }],
}))

const tacticOption = computed<EChartsOption>(() => {
  const entries = Object.entries(report.value.tacticDistribution)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
  return {
    tooltip: { show: false },
    grid: { left: '3%', right: '4%', bottom: 60, top: 20, containLabel: true },
    xAxis: {
      type: 'category',
      data: entries.map(([k]) => tacticLabelMap[k] || k),
      axisLabel: { rotate: 35, interval: 0, fontSize: 11 },
    },
    yAxis: { type: 'value', splitLine: { lineStyle: { type: 'dashed' } } },
    series: [{
      name: '告警数', type: 'bar', barMaxWidth: 28,
      data: entries.map(([, v]) => v),
      itemStyle: { color: '#722ed1', borderRadius: [4, 4, 0, 0] },
      label: { show: true, position: 'top', fontSize: 10 },
    }],
  }
})

const eventTypeOption = computed<EChartsOption>(() => ({
  tooltip: { show: false },
  legend: { type: 'scroll', orient: 'horizontal', bottom: 0, textStyle: { fontSize: 11 } },
  series: [{
    name: '事件类型', type: 'pie', radius: ['38%', '62%'], center: ['50%', '46%'],
    itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
    label: { show: true, formatter: '{b}\n{d}%', fontSize: 10 },
    labelLine: { length: 6, length2: 4 },
    data: (report.value.rawEventStats?.eventsByType || []).map(e => ({
      value: Number(e.count), name: e.event_type,
    })),
  }],
}))

const eventTrendOption = computed<EChartsOption>(() => {
  const data = report.value.rawEventStats?.eventsByHour || []
  return {
    tooltip: { show: false },
    grid: { left: '3%', right: '4%', bottom: 50, top: 20, containLabel: true },
    xAxis: {
      type: 'category',
      data: data.map(d => d.hour.slice(5)),
      axisLabel: { rotate: 45, fontSize: 9, interval: Math.max(0, Math.floor(data.length / 16)) },
    },
    yAxis: { type: 'value', splitLine: { lineStyle: { type: 'dashed' } } },
    series: [{
      name: '事件量', type: 'line', smooth: true, showSymbol: false,
      areaStyle: { opacity: 0.25 },
      data: data.map(d => Number(d.count)),
      itemStyle: { color: '#3B82F6' },
      lineStyle: { width: 1.5 },
    }],
  }
})

const loadData = async () => {
  try {
    const data = await reportsApi.getEDRReport({
      start_time: props.dateRange[0].format('YYYY-MM-DD'),
      end_time: props.dateRange[1].format('YYYY-MM-DD'),
    })
    report.value = data
    emit('ready')
  } catch (e) {
    console.error('打印报告数据加载失败', e)
    emit('ready')
  }
}

watch(() => props.dateRange, loadData, { deep: true })
onMounted(loadData)
</script>

<style scoped lang="scss">
@import '@/styles/tokens.scss';

.doc {
  background: #fff;
  color: $text-primary;
  font-family: $font-sans;
  font-size: 13px;
  line-height: $leading-relaxed;
  max-width: 794px;
  margin: 0 auto;
  padding: 0;
}

/* ============== 封面 ============== */
.doc-cover {
  height: 1100px;
  padding: 80px 60px;
  display: flex;
  flex-direction: column;
  background:
    linear-gradient(135deg, rgba(37, 99, 235, 0.04) 0%, rgba(114, 46, 209, 0.04) 100%),
    #fff;
  page-break-after: always;
  break-after: page;
  border-bottom: 4px solid $brand-primary;

  &__brand {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  &__logo { width: 64px; height: 64px; }
  &__brand-name { font-size: 18px; font-weight: $weight-semibold; }
  &__brand-en { font-size: 12px; color: $text-tertiary; font-family: $font-mono; }

  &__center {
    flex: 1;
    display: flex; flex-direction: column;
    justify-content: center; align-items: center;
    text-align: center;
  }
  &__kind {
    font-size: 16px; color: $brand-primary;
    letter-spacing: 4px; margin-bottom: 24px;
    font-weight: $weight-medium;
  }
  &__title {
    font-size: 56px;
    font-weight: $weight-bold;
    background: linear-gradient(135deg, #2563eb 0%, #722ed1 100%);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    margin: 0 0 32px 0;
    letter-spacing: 6px;
  }
  &__period {
    font-size: 20px; color: $text-secondary;
    padding: 8px 24px; border: 1px solid $border-default;
    border-radius: $radius-pill;
  }

  &__meta {
    border-top: 1px solid $border-default;
    padding-top: 24px;
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 8px 32px;
    font-size: 13px;
  }
  &__meta-row { display: flex; justify-content: space-between; }
  &__meta-label { color: $text-tertiary; }
  &__meta-value { font-family: $font-mono; font-weight: $weight-medium; }
  &__classification {
    grid-column: span 2;
    margin-top: 16px;
    text-align: right;
    color: $brand-danger;
    font-weight: $weight-semibold;
    letter-spacing: 2px;
  }
}

/* ============== 普通页 ============== */
.doc-page {
  padding: 40px 60px 50px;
  page-break-before: always;
  break-before: page;
  page-break-inside: auto;
}

.doc-h2 {
  font-size: 22px;
  font-weight: $weight-semibold;
  color: $text-primary;
  margin: 0 0 20px 0;
  padding-bottom: 10px;
  border-bottom: 2px solid $brand-primary;
  page-break-after: avoid;
}
.doc-h3 {
  font-size: 16px;
  font-weight: $weight-semibold;
  color: $text-primary;
  margin: 24px 0 12px 0;
  padding-left: 10px;
  border-left: 3px solid $brand-secondary;
  page-break-after: avoid;
}
.doc-p {
  margin: 0 0 14px 0;
  text-indent: 2em;
  text-align: justify;
  color: $text-primary;
}
.doc-ul, .doc-ol {
  margin: 0 0 14px 0;
  padding-left: 24px;
  li { margin-bottom: 6px; }
}
.doc-empty {
  color: $text-tertiary; font-style: italic; margin: 12px 0;
}

/* ============== 目录 ============== */
.doc-toc {
  &__title {
    text-align: center;
    font-size: 28px;
    font-weight: $weight-semibold;
    letter-spacing: 12px;
    margin: 0 0 40px 0;
    color: $text-primary;
  }
  &__list {
    list-style: none; padding: 0; margin: 0;
    counter-reset: toc;
    li {
      display: flex; justify-content: space-between;
      padding: 12px 0;
      border-bottom: 1px dotted $border-default;
      font-size: 14px;
      counter-increment: toc;
      &::before {
        content: counter(toc) ".";
        font-family: $font-mono;
        color: $brand-primary;
        margin-right: 12px;
        font-weight: $weight-semibold;
      }
      span:first-of-type { flex: 1; }
    }
  }
  &__page {
    font-family: $font-mono; color: $text-tertiary;
  }
  &__hint {
    margin-top: 48px;
    padding: 16px;
    background: $bg-secondary;
    border-left: 3px solid $brand-info;
    font-size: 12px; color: $text-secondary; line-height: 1.7;
  }
}

/* ============== 表格 ============== */
.doc-table {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0 18px;
  font-size: 12.5px;

  thead th {
    background: $bg-secondary;
    color: $text-primary;
    font-weight: $weight-semibold;
    text-align: left;
    padding: 8px 12px;
    border-bottom: 2px solid $brand-primary;
    border-top: 1px solid $border-default;
  }
  tbody td {
    padding: 7px 12px;
    border-bottom: 1px solid $border-default;
    color: $text-primary;
    vertical-align: top;
  }
  tbody tr:nth-child(even) td {
    background: rgba(0, 0, 0, 0.015);
  }
  page-break-inside: auto;
  tr { page-break-inside: avoid; }
}
.doc-table--kv {
  td:first-child { width: 30%; color: $text-secondary; }
}
.doc-td-num {
  text-align: right;
  font-family: $font-mono;
  font-variant-numeric: tabular-nums;
}
.doc-td-code {
  font-family: $font-mono;
  font-size: 11.5px;
  word-break: break-all;
}
.doc-td-empty {
  text-align: center; color: $text-tertiary; font-style: italic;
}

.doc-sev-dot {
  display: inline-block;
  width: 8px; height: 8px;
  border-radius: 50%;
  margin-right: 8px;
  vertical-align: middle;
}
.doc-sev-pill {
  display: inline-block;
  padding: 2px 8px;
  border-radius: $radius-sm;
  font-size: 11px;
  font-weight: $weight-medium;
}

/* ============== 图表 figure ============== */
.doc-figure {
  margin: 18px 0;
  page-break-inside: avoid;
}
.doc-chart {
  width: 100%;
  height: 280px;
}
.doc-figure__caption {
  text-align: center;
  margin-top: 6px;
  font-size: 12px;
  color: $text-secondary;
  font-weight: $weight-medium;
  letter-spacing: 1px;
}

/* ============== 打印 ============== */
@media print {
  .doc { max-width: none; }
  .doc-cover { border-bottom: 4px solid $brand-primary; }
  .doc-page { padding: 30px 40px 40px; }
}
</style>
