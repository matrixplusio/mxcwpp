"use client";
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Panel } from "@/components/screen/Panel";
import { ScreenHeader } from "@/components/screen/ScreenHeader";
import { KpiTicker } from "@/components/screen/KpiTicker";
import { PostureGauge, SeverityRing, TrendChart } from "@/components/screen/ScreenCharts";
import { EngineHealthWall } from "@/components/screen/EngineHealthWall";
import { AlertFeed } from "@/components/screen/AlertFeed";
import { AttackMap } from "@/components/screen/AttackMap";
import { AttackMatrix } from "@/components/screen/AttackMatrix";
import { HostRank, ComplianceBar } from "@/components/screen/HostRank";
import { screenApi, streamScreenAlerts, type ScreenOverview, type ScreenFeedItem } from "@/lib/api/screen";

// 后端不可用（如本地无后端）时的兜底 mock，保证大屏始终可渲染。
const FALLBACK: ScreenOverview = {
  kpi: { blockedToday: 229, activeThreats: 148, agentsOnline: 227, agentsTotal: 228, fpSuppressRate: 96, postureScore: 72 },
  engines: [
    { key: "edr", name: "EDR 检测", count: 148, unit: "活跃告警", status: "healthy" },
    { key: "bde", name: "行为引擎", count: 478, unit: "待处置", status: "healthy" },
    { key: "ml", name: "ML 异常", count: 3791, unit: "critical", status: "warn" },
    { key: "fim", name: "文件完整性", count: 96413, unit: "24h 事件", status: "healthy" },
    { key: "kube", name: "K8s 基线", count: 172, unit: "活跃项", status: "warn" },
    { key: "ac", name: "接入中心", count: 227, unit: "在线探针", status: "healthy" },
  ],
  severity: { critical: 4, high: 52, medium: 53, low: 39 },
  trend: {
    hours: Array.from({ length: 12 }, (_, i) => `${String(i * 2).padStart(2, "0")}:00`),
    edr: [12, 8, 6, 5, 4, 7, 15, 22, 30, 26, 18, 14],
    bde: [4, 3, 2, 2, 1, 3, 8, 12, 10, 9, 6, 5],
    ml: [40, 35, 28, 30, 25, 33, 52, 60, 48, 42, 38, 44],
  },
  hostRank: [
    { name: "app-server-01", score: 38, issues: "内存马" },
    { name: "app-server-02", score: 45, issues: "勒索特征" },
    { name: "app-server-03", score: 52, issues: "提权" },
    { name: "gateway-01", score: 58, issues: "端口扫描" },
    { name: "app-server-04", score: 61, issues: "横向移动" },
    { name: "app-server-05", score: 66, issues: "凭据访问" },
  ],
  attck: [
    { id: "TA0001", name: "初始访问", count: 6 }, { id: "TA0002", name: "执行", count: 1 },
    { id: "TA0003", name: "持久化", count: 7 }, { id: "TA0004", name: "提权", count: 15 },
    { id: "TA0005", name: "防御绕过", count: 10 }, { id: "TA0006", name: "凭据访问", count: 11 },
    { id: "TA0007", name: "发现", count: 38 }, { id: "TA0008", name: "横向移动", count: 30 },
    { id: "TA0009", name: "收集", count: 3 }, { id: "TA0010", name: "数据渗出", count: 5 },
    { id: "TA0011", name: "命令控制", count: 2 }, { id: "TA0040", name: "影响", count: 1 },
  ],
  compliance: { criticalVuln: 17, highVuln: 448, baselineRate: 78, kubeBaseline: 172 },
  feed: [
    { id: "1", time: "16:42:07", severity: "critical", title: "检测到内存马注入 - java 进程异常加载", host: "app-server-01" },
    { id: "2", time: "16:41:53", severity: "high", title: "端口扫描检测 - 来自 203.0.113.44", host: "gateway-01" },
    { id: "3", time: "16:41:22", severity: "high", title: "可疑提权 - sudo 异常调用链", host: "app-server-03" },
    { id: "4", time: "16:40:58", severity: "medium", title: "敏感文件访问 - /etc/shadow 读取", host: "app-server-06" },
    { id: "5", time: "16:40:31", severity: "critical", title: "勒索行为特征 - 批量文件加密", host: "app-server-02" },
    { id: "6", time: "16:39:47", severity: "high", title: "横向移动 - SSH 爆破成功", host: "app-server-04" },
  ],
};

const MARQUEE = [
  "攻击链溯源 TOP：SSH爆破 → 提权 → 横向移动",
  "APT 情报命中：Lazarus C2 IP × 2",
  "多引擎融合态势感知 · 误报保真分级治理",
];

export default function ScreenPage() {
  const { data } = useQuery({
    queryKey: ["screen-overview"],
    queryFn: screenApi.getOverview,
    refetchInterval: 15000,
    staleTime: 12000,
  });
  const d = data ?? FALLBACK;

  // SSE 实时告警流：新告警前插，与轮询 feed 合并去重，保留最新 12 条。
  const [live, setLive] = useState<ScreenFeedItem[]>([]);
  useEffect(() => {
    const ac = new AbortController();
    streamScreenAlerts((a) => setLive((prev) => [a, ...prev].slice(0, 12)), ac.signal);
    return () => ac.abort();
  }, []);
  const feed = dedupeById([...live, ...d.feed]).slice(0, 12);

  return (
    <div className="flex h-screen flex-col">
      <ScreenHeader online={d.kpi.agentsOnline} total={d.kpi.agentsTotal} />
      <KpiTicker kpi={d.kpi} />

      <main className="flex min-h-0 flex-1 gap-3 px-3 pb-2">
        {/* 左列 */}
        <div className="flex w-[23%] flex-col gap-3">
          <Panel title="安全态势评分" accent="cyan" className="flex-[4]">
            <PostureGauge score={d.kpi.postureScore} />
          </Panel>
          <Panel title="检测引擎健康墙" accent="emerald" className="flex-[4]">
            <EngineHealthWall engines={d.engines} />
          </Panel>
          <Panel title="主机安全评分榜" accent="rose" className="flex-[5]">
            <HostRank hosts={d.hostRank} />
          </Panel>
        </div>

        {/* 中列 */}
        <div className="flex flex-1 flex-col gap-3">
          <Panel title="攻击态势 · 实时" accent="rose" className="flex-[6]">
            <AttackMap />
          </Panel>
          <div className="flex flex-[4] gap-3">
            <Panel title="ATT&CK 战术覆盖" accent="amber" className="flex-1">
              <AttackMatrix tactics={d.attck} />
            </Panel>
            <Panel title="24h 告警趋势（多引擎）" accent="violet" className="flex-1">
              <TrendChart hours={d.trend.hours} edr={d.trend.edr} bde={d.trend.bde} ml={d.trend.ml} />
            </Panel>
          </div>
        </div>

        {/* 右列 */}
        <div className="flex w-[23%] flex-col gap-3">
          <Panel title="实时告警流" accent="rose" className="flex-[5]">
            <AlertFeed alerts={feed} />
          </Panel>
          <Panel title="告警等级分布" accent="amber" className="flex-[4]">
            <SeverityRing d={d.severity} />
          </Panel>
          <Panel title="漏洞 · 基线合规态势" accent="emerald" className="flex-[4]">
            <ComplianceBar data={d.compliance} />
          </Panel>
        </div>
      </main>

      {/* KPI 跑马灯 */}
      <footer className="relative h-8 shrink-0 overflow-hidden border-t border-cyan-400/15 bg-[#070D1B]">
        <motion.div
          className="absolute flex h-full items-center gap-10 whitespace-nowrap px-6 font-mono text-xs text-cyan-200/80"
          animate={{ x: ["0%", "-50%"] }}
          transition={{ duration: 30, repeat: Infinity, ease: "linear" }}
        >
          {[...MARQUEE, ...MARQUEE].map((m, i) => (
            <span key={i} className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
              {m}
            </span>
          ))}
        </motion.div>
      </footer>
    </div>
  );
}

function dedupeById(items: ScreenFeedItem[]): ScreenFeedItem[] {
  const seen = new Set<string>();
  return items.filter((it) => (seen.has(it.id) ? false : (seen.add(it.id), true)));
}
