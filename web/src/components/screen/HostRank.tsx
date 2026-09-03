"use client";
import { clsx } from "clsx";

// 主机安全评分排行（青藤万相招牌）。分越低风险越高，排最危险的在前。
type Host = { name: string; score: number; issues: string };

const scoreColor = (s: number) => (s < 50 ? "text-rose-300" : s < 70 ? "text-amber-300" : "text-emerald-300");
const barColor = (s: number) => (s < 50 ? "bg-rose-500" : s < 70 ? "bg-amber-400" : "bg-emerald-400");

export function HostRank({ hosts }: { hosts: Host[] }) {
  if (hosts.length === 0) {
    return <div className="flex h-full items-center justify-center text-xs text-slate-500">暂无高风险主机</div>;
  }
  return (
    <div className="flex h-full flex-col gap-1.5">
      {hosts.map((h, i) => (
        <div key={h.name} className="flex items-center gap-2">
          <span className="w-4 shrink-0 text-center font-mono text-[11px] text-slate-500">{i + 1}</span>
          <div className="min-w-0 flex-1">
            <div className="flex items-baseline justify-between">
              <span className="truncate font-mono text-[11px] text-slate-200">{h.name}</span>
              <span className={clsx("ml-2 shrink-0 font-mono text-sm font-bold tabular-nums", scoreColor(h.score))}>
                {h.score}
              </span>
            </div>
            <div className="mt-0.5 flex items-center gap-2">
              <div className="h-1 flex-1 overflow-hidden rounded-full bg-slate-700/40">
                <div className={clsx("h-full rounded-full", barColor(h.score))} style={{ width: `${h.score}%` }} />
              </div>
              <span className="shrink-0 text-[9px] text-slate-500">{h.issues}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export type ComplianceData = { criticalVuln: number; highVuln: number; baselineRate: number; kubeBaseline: number };

/** 漏洞 + 基线合规双仪表（等保态势）。 */
export function ComplianceBar({ data }: { data: ComplianceData }) {
  const items = [
    { label: "严重漏洞", value: data.criticalVuln, max: 100, color: "bg-rose-500", text: "text-rose-300" },
    { label: "高危漏洞", value: data.highVuln, max: 500, color: "bg-orange-400", text: "text-orange-300" },
    { label: "基线合规率", value: data.baselineRate, max: 100, color: "bg-emerald-400", text: "text-emerald-300", suffix: "%" },
    { label: "K8s 基线", value: data.kubeBaseline, max: 200, color: "bg-amber-400", text: "text-amber-300" },
  ];
  return (
    <div className="flex h-full flex-col justify-center gap-3">
      {items.map((it) => (
        <div key={it.label}>
          <div className="flex items-baseline justify-between text-[11px]">
            <span className="text-slate-400">{it.label}</span>
            <span className={`font-mono font-bold tabular-nums ${it.text}`}>
              {it.value}
              {it.suffix || ""}
            </span>
          </div>
          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-slate-700/40">
            <div className={`h-full rounded-full ${it.color}`} style={{ width: `${Math.min(100, (it.value / it.max) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}
