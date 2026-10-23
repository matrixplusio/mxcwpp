"use client";
import { useEffect, useState } from "react";
import { ShieldBan, Flame, Radar, Filter, Gauge } from "lucide-react";

/** 数字翻牌滚动动画（国内大屏标配）。 */
function useCountUp(target: number, ms = 1200) {
  const [v, setV] = useState(0);
  useEffect(() => {
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / ms);
      setV(Math.round(target * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

type Kpi = { icon: React.ReactNode; label: string; value: number; suffix?: string; accent: string };

export type KpiData = {
  blockedToday: number;
  activeThreats: number;
  agentsOnline: number;
  fpSuppressRate: number;
  postureScore: number;
};

export function KpiTicker({ kpi }: { kpi: KpiData }) {
  const kpis: Kpi[] = [
    { icon: <ShieldBan className="h-5 w-5" />, label: "今日拦截威胁", value: kpi.blockedToday, accent: "text-rose-300" },
    { icon: <Flame className="h-5 w-5" />, label: "活跃威胁", value: kpi.activeThreats, accent: "text-orange-300" },
    { icon: <Radar className="h-5 w-5" />, label: "在线探针", value: kpi.agentsOnline, accent: "text-emerald-300" },
    { icon: <Filter className="h-5 w-5" />, label: "误报压制率", value: kpi.fpSuppressRate, suffix: "%", accent: "text-cyan-300" },
    { icon: <Gauge className="h-5 w-5" />, label: "安全态势评分", value: kpi.postureScore, accent: "text-violet-300" },
  ];
  return (
    <div className="grid grid-cols-5 gap-3 px-4 py-2">
      {kpis.map((k) => (
        <KpiCard key={k.label} {...k} />
      ))}
    </div>
  );
}

function KpiCard({ icon, label, value, suffix, accent }: Kpi) {
  const v = useCountUp(value);
  return (
    <div className="relative flex items-center gap-3 overflow-hidden rounded-lg border border-cyan-400/12 bg-[#070D1B]/70 px-4 py-2.5">
      <span className={`${accent} opacity-90`}>{icon}</span>
      <div className="leading-tight">
        <div className={`font-mono text-2xl font-extrabold tabular-nums drop-shadow-[0_0_10px_currentColor] ${accent}`}>
          {v.toLocaleString()}
          {suffix && <span className="text-base">{suffix}</span>}
        </div>
        <div className="text-[10px] tracking-wide text-slate-400">{label}</div>
      </div>
      <span className="pointer-events-none absolute -right-3 -top-3 h-10 w-10 rounded-full bg-cyan-500/5 blur-lg" />
    </div>
  );
}
