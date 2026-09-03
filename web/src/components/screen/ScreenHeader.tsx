"use client";
import { useEffect, useState } from "react";
import { ShieldCheck, Radar, Activity } from "lucide-react";

function useClock() {
  const [now, setNow] = useState<Date | null>(null);
  useEffect(() => {
    setNow(new Date());
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

export function ScreenHeader({
  online,
  total,
}: {
  online: number;
  total: number;
}) {
  const now = useClock();
  const pad = (n: number) => String(n).padStart(2, "0");
  const time = now ? `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}` : "--:--:--";
  const date = now
    ? `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`
    : "----------";

  return (
    <header className="relative flex h-16 items-center justify-between px-6">
      {/* 左：在线率 */}
      <div className="flex items-center gap-6">
        <Kpi icon={<Activity className="h-4 w-4" />} label="主机在线" value={`${online}/${total}`} accent="text-emerald-300" />
        <Kpi icon={<Radar className="h-4 w-4" />} label="探针在线率" value={`${total ? Math.round((online / total) * 100) : 0}%`} accent="text-cyan-300" />
      </div>

      {/* 中：标题 */}
      <div className="absolute left-1/2 top-1/2 flex -translate-x-1/2 -translate-y-1/2 items-center gap-3">
        <ShieldCheck className="h-7 w-7 text-cyan-300 drop-shadow-[0_0_8px_rgba(34,211,238,0.7)]" />
        <h1 className="bg-gradient-to-r from-cyan-200 via-white to-cyan-200 bg-clip-text text-2xl font-bold tracking-[0.3em] text-transparent">
          矩阵云安全态势感知
        </h1>
      </div>

      {/* 右：时钟 */}
      <div className="text-right">
        <div className="font-mono text-2xl font-bold tabular-nums tracking-widest text-cyan-100">{time}</div>
        <div className="font-mono text-[11px] tracking-widest text-slate-400">{date}</div>
      </div>

      {/* 底部霓虹分割线 */}
      <div className="absolute bottom-0 left-0 h-px w-full bg-gradient-to-r from-transparent via-cyan-400/60 to-transparent" />
    </header>
  );
}

function Kpi({ icon, label, value, accent }: { icon: React.ReactNode; label: string; value: string; accent: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className={accent}>{icon}</span>
      <div className="leading-tight">
        <div className={`font-mono text-lg font-bold tabular-nums ${accent}`}>{value}</div>
        <div className="text-[10px] tracking-wide text-slate-400">{label}</div>
      </div>
    </div>
  );
}
