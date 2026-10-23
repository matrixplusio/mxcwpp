"use client";
import { clsx } from "clsx";

// MITRE ATT&CK 战术覆盖热力。告警带 attck_tactic，由后端聚合真实计数。
type Tactic = { id: string; name: string; count: number };

function heat(count: number, max: number): string {
  if (count === 0) return "bg-slate-700/20 text-slate-500 border-slate-600/20";
  const r = count / max;
  if (r > 0.66) return "bg-rose-500/25 text-rose-200 border-rose-500/40 shadow-[0_0_8px_-2px_rgba(244,63,94,0.6)]";
  if (r > 0.33) return "bg-orange-500/20 text-orange-200 border-orange-500/35";
  return "bg-cyan-500/12 text-cyan-200 border-cyan-500/30";
}

export function AttackMatrix({ tactics }: { tactics: Tactic[] }) {
  const max = Math.max(1, ...tactics.map((t) => t.count));
  const covered = tactics.filter((t) => t.count > 0).length;
  return (
    <div className="flex h-full flex-col">
      <div className="mb-2 flex items-center justify-between text-[11px] text-slate-400">
        <span>MITRE ATT&CK 战术覆盖</span>
        <span className="text-cyan-300">
          命中 {covered}/{tactics.length} 战术
        </span>
      </div>
      <div className="grid min-h-0 flex-1 grid-cols-6 gap-1.5">
        {tactics.map((t) => (
          <div
            key={t.id}
            className={clsx(
              "flex flex-col items-center justify-center rounded border px-1 py-1 transition-colors",
              heat(t.count, max),
            )}
          >
            <span className="font-mono text-lg font-bold tabular-nums leading-none">{t.count}</span>
            <span className="mt-0.5 truncate text-[9px] leading-tight opacity-80">{t.name}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
