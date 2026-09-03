"use client";
import { clsx } from "clsx";

export type EngineStat = {
  key: string;
  name: string;
  count: number;
  unit: string;
  status: "healthy" | "warn" | "down";
};

const statusColor = {
  healthy: { dot: "bg-emerald-400", ring: "shadow-[0_0_8px_rgba(52,211,153,0.8)]", text: "text-emerald-300", label: "正常" },
  warn: { dot: "bg-amber-400", ring: "shadow-[0_0_8px_rgba(251,191,36,0.8)]", text: "text-amber-300", label: "关注" },
  down: { dot: "bg-rose-500", ring: "shadow-[0_0_8px_rgba(244,63,94,0.9)]", text: "text-rose-300", label: "异常" },
};

export function EngineHealthWall({ engines }: { engines: EngineStat[] }) {
  return (
    <div className="grid h-full grid-cols-2 gap-2.5">
      {engines.map((e) => {
        const s = statusColor[e.status];
        return (
          <div
            key={e.key}
            className="relative flex flex-col justify-center gap-1 overflow-hidden rounded-md border border-cyan-400/10 bg-[#0A1120] px-3 py-2"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium tracking-wide text-slate-300">{e.name}</span>
              <span className="flex items-center gap-1.5">
                <span className={clsx("h-2 w-2 rounded-full", s.dot, s.ring)} />
                <span className={clsx("text-[10px]", s.text)}>{s.label}</span>
              </span>
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="font-mono text-xl font-bold tabular-nums text-slate-100 drop-shadow-[0_0_8px_rgba(226,232,240,0.25)]">
                {e.count.toLocaleString()}
              </span>
              <span className="truncate text-[10px] text-slate-500">{e.unit}</span>
            </div>
            <span className="pointer-events-none absolute -right-4 -top-4 h-12 w-12 rounded-full bg-cyan-500/5 blur-xl" />
          </div>
        );
      })}
    </div>
  );
}
