"use client";
import { clsx } from "clsx";
import { AnimatePresence, motion } from "framer-motion";

export type FeedAlert = {
  id: string;
  time: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  host: string;
};

const sev = {
  critical: { dot: "bg-rose-500", text: "text-rose-300", tag: "严重", glow: "shadow-[0_0_10px_rgba(244,63,94,0.5)]", border: "border-rose-500/40" },
  high: { dot: "bg-orange-400", text: "text-orange-300", tag: "高危", glow: "", border: "border-orange-400/25" },
  medium: { dot: "bg-yellow-400", text: "text-yellow-300", tag: "中危", glow: "", border: "border-yellow-400/20" },
  low: { dot: "bg-sky-400", text: "text-sky-300", tag: "低危", glow: "", border: "border-sky-400/20" },
};

export function AlertFeed({ alerts }: { alerts: FeedAlert[] }) {
  return (
    <div
      className="flex h-full flex-col gap-1.5 overflow-hidden"
      style={{ maskImage: "linear-gradient(to bottom, #000 82%, transparent 100%)", WebkitMaskImage: "linear-gradient(to bottom, #000 82%, transparent 100%)" }}
    >
      <AnimatePresence initial={false}>
        {alerts.map((a) => {
          const s = sev[a.severity];
          return (
            <motion.div
              key={a.id}
              layout
              initial={{ opacity: 0, x: 24 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.35 }}
              className={clsx(
                "flex items-center gap-2.5 rounded-md border bg-[#0A1120]/80 px-2.5 py-1.5",
                s.border,
                a.severity === "critical" && s.glow,
              )}
            >
              <span className={clsx("h-2 w-2 shrink-0 rounded-full", s.dot, a.severity === "critical" && "animate-pulse")} />
              <span className="w-14 shrink-0 font-mono text-[11px] tabular-nums text-slate-500">{a.time}</span>
              <span className={clsx("w-9 shrink-0 rounded px-1 text-center text-[10px] font-semibold", s.text)}>{s.tag}</span>
              <span className="min-w-0 flex-1 truncate text-[12px] text-slate-200">{a.title}</span>
              <span className="hidden shrink-0 truncate font-mono text-[10px] text-slate-500 xl:block xl:max-w-[120px]">{a.host}</span>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
