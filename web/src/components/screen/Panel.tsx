"use client";
import { clsx } from "clsx";

/**
 * Panel 态势大屏统一面板外框：深色玻璃底 + 霓虹描边 + 科技切角 + 标题辉光。
 */
const ACCENTS: Record<string, { text: string; bar: string; glow: string; dot: string }> = {
  cyan: { text: "text-cyan-300", bar: "from-cyan-400", glow: "shadow-[0_0_28px_-10px_rgba(34,211,238,0.45)]", dot: "bg-cyan-400" },
  emerald: { text: "text-emerald-300", bar: "from-emerald-400", glow: "shadow-[0_0_28px_-10px_rgba(52,211,153,0.4)]", dot: "bg-emerald-400" },
  amber: { text: "text-amber-300", bar: "from-amber-400", glow: "shadow-[0_0_28px_-10px_rgba(251,191,36,0.4)]", dot: "bg-amber-400" },
  rose: { text: "text-rose-300", bar: "from-rose-400", glow: "shadow-[0_0_28px_-10px_rgba(244,63,94,0.4)]", dot: "bg-rose-400" },
  violet: { text: "text-violet-300", bar: "from-violet-400", glow: "shadow-[0_0_28px_-10px_rgba(167,139,250,0.4)]", dot: "bg-violet-400" },
};

export function Panel({
  title,
  accent = "cyan",
  className,
  right,
  children,
}: {
  title: string;
  accent?: "cyan" | "emerald" | "amber" | "rose" | "violet";
  className?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
}) {
  const a = ACCENTS[accent];
  return (
    <section
      className={clsx(
        "group relative flex min-h-0 flex-col rounded-lg border border-cyan-400/20 bg-gradient-to-b from-[#0A1122]/90 to-[#060B16]/90 backdrop-blur-sm",
        a.glow,
        className,
      )}
    >
      {/* 顶部霓虹渐变线 */}
      <span className={clsx("absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent to-transparent", a.bar, "via-30%")} />
      <header className="flex items-center justify-between gap-2 border-b border-white/[0.06] px-3 py-2">
        <div className="flex items-center gap-2">
          <span className={clsx("h-3.5 w-[3px] rounded-full", a.dot)} style={{ boxShadow: "0 0 8px currentColor" }} />
          <h3 className={clsx("text-[13px] font-semibold tracking-wide drop-shadow-[0_0_6px_currentColor]", a.text)}>
            {title}
          </h3>
        </div>
        {right}
      </header>
      <div className="min-h-0 flex-1 p-3">{children}</div>
      {/* 科技切角 */}
      <Corner className="left-0 top-0 border-l-2 border-t-2" a={a.text} />
      <Corner className="right-0 top-0 border-r-2 border-t-2" a={a.text} />
      <Corner className="bottom-0 left-0 border-b-2 border-l-2" a={a.text} />
      <Corner className="bottom-0 right-0 border-b-2 border-r-2" a={a.text} />
    </section>
  );
}

function Corner({ className, a }: { className: string; a: string }) {
  return <span className={clsx("pointer-events-none absolute h-2.5 w-2.5 border-current opacity-60", a, className)} />;
}
