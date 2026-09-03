"use client";
import { useTranslation } from "react-i18next";
import { Card, CardHeader } from "@/components/ui/Card";
import type { StorylineTop } from "@/lib/api/types";

function riskTone(score: number) {
  if (score >= 80) return { bar: "bg-danger", text: "text-danger" };
  if (score >= 50) return { bar: "bg-warning", text: "text-warning" };
  return { bar: "bg-primary", text: "text-primary" };
}

export function StorylineList({ rows }: { rows: StorylineTop[] }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader title={t("dashboard.attackStorylines")} />
      <ul className="px-5 pb-5 space-y-1">
        {rows.map((r) => {
          const t = riskTone(r.risk_score);
          return (
            <li key={r.story_id} className="flex items-center gap-4 rounded-control px-3 py-2.5 -mx-3 hover:bg-bg transition-colors">
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium text-ink truncate">{r.title}</div>
                <div className="mt-1 flex items-center gap-2">
                  <span className="rounded-full bg-surface-muted border border-border px-2 py-0.5 text-[11px] font-medium text-muted">{r.phase}</span>
                  <span className="text-xs text-faint truncate">{r.hostname}</span>
                </div>
              </div>
              <div className="flex items-center gap-2.5 shrink-0 w-28">
                <div className="flex-1 h-1.5 rounded-full bg-border overflow-hidden">
                  <div className={`h-full rounded-full ${t.bar}`} style={{ width: `${Math.min(100, r.risk_score)}%` }} />
                </div>
                <span className={`text-sm font-bold tabular-nums ${t.text}`}>{r.risk_score}</span>
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
