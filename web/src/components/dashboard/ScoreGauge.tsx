"use client";
import { useTranslation } from "react-i18next";
import { Card } from "@/components/ui/Card";

/** 安全评分环形仪表，score 0-100 */
export function ScoreGauge({ score }: { score: number }) {
  const { t } = useTranslation();
  const v = Math.max(0, Math.min(100, score));
  const r = 22;
  const c = 2 * Math.PI * r;
  const offset = c * (1 - v / 100);
  const color = v >= 80 ? "#16A34A" : v >= 60 ? "#F59E0B" : "#DC2626";

  return (
    <Card className="p-5 flex items-center gap-4 transition-all duration-200 hover:-translate-y-0.5">
      <div className="relative h-14 w-14 shrink-0">
        <svg className="h-14 w-14 -rotate-90" viewBox="0 0 56 56">
          <circle cx="28" cy="28" r={r} fill="none" stroke="#E5E8EC" strokeWidth="5" />
          <circle
            cx="28" cy="28" r={r} fill="none" stroke={color} strokeWidth="5" strokeLinecap="round"
            strokeDasharray={c} strokeDashoffset={offset}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center text-xs font-bold text-ink tabular-nums">
          {v.toFixed(0)}
        </div>
      </div>
      <div className="min-w-0">
        <div className="text-2xl font-bold text-ink leading-tight tabular-nums">{v.toFixed(1)}</div>
        <div className="text-sm text-muted truncate">{t("dashboard.securityScore")}</div>
      </div>
    </Card>
  );
}
