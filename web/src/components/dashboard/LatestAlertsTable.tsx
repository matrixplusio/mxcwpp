"use client";
import { useTranslation } from "react-i18next";
import { Card, CardHeader } from "@/components/ui/Card";
import { SeverityTag } from "@/components/ui/Tag";
import type { LatestAlert } from "@/lib/api/types";

export function LatestAlertsTable({ rows }: { rows: LatestAlert[] }) {
  const { t } = useTranslation();
  return (
    <Card className="overflow-hidden">
      <CardHeader title={t("dashboard.recentHighAlerts")} />
      <table className="w-full text-sm">
        <thead>
          <tr className="text-[12px] uppercase tracking-wide text-faint bg-surface-muted/60">
            <th className="text-left font-semibold px-5 py-2.5">{t("dashboard.colAlert")}</th>
            <th className="text-left font-semibold px-3 py-2.5">{t("dashboard.colSeverity")}</th>
            <th className="text-left font-semibold px-3 py-2.5">{t("dashboard.colHost")}</th>
            <th className="text-right font-semibold px-5 py-2.5">{t("dashboard.colTime")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-t border-border hover:bg-bg transition-colors">
              <td className="px-5 py-3 text-ink font-medium">{r.title}</td>
              <td className="px-3 py-3"><SeverityTag level={r.severity} /></td>
              <td className="px-3 py-3 text-muted">{r.hostname}</td>
              <td className="px-5 py-3 text-right text-faint tabular-nums">{r.last_seen_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
