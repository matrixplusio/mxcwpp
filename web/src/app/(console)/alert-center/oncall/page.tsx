"use client";

import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { oncallApi } from "@/lib/api/response-actions";
import type { OncallShift, OncallTier } from "@/lib/api/types";
import { CalendarClock, AlertTriangle } from "lucide-react";

const tierLabelKey: Record<OncallTier, string> = {
  l1: "alerts.oncall.tierL1",
  l2: "alerts.oncall.tierL2",
  security: "alerts.oncall.tierSecurity",
};

/**
 * 值班表。
 *
 * 新事件自动派给当班的一线值班人。没有排班就没有负责人，超时告警只会天天响
 * 而没人知道该找谁——所以排班缺口在这里显式标出，而不是等事件无主了才发现。
 */
export default function OncallPage() {
  const { t } = useTranslation();

  const currentQuery = useQuery({
    queryKey: ["oncall-current"],
    queryFn: () => oncallApi.current(),
  });
  const shiftsQuery = useQuery({
    queryKey: ["oncall-shifts"],
    queryFn: () => oncallApi.shifts(14),
  });

  const tiers: OncallTier[] = ["l1", "l2", "security"];
  const uncovered = currentQuery.data?.uncovered_tiers ?? [];

  const columns: Column<OncallShift>[] = [
    {
      key: "tier",
      title: t("alerts.oncall.colTier"),
      render: (r) => t(tierLabelKey[r.tier] ?? "alerts.oncall.tierL1"),
    },
    { key: "username", title: t("alerts.oncall.colUser"), render: (r) => r.username },
    {
      key: "window",
      title: t("alerts.oncall.colWindow"),
      render: (r) => (
        <span className="text-sm text-muted">
          {/* 后端 LocalTime 已是本地时间的可读串，直接渲染：
              再过一道 new Date() 既与全站格式不一致，空格分隔的日期时间
              也不在 ECMAScript 规范内（部分引擎会得到 Invalid Date）。*/}
          <span className="tabular-nums">{r.starts_at}</span> →{" "}
          <span className="tabular-nums">{r.ends_at}</span>
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex items-start gap-2.5">
          <CalendarClock size={18} className="mt-0.5 shrink-0 text-primary" />
          <p className="text-sm text-muted">{t("alerts.oncall.intro")}</p>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        {tiers.map((tier) => {
          const who = currentQuery.data?.oncall?.[tier];
          const gap = uncovered.includes(tier);
          return (
            <Card key={tier} className="p-4">
              <div className="text-sm text-muted">{t(tierLabelKey[tier])}</div>
              <div className={`mt-1 text-lg font-semibold ${gap ? "text-danger" : "text-ink"}`}>
                {/* 取不到就显示占位符，不渲染成空白让人以为还在加载。 */}
                {currentQuery.isError
                  ? "—"
                  : gap || !who
                    ? t("alerts.oncall.uncovered")
                    : who}
              </div>
            </Card>
          );
        })}
      </div>

      {uncovered.length > 0 && (
        <Card className="border-danger/30 p-4">
          <div className="flex items-start gap-2.5">
            <AlertTriangle size={18} className="mt-0.5 shrink-0 text-danger" />
            <p className="text-sm text-ink">{t("alerts.oncall.gapWarning")}</p>
          </div>
        </Card>
      )}

      <DataTable
        columns={columns}
        rows={shiftsQuery.data?.items ?? []}
        rowKey={(r) => r.id}
        loading={shiftsQuery.isLoading}
        emptyText={t("alerts.oncall.empty")}
      />
    </div>
  );
}
