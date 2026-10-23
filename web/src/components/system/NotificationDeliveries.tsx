"use client";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { systemApi } from "@/lib/api/system";
import type { DeliveryOutcome, NotificationDelivery } from "@/lib/api/types";
import { useUrlState } from "@/hooks/useUrlState";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Pagination } from "@/components/ui/Pagination";
import { SeverityTag, StatusTag } from "@/components/ui/Tag";
import { DateTimeCell } from "@/components/ui/DateTimeCell";
import { HostCell } from "@/components/ui/HostCell";
import type { Severity } from "@/lib/api/types";

const OUTCOMES: DeliveryOutcome[] = ["sent", "failed", "suppressed", "no_recipient", "category_disabled", "below_severity"];
const outcomeTone: Record<DeliveryOutcome, "success" | "danger" | "neutral" | "warning"> = {
  sent: "success",
  failed: "danger",
  suppressed: "neutral",
  no_recipient: "warning",
  category_disabled: "neutral",
  below_severity: "neutral",
};
const isSeverity = (s: string): s is Severity => ["critical", "high", "medium", "low"].includes(s);

/**
 * 通知记录：统一出口对每条告警、每个渠道的每一次决定。
 * 「为什么群里没收到」先看这里——没发的原因（类别未开启、没有匹配渠道、被抑制、发送失败）都分开记着。
 */
export function NotificationDeliveries({ categoryLabels }: { categoryLabels: Record<string, string> }) {
  const { t } = useTranslation();
  // 参数名带 d 前缀：与同页「通知配置」页签的 page / keyword 分开，切换页签不会互相串
  const [params, setParams] = useUrlState({ dpage: 1, dsize: 20, outcome: "", category: "", dkeyword: "" });
  const { data, isLoading } = useQuery({
    queryKey: ["notification-deliveries", params],
    queryFn: () =>
      systemApi.listNotificationDeliveries({
        page: params.dpage,
        page_size: params.dsize,
        outcome: params.outcome || undefined,
        category: params.category || undefined,
        keyword: params.dkeyword || undefined,
      }),
    refetchInterval: 30_000,
  });

  const columns: Column<NotificationDelivery>[] = [
    {
      key: "created_at",
      title: t("system.deliveries.colTime"),
      nowrap: true,
      render: (r) => <DateTimeCell value={r.created_at.slice(0, 19).replace("T", " ")} className="text-faint" />,
    },
    {
      key: "channel",
      title: t("system.deliveries.colChannel"),
      render: (r) => (
        <div className="min-w-0 max-w-[10rem]">
          <div className="truncate text-ink">{r.channel_name || "—"}</div>
          <div className="truncate text-xs text-faint">{categoryLabels[r.category] ?? r.category}</div>
        </div>
      ),
    },
    {
      key: "title",
      title: t("system.deliveries.colTitle"),
      render: (r) => (
        <div className="max-w-[18rem]">
          <div className="flex items-center gap-2">
            {isSeverity(r.severity) && <SeverityTag level={r.severity} />}
            {(r.kind === "resolved" || r.kind === "digest") && (
              <StatusTag tone="info">{t(`system.deliveries.kind.${r.kind}`)}</StatusTag>
            )}
          </div>
          <div title={r.title} className="mt-1 line-clamp-2 text-ink">
            {r.title}
          </div>
        </div>
      ),
    },
    {
      key: "host",
      title: t("system.deliveries.colHost"),
      render: (r) => <HostCell hostname={r.hostname} hostId={r.host_id} />,
    },
    {
      key: "outcome",
      title: t("system.deliveries.colOutcome"),
      render: (r) => (
        <div className="max-w-[14rem]">
          <StatusTag tone={outcomeTone[r.outcome] ?? "neutral"}>{t(`system.deliveries.outcome.${r.outcome}`)}</StatusTag>
          {r.error && (
            <div title={r.error} className="mt-1 line-clamp-2 text-xs text-danger">
              {r.error}
            </div>
          )}
        </div>
      ),
    },
  ];

  const outcomeOptions = [
    { value: "", label: t("system.deliveries.allOutcomes") },
    ...OUTCOMES.map((o) => ({ value: o, label: t(`system.deliveries.outcome.${o}`) })),
  ];
  const categoryOptions = [
    { value: "", label: t("system.deliveries.allCategories") },
    ...Object.entries(categoryLabels).map(([value, label]) => ({ value, label })),
  ];

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">{t("system.deliveries.desc")}</p>
      <FilterBar>
        <SearchInput
          value={params.dkeyword}
          onChange={(v) => setParams((p) => ({ ...p, dkeyword: v, dpage: 1 }))}
          placeholder={t("system.deliveries.searchPlaceholder")}
        />
        <Select value={params.outcome} onChange={(v) => setParams((p) => ({ ...p, outcome: v, dpage: 1 }))} options={outcomeOptions} />
        <Select value={params.category} onChange={(v) => setParams((p) => ({ ...p, category: v, dpage: 1 }))} options={categoryOptions} />
      </FilterBar>
      <Card>
        <DataTable
          columns={columns}
          rows={data?.items ?? []}
          rowKey={(r) => r.id}
          loading={isLoading}
          emptyText={t("system.deliveries.empty")}
        />
        <Pagination
          page={params.dpage}
          pageSize={params.dsize}
          total={data?.total ?? 0}
          onChange={(dpage) => setParams((p) => ({ ...p, dpage }))}
        />
      </Card>
    </div>
  );
}
