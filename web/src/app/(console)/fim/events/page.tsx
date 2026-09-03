"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { fimApi } from "@/lib/api/fim";
import type { FimEvent, FimChangeType, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Drawer } from "@/components/ui/Drawer";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";

interface ListParams {
  page: number;
  page_size: number;
  hostname: string;
  change_type: string;
  severity: string;
  category: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

const CHANGE_TONE: Record<FimChangeType, Tone> = {
  added: "success",
  removed: "danger",
  changed: "warning",
};

const buildChangeTypeOptions = (t: TFunction) => [
  { label: t("fim.events.allChangeType"), value: "" },
  { label: t("fim.changeType.added"), value: "added" },
  { label: t("fim.changeType.removed"), value: "removed" },
  { label: t("fim.changeType.changed"), value: "changed" },
];
const buildSeverityOptions = (t: TFunction) => [
  { label: t("common.allSeverity"), value: "" },
  { label: t("common.severity.critical"), value: "critical" },
  { label: t("common.severity.high"), value: "high" },
  { label: t("common.severity.medium"), value: "medium" },
  { label: t("common.severity.low"), value: "low" },
];
const buildCategoryOptions = (t: TFunction) => [
  { label: t("fim.events.allCategory"), value: "" },
  { label: t("fim.category.binary"), value: "binary" },
  { label: t("fim.category.config"), value: "config" },
  { label: t("fim.category.auth"), value: "auth" },
  { label: t("fim.category.log"), value: "log" },
  { label: t("fim.category.other"), value: "other" },
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
function isSeverity(v: string): v is Severity {
  return (SEVERITIES as string[]).includes(v);
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="min-w-0 break-all text-ink">{value}</span>
    </div>
  );
}

export default function FimEventsPage() {
  const { t } = useTranslation();
  const changeTypeOptions = buildChangeTypeOptions(t);
  const severityOptions = buildSeverityOptions(t);
  const categoryOptions = buildCategoryOptions(t);
  const categoryLabel: Record<string, string> = {
    binary: t("fim.category.binary"),
    config: t("fim.category.config"),
    auth: t("fim.category.auth"),
    log: t("fim.category.log"),
    other: t("fim.category.other"),
  };
  const changeMeta = (ct: FimChangeType) => ({
    tone: CHANGE_TONE[ct] ?? ("neutral" as Tone),
    label: t(`fim.changeType.${ct}`, ct),
  });
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    hostname: "",
    change_type: "",
    severity: "",
    category: "",
  });

  const { data, isLoading } = useQuery({
    queryKey: ["fim-events", params],
    queryFn: () =>
      fimApi.listEvents({
        page: params.page,
        page_size: params.page_size,
        hostname: params.hostname || undefined,
        change_type: params.change_type || undefined,
        severity: params.severity || undefined,
        category: params.category || undefined,
      }),
  });

  const [detail, setDetail] = useState<FimEvent | null>(null);

  const columns: Column<FimEvent>[] = [
    {
      key: "detected_at",
      title: t("fim.events.colTime"),
      render: (r) => <span className="text-faint tabular-nums">{r.detected_at}</span>,
    },
    { key: "hostname", title: t("fim.events.colHost"), render: (r) => <span className="font-medium text-ink">{r.hostname || r.host_id}</span> },
    {
      key: "file_path",
      title: t("fim.events.colFilePath"),
      render: (r) => <span className="block max-w-[320px] truncate font-mono text-xs text-ink">{r.file_path}</span>,
    },
    {
      key: "change_type",
      title: t("fim.events.colChangeType"),
      render: (r) => {
        const m = changeMeta(r.change_type);
        return <StatusTag tone={m.tone}>{m.label}</StatusTag>;
      },
    },
    {
      key: "severity",
      title: t("fim.events.colLevel"),
      render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : <StatusTag tone="neutral">{r.severity}</StatusTag>),
    },
    {
      key: "category",
      title: t("fim.events.colCategory"),
      render: (r) => <StatusTag tone="neutral">{categoryLabel[r.category] ?? r.category}</StatusTag>,
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={params.hostname}
            onChange={(v) => setParams((p) => ({ ...p, hostname: v, page: 1 }))}
            placeholder={t("fim.events.searchPlaceholder")}
          />
          <Select
            value={params.change_type}
            onChange={(v) => setParams((p) => ({ ...p, change_type: v, page: 1 }))}
            options={changeTypeOptions}
          />
          <Select
            value={params.severity}
            onChange={(v) => setParams((p) => ({ ...p, severity: v, page: 1 }))}
            options={severityOptions}
          />
          <Select
            value={params.category}
            onChange={(v) => setParams((p) => ({ ...p, category: v, page: 1 }))}
            options={categoryOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => `${r.trace_id}`}
            loading={isLoading}
            emptyText={t("fim.events.empty")}
            onRowClick={setDetail}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      <Drawer open={!!detail} onClose={() => setDetail(null)} title={t("fim.events.detailTitle")} width={560}>
        {detail && (
          <div className="space-y-5">
            <div>
              <div className="mb-1.5 text-sm font-medium text-ink">{t("fim.events.fieldFilePath")}</div>
              <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                {detail.file_path}
              </pre>
            </div>

            <div className="space-y-2">
              <Field label={t("fim.events.fieldHost")} value={detail.hostname || detail.host_id} />
              <Field label={t("fim.events.fieldChangeType")} value={<StatusTag tone={changeMeta(detail.change_type).tone}>{changeMeta(detail.change_type).label}</StatusTag>} />
              <Field
                label={t("fim.events.fieldLevel")}
                value={isSeverity(detail.severity) ? <SeverityTag level={detail.severity} /> : <StatusTag tone="neutral">{detail.severity}</StatusTag>}
              />
              <Field label={t("fim.events.fieldCategory")} value={categoryLabel[detail.category] ?? detail.category} />
              <Field label={t("fim.events.fieldTime")} value={<span className="tabular-nums">{detail.detected_at}</span>} />
            </div>

            {detail.detail && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("fim.events.fieldDetail")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                  {detail.detail}
                </pre>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </>
  );
}
