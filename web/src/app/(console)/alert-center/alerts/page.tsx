"use client";
import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Bell, AlertTriangle, CheckCircle, EyeOff } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { alertsApi } from "@/lib/api/alerts";
import { businessLinesApi } from "@/lib/api/assets";
import type { Alert, AlertSource } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { toast } from "@/components/ui/toast";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { CloseAlertModal, type CloseAction } from "@/components/alerts/CloseAlertModal";
import { WhitelistFromAlertModal } from "@/components/alerts/WhitelistFromAlertModal";

interface ListParams {
  page: number;
  page_size: number;
  status: string;
  severity: string;
  alert_type: string;
  keyword: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

const statusTone: Record<Alert["status"], Tone> = {
  active: "danger",
  suppressed: "info",
  resolved: "success",
  ignored: "neutral",
};

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="text-ink">{value}</span>
    </div>
  );
}

export default function AlertsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const sourceLabel = (s: AlertSource) => t(`alerts.source.${s}`, { defaultValue: s });
  const statusLabel = (s: Alert["status"]) => t(`alerts.status.${s}`);
  const statusOptions = [
    { label: t("alerts.list.allStatus"), value: "" },
    { label: t("alerts.status.active"), value: "active" },
    { label: t("alerts.status.suppressed"), value: "suppressed" },
    { label: t("alerts.status.resolved"), value: "resolved" },
    { label: t("alerts.status.ignored"), value: "ignored" },
  ];
  const severityOptions = [
    { label: t("alerts.list.allSeverity"), value: "" },
    { label: t("common.severity.critical"), value: "critical" },
    { label: t("common.severity.high"), value: "high" },
    { label: t("common.severity.medium"), value: "medium" },
    { label: t("common.severity.low"), value: "low" },
  ];
  const typeOptions = [
    { label: t("alerts.list.allType"), value: "" },
    { label: t("alerts.source.baseline"), value: "baseline" },
    { label: t("alerts.source.detection"), value: "detection" },
    { label: t("alerts.source.agent"), value: "agent" },
    { label: t("alerts.source.vulnerability"), value: "vulnerability" },
    { label: t("alerts.source.fim"), value: "fim" },
    { label: t("alerts.source.virus"), value: "virus" },
    { label: t("alerts.source.kube"), value: "kube" },
  ];

  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    status: "",
    severity: "",
    alert_type: "",
    keyword: "",
    host_id: "",
    business_line: "",
  });

  const { data: blData } = useQuery({
    queryKey: ["business-lines-all"],
    queryFn: () => businessLinesApi.list({ page: 1, page_size: 200 }),
  });
  const businessLineOptions = [
    { label: t("alerts.list.allBusinessLine"), value: "" },
    ...(blData?.items ?? []).map((b) => ({ label: b.name, value: b.name })),
  ];

  const { data: stats, isError: statsError } = useQuery({
    queryKey: ["alerts-stats"],
    queryFn: () => alertsApi.statistics(),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["alerts", params],
    queryFn: () =>
      alertsApi.list({
        page: params.page,
        page_size: params.page_size,
        status: params.status || undefined,
        severity: params.severity || undefined,
        alert_type: params.alert_type || undefined,
        keyword: params.keyword || undefined,
        host_id: params.host_id || undefined,
        business_line: params.business_line || undefined,
      }),
  });

  const [detail, setDetail] = useState<Alert | null>(null);
  // 通知里的「查看详情」带 ?id=，直接打开这条告警；它不一定在当前筛选的第一页里。
  // 必须在首次渲染时读：useUrlState 的 effect 会按筛选参数重写地址栏，把 id 抹掉。
  const [deepLinkId] = useState(() =>
    typeof window === "undefined" ? 0 : Number(new URLSearchParams(window.location.search).get("id")) || 0,
  );
  useEffect(() => {
    if (!deepLinkId) return;
    alertsApi
      .get(deepLinkId)
      .then(setDetail)
      .catch(() => toast.error(t("alerts.notFound")));
  }, [deepLinkId, t]);
  const [closing, setClosing] = useState<{ alert: Alert; action: CloseAction } | null>(null);
  const [whitelisting, setWhitelisting] = useState<Alert | null>(null);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["alerts"] });
    queryClient.invalidateQueries({ queryKey: ["alerts-stats"] });
  };

  const isOpen = (a: Alert) => a.status === "active" || a.status === "suppressed";
  const openClose = (alert: Alert, action: CloseAction) => setClosing({ alert, action });

  const columns: Column<Alert>[] = [
    {
      key: "title",
      title: t("alerts.list.colTitle"),
      render: (r) => (
        <div className="flex items-center gap-2">
          {r.recurrence_of && <StatusTag tone="warning">{t("alerts.list.recurrenceTag")}</StatusTag>}
          <span className="font-medium text-ink">{r.title}</span>
        </div>
      ),
    },
    {
      key: "source",
      title: t("alerts.list.colSource"),
      render: (r) => <StatusTag tone="neutral">{sourceLabel(r.source)}</StatusTag>,
    },
    { key: "severity", title: t("common.level"), render: (r) => <SeverityTag level={r.severity} /> },
    {
      key: "risk_score",
      title: t("alerts.list.colRisk"),
      render: (r) => {
        const s = r.risk_score ?? 0;
        const tone = s >= 70 ? "danger" : s >= 40 ? "warning" : "neutral";
        return <StatusTag tone={tone}>{s}</StatusTag>;
      },
    },
    {
      key: "host",
      title: t("alerts.list.colHost"),
      render: (r) => {
        const h = r.host?.hostname ?? r.host_id;
        return (
          <span className="block max-w-[220px] truncate text-faint" title={h}>
            {h}
          </span>
        );
      },
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => <StatusTag tone={statusTone[r.status]}>{statusLabel(r.status)}</StatusTag>,
    },
    {
      key: "last_seen_at",
      title: t("alerts.list.colLastSeen"),
      render: (r) => <span className="text-faint tabular-nums">{r.last_seen_at}</span>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          <Button
            variant="ghost"
            className="h-8 whitespace-nowrap px-3"
            disabled={!isOpen(r)}
            onClick={() => openClose(r, "resolve")}
          >
            {t("alerts.list.actionResolve")}
          </Button>
          <Button
            variant="ghost"
            className="h-8 whitespace-nowrap px-3"
            disabled={!isOpen(r)}
            onClick={() => openClose(r, "ignore")}
          >
            {t("alerts.list.actionIgnore")}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 mb-5">
        <StatCard compact label={t("alerts.list.statTotal")} value={stats?.total ?? 0} error={statsError} icon={Bell} tone="default" />
        <StatCard compact label={t("alerts.list.statActive")} value={stats?.active ?? 0} error={statsError} icon={AlertTriangle} tone="danger" />
        <StatCard compact label={t("alerts.list.statResolved")} value={stats?.resolved ?? 0} error={statsError} icon={CheckCircle} tone="success" />
        <StatCard compact label={t("alerts.list.statIgnored")} value={stats?.ignored ?? 0} error={statsError} icon={EyeOff} tone="warning" />
      </div>

      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={params.keyword}
            onChange={(v) => setParams((p) => ({ ...p, keyword: v, page: 1 }))}
            placeholder={t("alerts.list.searchPlaceholder")}
          />
          <Select
            value={params.status}
            onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))}
            options={statusOptions}
          />
          <Select
            value={params.severity}
            onChange={(v) => setParams((p) => ({ ...p, severity: v, page: 1 }))}
            options={severityOptions}
          />
          <Select
            value={params.alert_type}
            onChange={(v) => setParams((p) => ({ ...p, alert_type: v, page: 1 }))}
            options={typeOptions}
          />
          <Select
            value={params.business_line}
            onChange={(v) => setParams((p) => ({ ...p, business_line: v, page: 1 }))}
            options={businessLineOptions}
          />
          <Input
            value={params.host_id}
            onChange={(e) => setParams((p) => ({ ...p, host_id: e.target.value, page: 1 }))}
            placeholder={t("alerts.list.filterHostId")}
            className="w-56"
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("alerts.list.empty")}
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

      <Drawer
        open={!!detail}
        onClose={() => setDetail(null)}
        title={t("alerts.list.detailTitle")}
        width={560}
        footer={
          detail ? (
            <>
              {detail.host_id !== "fleet" && (
                <Button variant="ghost" onClick={() => setWhitelisting(detail)}>
                  {t("alerts.list.actionWhitelist")}
                </Button>
              )}
              {isOpen(detail) && (
                <>
                  <Button variant="ghost" onClick={() => openClose(detail, "ignore")}>
                    {t("alerts.list.actionIgnore")}
                  </Button>
                  <Button onClick={() => openClose(detail, "resolve")}>{t("alerts.list.actionResolve")}</Button>
                </>
              )}
            </>
          ) : undefined
        }
      >
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold text-ink">{detail.title}</h2>
              <div className="flex items-center gap-2">
                <SeverityTag level={detail.severity} />
                <StatusTag tone={statusTone[detail.status]}>{statusLabel(detail.status)}</StatusTag>
              </div>
            </div>

            <div className="space-y-2">
              <Field label={t("alerts.list.colSource")} value={sourceLabel(detail.source)} />
              <Field label={t("alerts.list.colHost")} value={detail.host?.hostname ?? detail.host_id} />
              <Field label={t("alerts.list.fieldCategory")} value={detail.category || "—"} />
              <Field label={t("alerts.list.fieldFirstSeen")} value={<span className="tabular-nums">{detail.first_seen_at}</span>} />
              <Field label={t("alerts.list.fieldLastSeen")} value={<span className="tabular-nums">{detail.last_seen_at}</span>} />
              {detail.recurrence_of && <Field label={t("alerts.list.fieldRecurrenceOf")} value={`#${detail.recurrence_of}`} />}
              {detail.status === "suppressed" && (
                <Field
                  label={t("alerts.list.fieldSuppressedBy")}
                  value={
                    detail.suppression_id
                      ? t("alerts.list.suppressedByRule", { id: detail.suppression_id })
                      : t("alerts.list.suppressedByFleet")
                  }
                />
              )}
              {detail.verdict && <Field label={t("alerts.list.fieldVerdict")} value={t(`alerts.verdict.${detail.verdict}`)} />}
              {detail.resolved_by && <Field label={t("alerts.list.fieldResolvedBy")} value={detail.resolved_by} />}
              {detail.resolve_reason && <Field label={t("alerts.list.fieldResolveReason")} value={detail.resolve_reason} />}
            </div>

            {detail.description && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("alerts.list.fieldDescription")}</div>
                <p className="text-sm leading-relaxed text-muted">{detail.description}</p>
              </div>
            )}

            {detail.actual && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("alerts.list.fieldActual")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                  {detail.actual}
                </pre>
              </div>
            )}
            {detail.expected && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("alerts.list.fieldExpected")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                  {detail.expected}
                </pre>
              </div>
            )}

            {detail.fix_suggestion && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("alerts.list.fieldFixSuggestion")}</div>
                <div className="rounded-r-control border-l-4 border-primary bg-primary/5 p-3 text-sm leading-relaxed text-ink">
                  {detail.fix_suggestion}
                </div>
              </div>
            )}
          </div>
        )}
      </Drawer>

      <CloseAlertModal
        alert={closing?.alert ?? null}
        action={closing?.action ?? "resolve"}
        onClose={() => setClosing(null)}
        onDone={() => {
          invalidate();
          setClosing(null);
          setDetail(null);
        }}
      />

      <WhitelistFromAlertModal
        alert={whitelisting}
        onClose={() => setWhitelisting(null)}
        onDone={() => setWhitelisting(null)}
      />
    </>
  );
}
