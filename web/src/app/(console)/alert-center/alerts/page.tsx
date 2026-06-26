"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Bell, AlertTriangle, CheckCircle, EyeOff } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { alertsApi } from "@/lib/api/alerts";
import type { Alert, AlertSource } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { Modal } from "@/components/ui/Modal";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Textarea } from "@/components/ui/Input";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

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
  });

  const { data: stats } = useQuery({
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
      }),
  });

  const [detail, setDetail] = useState<Alert | null>(null);
  const [resolving, setResolving] = useState<Alert | null>(null);
  const [reason, setReason] = useState("");
  const [ignoring, setIgnoring] = useState<Alert | null>(null);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["alerts"] });
    queryClient.invalidateQueries({ queryKey: ["alerts-stats"] });
  };

  const resolveMutation = useMutation({
    mutationFn: ({ id, reason }: { id: number; reason: string }) => alertsApi.resolve(id, reason),
    onSuccess: () => {
      invalidate();
      setResolving(null);
      setReason("");
      setDetail(null);
      toast.success(t("alerts.list.resolved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const ignoreMutation = useMutation({
    mutationFn: (id: number) => alertsApi.ignore(id),
    onSuccess: () => {
      invalidate();
      setIgnoring(null);
      setDetail(null);
      toast.success(t("alerts.list.ignored"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const openResolve = (a: Alert) => {
    setResolving(a);
    setReason("");
  };

  const columns: Column<Alert>[] = [
    { key: "title", title: t("alerts.list.colTitle"), render: (r) => <span className="font-medium text-ink">{r.title}</span> },
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
            disabled={r.status !== "active"}
            onClick={() => openResolve(r)}
          >
            {t("alerts.list.actionResolve")}
          </Button>
          <Button
            variant="ghost"
            className="h-8 whitespace-nowrap px-3"
            disabled={r.status !== "active"}
            onClick={() => setIgnoring(r)}
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
        <StatCard compact label={t("alerts.list.statTotal")} value={stats?.total ?? 0} icon={Bell} tone="default" />
        <StatCard compact label={t("alerts.list.statActive")} value={stats?.active ?? 0} icon={AlertTriangle} tone="danger" />
        <StatCard compact label={t("alerts.list.statResolved")} value={stats?.resolved ?? 0} icon={CheckCircle} tone="success" />
        <StatCard compact label={t("alerts.list.statIgnored")} value={stats?.ignored ?? 0} icon={EyeOff} tone="warning" />
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
          detail?.status === "active" ? (
            <>
              <Button variant="ghost" onClick={() => detail && setIgnoring(detail)}>
                {t("alerts.list.actionIgnore")}
              </Button>
              <Button onClick={() => detail && openResolve(detail)}>{t("alerts.list.actionResolve")}</Button>
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

      <Modal
        open={!!resolving}
        onClose={() => setResolving(null)}
        title={t("alerts.list.resolveTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setResolving(null)}>
              {t("common.cancel")}
            </Button>
            <Button
              onClick={() => resolving && resolveMutation.mutate({ id: resolving.id, reason })}
              disabled={resolveMutation.isPending}
            >
              {resolveMutation.isPending ? t("common.processing") : t("alerts.list.resolveConfirm")}
            </Button>
          </>
        }
      >
        <FormField label={t("alerts.list.resolveReason")}>
          <Textarea value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("alerts.list.resolveReasonPlaceholder")} />
        </FormField>
      </Modal>

      <ConfirmDialog
        open={!!ignoring}
        title={t("alerts.list.ignoreTitle")}
        desc={ignoring ? t("alerts.list.ignoreConfirmDesc", { title: ignoring.title }) : undefined}
        loading={ignoreMutation.isPending}
        onConfirm={() => ignoring && ignoreMutation.mutate(ignoring.id)}
        onCancel={() => setIgnoring(null)}
      />
    </>
  );
}
