"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { kubeApi } from "@/lib/api/kube";
import type { KubeEvent, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { ClusterFilter } from "@/components/kube/ClusterFilter";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  severity: string;
  status: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

function isSeverity(v: string): v is Severity {
  return v === "critical" || v === "high" || v === "medium" || v === "low";
}

const buildSeverityOptions = (t: TFunction) => [
  { label: t("kube.common.allSeverity"), value: "" },
  { label: t("common.severity.critical"), value: "critical" },
  { label: t("common.severity.high"), value: "high" },
  { label: t("common.severity.medium"), value: "medium" },
  { label: t("common.severity.low"), value: "low" },
];
const buildStatusOptions = (t: TFunction) => [
  { label: t("kube.common.allStatus"), value: "" },
  { label: t("kube.common.statusPending"), value: "pending" },
  { label: t("kube.common.statusProcessed"), value: "processed" },
  { label: t("kube.common.statusIgnored"), value: "ignored" },
];

const buildStatusMeta = (t: TFunction): Record<string, { tone: Tone; label: string }> => ({
  pending: { tone: "danger", label: t("kube.common.statusPending") },
  processed: { tone: "success", label: t("kube.common.statusProcessed") },
  ignored: { tone: "neutral", label: t("kube.common.statusIgnored") },
});

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="text-ink">{value}</span>
    </div>
  );
}

export default function KubeEventsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, severity: "", status: "", cluster_id: "" });

  const severityOptions = buildSeverityOptions(t);
  const statusOptions = buildStatusOptions(t);
  const statusMeta = buildStatusMeta(t);
  const statusTag = (s: string) => statusMeta[s] ?? { tone: "neutral" as Tone, label: s };

  const { data, isLoading } = useQuery({
    queryKey: ["kube-events", params],
    queryFn: () =>
      kubeApi.listEvents({
        page: params.page,
        page_size: params.page_size,
        severity: params.severity || undefined,
        status: params.status || undefined,
        cluster_id: params.cluster_id || undefined,
      }),
  });

  const [detail, setDetail] = useState<KubeEvent | null>(null);
  const [handling, setHandling] = useState<KubeEvent | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["kube-events"] });

  const handleMutation = useMutation({
    mutationFn: (id: number) => kubeApi.handleEvent(id),
    onSuccess: () => {
      invalidate();
      setHandling(null);
      setDetail(null);
      toast.success(t("kube.events.processed"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<KubeEvent>[] = [
    { key: "createdAt", title: t("common.time"), render: (r) => <span className="text-faint tabular-nums">{r.createdAt}</span> },
    { key: "clusterName", title: t("kube.common.colCluster"), render: (r) => <span className="font-medium text-ink">{r.clusterName}</span> },
    { key: "namespace", title: t("kube.common.colNamespace"), render: (r) => <span className="font-mono text-sm text-muted">{r.namespace || "—"}</span> },
    { key: "eventType", title: t("kube.events.colEventType"), render: (r) => <StatusTag tone="neutral">{r.eventType}</StatusTag> },
    {
      key: "severity",
      title: t("common.level"),
      render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : <StatusTag tone="neutral">{r.severity}</StatusTag>),
    },
    {
      key: "title",
      title: t("kube.events.colTitle"),
      render: (r) => <span className="block max-w-xs truncate text-ink">{r.title}</span>,
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => <StatusTag tone={statusTag(r.status).tone}>{statusTag(r.status).label}</StatusTag>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          <Button variant="ghost" className="h-8 px-3" disabled={r.status !== "pending"} onClick={() => setHandling(r)}>
            {t("kube.common.actionProcess")}
          </Button>
          <Button variant="ghost" className="h-8 px-3" onClick={() => setDetail(r)}>
            {t("common.details")}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <FilterBar>
          <ClusterFilter
            value={params.cluster_id}
            onChange={(v) => setParams((p) => ({ ...p, cluster_id: v, page: 1 }))}
          />
          <Select
            value={params.severity}
            onChange={(v) => setParams((p) => ({ ...p, severity: v, page: 1 }))}
            options={severityOptions}
          />
          <Select
            value={params.status}
            onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))}
            options={statusOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("kube.events.empty")}
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
        title={t("kube.events.detailTitle")}
        width={560}
        footer={
          detail?.status === "pending" ? <Button onClick={() => detail && setHandling(detail)}>{t("kube.common.actionProcess")}</Button> : undefined
        }
      >
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold text-ink">{detail.title}</h2>
              <div className="flex items-center gap-2">
                {isSeverity(detail.severity) ? (
                  <SeverityTag level={detail.severity} />
                ) : (
                  <StatusTag tone="neutral">{detail.severity}</StatusTag>
                )}
                <StatusTag tone={statusTag(detail.status).tone}>{statusTag(detail.status).label}</StatusTag>
              </div>
            </div>
            <div className="space-y-2">
              <Field label={t("kube.common.colCluster")} value={detail.clusterName} />
              <Field label={t("kube.common.colNamespace")} value={<span className="font-mono">{detail.namespace || "—"}</span>} />
              <Field label={t("kube.events.fieldEventType")} value={detail.eventType} />
              <Field label={t("common.time")} value={<span className="tabular-nums">{detail.createdAt}</span>} />
            </div>
            {detail.message && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("common.details")}</div>
                <p className="text-sm leading-relaxed text-muted">{detail.message}</p>
              </div>
            )}
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!handling}
        title={t("kube.events.processTitle")}
        desc={handling ? t("kube.events.processConfirmDesc", { title: handling.title }) : undefined}
        loading={handleMutation.isPending}
        onConfirm={() => handling && handleMutation.mutate(handling.id)}
        onCancel={() => setHandling(null)}
      />
    </>
  );
}
