"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Archive, ShieldAlert, Server, HardDrive } from "lucide-react";
import { virusApi } from "@/lib/api/virus";
import { useUrlState } from "@/hooks/useUrlState";
import type { Severity, QuarantineItem } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

function isSeverity(v: string): v is Severity {
  return v === "critical" || v === "high" || v === "medium" || v === "low";
}

const buildThreatTypeLabels = (t: TFunction): Record<string, string> => ({
  virus: t("virus.threatType.virus"),
  trojan: t("virus.threatType.trojan"),
  worm: t("virus.threatType.worm"),
  ransomware: t("virus.threatType.ransomware"),
  rootkit: t("virus.threatType.rootkit"),
  miner: t("virus.threatType.miner"),
  backdoor: t("virus.threatType.backdoor"),
  other: t("virus.threatType.other"),
});
const buildStatusMeta = (t: TFunction): Record<string, { tone: Tone; label: string }> => ({
  quarantined: { tone: "warning", label: t("virus.quarantine.status.quarantined") },
  restored: { tone: "success", label: t("virus.quarantine.status.restored") },
  deleted: { tone: "neutral", label: t("virus.quarantine.status.deleted") },
});

const buildStatusOptions = (t: TFunction) => [
  { label: t("common.allStatus"), value: "" },
  { label: t("virus.quarantine.status.quarantined"), value: "quarantined" },
  { label: t("virus.quarantine.status.restored"), value: "restored" },
  { label: t("virus.quarantine.status.deleted"), value: "deleted" },
];
const buildSeverityOptions = (t: TFunction) => [
  { label: t("common.allSeverity"), value: "" },
  { label: t("common.severity.critical"), value: "critical" },
  { label: t("common.severity.high"), value: "high" },
  { label: t("common.severity.medium"), value: "medium" },
  { label: t("common.severity.low"), value: "low" },
];

function formatFileSize(bytes: number): string {
  if (!bytes) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let size = bytes;
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024;
    i++;
  }
  return `${size.toFixed(1)} ${units[i]}`;
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="min-w-0 break-all text-ink">{value}</span>
    </div>
  );
}

interface ListParams {
  page: number;
  page_size: number;
  keyword: string;
  status: string;
  severity: string;
}

export default function QuarantinePage() {
  const { t } = useTranslation();
  const threatTypeLabels = buildThreatTypeLabels(t);
  const statusMeta = buildStatusMeta(t);
  const statusOptions = buildStatusOptions(t);
  const severityOptions = buildSeverityOptions(t);
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, keyword: "", status: "", severity: "" });

  const { data: stats, isError: statsError } = useQuery({
    queryKey: ["quarantine-stats"],
    queryFn: () => virusApi.quarantineStatistics(),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["quarantine-files", params],
    queryFn: () =>
      virusApi.listQuarantine({
        page: params.page,
        page_size: params.page_size,
        keyword: params.keyword || undefined,
        status: params.status || undefined,
        severity: params.severity || undefined,
      }),
  });

  const [detail, setDetail] = useState<QuarantineItem | null>(null);
  const [restoring, setRestoring] = useState<QuarantineItem | null>(null);
  const [deleting, setDeleting] = useState<QuarantineItem | null>(null);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["quarantine-files"] });
    queryClient.invalidateQueries({ queryKey: ["quarantine-stats"] });
  };

  const restoreMutation = useMutation({
    mutationFn: (id: number) => virusApi.restoreQuarantine(id),
    onSuccess: () => {
      invalidate();
      setRestoring(null);
      setDetail(null);
      toast.success(t("virus.quarantine.toastRestored"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => virusApi.deleteQuarantine(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      setDetail(null);
      toast.success(t("virus.quarantine.toastDeleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<QuarantineItem>[] = [
    {
      key: "originalPath",
      title: t("virus.quarantine.colFilePath"),
      render: (r) => <span className="font-mono text-xs text-muted break-all">{r.originalPath}</span>,
    },
    { key: "host", title: t("common.host"), render: (r) => <span className="text-faint">{r.hostname || r.hostId}</span> },
    { key: "threatName", title: t("virus.quarantine.colThreatName"), render: (r) => <span className="font-medium text-ink">{r.threatName}</span> },
    {
      key: "severity",
      title: t("common.level"),
      render: (r) =>
        isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : <StatusTag tone="neutral">{r.severity}</StatusTag>,
    },
    { key: "fileSize", title: t("virus.quarantine.colSize"), render: (r) => <span className="text-faint tabular-nums">{formatFileSize(r.fileSize)}</span> },
    {
      key: "quarantinedAt",
      title: t("virus.quarantine.colQuarantinedAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.quarantinedAt}</span>,
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => {
        const m = statusMeta[r.status] ?? { tone: "neutral" as Tone, label: r.status };
        return <StatusTag tone={m.tone}>{m.label}</StatusTag>;
      },
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) =>
        r.status === "quarantined" ? (
          <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
            <button
              type="button"
              className="text-sm text-success transition-colors hover:opacity-80"
              onClick={() => setRestoring(r)}
            >
              {t("virus.quarantine.restore")}
            </button>
            <button
              type="button"
              className="text-sm text-danger transition-colors hover:opacity-80"
              onClick={() => setDeleting(r)}
            >
              {t("common.delete")}
            </button>
          </div>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
  ];

  return (
    <>
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard compact label={t("virus.quarantine.statQuarantined")} value={stats?.quarantined ?? 0} error={statsError} icon={Archive} tone="warning" />
        <StatCard
          compact
          label={t("virus.quarantine.statHighRisk")}
          value={(stats?.severity.critical ?? 0) + (stats?.severity.high ?? 0)}
          error={statsError}
          icon={ShieldAlert}
          tone="danger"
        />
        <StatCard compact label={t("virus.quarantine.statAffectedHosts")} value={stats?.affectedHosts ?? 0} error={statsError} icon={Server} tone="default" />
        <StatCard compact label={t("virus.quarantine.statStorage")} value={formatFileSize(stats?.totalSize ?? 0)} error={statsError} icon={HardDrive} tone="success" />
      </div>

      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={params.keyword}
            onChange={(v) => setParams((p) => ({ ...p, keyword: v, page: 1 }))}
            placeholder={t("virus.quarantine.search")}
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
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("virus.quarantine.empty")}
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
        title={t("virus.quarantine.detailTitle")}
        width={560}
        footer={
          detail?.status === "quarantined" ? (
            <>
              <Button variant="ghost" onClick={() => detail && setRestoring(detail)}>
                {t("virus.quarantine.restoreFile")}
              </Button>
              <Button variant="danger" onClick={() => detail && setDeleting(detail)}>
                {t("virus.quarantine.deletePermanently")}
              </Button>
            </>
          ) : undefined
        }
      >
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold text-ink">{detail.threatName}</h2>
              <div className="flex items-center gap-2">
                {isSeverity(detail.severity) ? (
                  <SeverityTag level={detail.severity} />
                ) : (
                  <StatusTag tone="neutral">{detail.severity}</StatusTag>
                )}
                <StatusTag tone={(statusMeta[detail.status] ?? { tone: "neutral" as Tone }).tone}>
                  {(statusMeta[detail.status] ?? { label: detail.status }).label}
                </StatusTag>
              </div>
            </div>
            <div className="space-y-2">
              <Field label={t("virus.quarantine.fieldThreatType")} value={threatTypeLabels[detail.threatType] ?? detail.threatType} />
              <Field label={t("virus.quarantine.fieldOriginalPath")} value={<span className="font-mono text-xs">{detail.originalPath}</span>} />
              {detail.quarantinePath && (
                <Field label={t("virus.quarantine.fieldQuarantinePath")} value={<span className="font-mono text-xs">{detail.quarantinePath}</span>} />
              )}
              <Field label={t("virus.quarantine.fieldFileHash")} value={<span className="font-mono text-xs">{detail.fileHash || "—"}</span>} />
              <Field label={t("virus.quarantine.fieldFileSize")} value={formatFileSize(detail.fileSize)} />
              <Field label={t("virus.quarantine.fieldFilePermission")} value={detail.filePermission || "—"} />
              <Field label={t("virus.quarantine.fieldFileOwner")} value={detail.fileOwner || "—"} />
              <Field label={t("common.host")} value={`${detail.hostname || detail.hostId}${detail.ip ? ` (${detail.ip})` : ""}`} />
              <Field label={t("virus.quarantine.fieldQuarantinedBy")} value={detail.quarantinedBy || "—"} />
              <Field label={t("virus.quarantine.fieldQuarantinedAt")} value={<span className="tabular-nums">{detail.quarantinedAt}</span>} />
              {detail.restoredAt && <Field label={t("virus.quarantine.fieldRestoredAt")} value={<span className="tabular-nums">{detail.restoredAt}</span>} />}
              {detail.deletedAt && <Field label={t("virus.quarantine.fieldDeletedAt")} value={<span className="tabular-nums">{detail.deletedAt}</span>} />}
            </div>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!restoring}
        title={t("virus.quarantine.restoreTitle")}
        desc={restoring ? t("virus.quarantine.restoreDesc", { path: restoring.originalPath }) : undefined}
        danger={false}
        confirmText={t("virus.quarantine.restoreConfirm")}
        loading={restoreMutation.isPending}
        onConfirm={() => restoring && restoreMutation.mutate(restoring.id)}
        onCancel={() => setRestoring(null)}
      />

      <ConfirmDialog
        open={!!deleting}
        title={t("virus.quarantine.deleteTitle")}
        desc={deleting ? t("virus.quarantine.deleteDesc", { path: deleting.originalPath }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
