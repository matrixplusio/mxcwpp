"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ListChecks, Clock, Loader, CheckCircle, XCircle } from "lucide-react";
import { vulnApi } from "@/lib/api/vuln";
import type { RemediationTask } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";
import { useUrlState } from "@/hooks/useUrlState";

interface ListParams {
  page: number;
  page_size: number;
  status: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

const buildStatusMeta = (t: TFunction): Record<string, { tone: Tone; label: string }> => ({
  pending: { tone: "info", label: t("vuln.remediationTasks.statusPending") },
  confirmed: { tone: "info", label: t("vuln.remediationTasks.statusConfirmed") },
  running: { tone: "info", label: t("vuln.remediationTasks.statusRunning") },
  success: { tone: "success", label: t("vuln.remediationTasks.statusSuccess") },
  success_pending_verify: { tone: "info", label: t("vuln.remediationTasks.statusSuccessPendingVerify") },
  main_verifying: { tone: "info", label: t("vuln.remediationTasks.statusMainVerifying") },
  verified: { tone: "success", label: t("vuln.remediationTasks.statusVerified") },
  verify_failed: { tone: "danger", label: t("vuln.remediationTasks.statusVerifyFailed") },
  verify_blocked: { tone: "warning", label: t("vuln.remediationTasks.statusVerifyBlocked") },
  failed: { tone: "danger", label: t("vuln.remediationTasks.statusFailed") },
  cancelled: { tone: "neutral", label: t("vuln.remediationTasks.statusCancelled") },
});

const buildVerifyMeta = (t: TFunction): Record<string, { tone: Tone; label: string }> => ({
  verified: { tone: "success", label: t("vuln.remediationTasks.verifyVerified") },
  pending: { tone: "info", label: t("vuln.remediationTasks.verifyPending") },
  failed: { tone: "danger", label: t("vuln.remediationTasks.verifyFailed") },
});

const buildStatusOptions = (t: TFunction) => [
  { label: t("vuln.remediationTasks.allStatus"), value: "" },
  { label: t("vuln.remediationTasks.statusPending"), value: "pending" },
  { label: t("vuln.remediationTasks.statusConfirmed"), value: "confirmed" },
  { label: t("vuln.remediationTasks.statusRunning"), value: "running" },
  { label: t("vuln.remediationTasks.statusSuccess"), value: "success" },
  { label: t("vuln.remediationTasks.statusSuccessPendingVerify"), value: "success_pending_verify" },
  { label: t("vuln.remediationTasks.statusMainVerifying"), value: "main_verifying" },
  { label: t("vuln.remediationTasks.statusVerified"), value: "verified" },
  { label: t("vuln.remediationTasks.statusVerifyFailed"), value: "verify_failed" },
  { label: t("vuln.remediationTasks.statusVerifyBlocked"), value: "verify_blocked" },
  { label: t("vuln.remediationTasks.statusFailed"), value: "failed" },
  { label: t("vuln.remediationTasks.statusCancelled"), value: "cancelled" },
];

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="text-ink break-all">{value}</span>
    </div>
  );
}

export default function RemediationTasksPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const statusMeta = buildStatusMeta(t);
  const statusTag = (status: string) => {
    const meta = statusMeta[status] ?? { tone: "neutral" as Tone, label: status || "—" };
    return <StatusTag tone={meta.tone}>{meta.label}</StatusTag>;
  };
  const verifyMeta = buildVerifyMeta(t);
  const verifyTag = (status?: string) => {
    if (!status) return <span className="text-faint">—</span>;
    const meta = verifyMeta[status] ?? { tone: "neutral" as Tone, label: status };
    return <StatusTag tone={meta.tone}>{meta.label}</StatusTag>;
  };
  const statusOptions = buildStatusOptions(t);
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, status: "" });

  const { data: stats, isError: statsError } = useQuery({
    queryKey: ["remediation-task-stats"],
    queryFn: () => vulnApi.remediationTaskStats(),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["remediation-tasks", params],
    queryFn: () =>
      vulnApi.listRemediationTasks({
        page: params.page,
        page_size: params.page_size,
        status: params.status || undefined,
      }),
  });

  const [detailId, setDetailId] = useState<number | null>(null);
  const [confirming, setConfirming] = useState<RemediationTask | null>(null);
  const [cancelling, setCancelling] = useState<RemediationTask | null>(null);
  const [retrying, setRetrying] = useState<RemediationTask | null>(null);

  const detail = data?.items.find((t) => t.id === detailId) ?? null;

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["remediation-tasks"] });
    queryClient.invalidateQueries({ queryKey: ["remediation-task-stats"] });
  };

  const confirmMutation = useMutation({
    mutationFn: (id: number) => vulnApi.confirmRemediationTask(id),
    onSuccess: () => { invalidate(); setConfirming(null); toast.success(t("vuln.remediationTasks.confirmed")); },
    onError: (e: Error) => toast.error(e.message),
  });
  const cancelMutation = useMutation({
    mutationFn: (id: number) => vulnApi.cancelRemediationTask(id),
    onSuccess: () => { invalidate(); setCancelling(null); toast.success(t("vuln.remediationTasks.cancelled")); },
    onError: (e: Error) => toast.error(e.message),
  });
  const retryMutation = useMutation({
    mutationFn: (id: number) => vulnApi.retryRemediationTask(id),
    onSuccess: () => { invalidate(); setRetrying(null); toast.success(t("vuln.remediationTasks.retried")); },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<RemediationTask>[] = [
    { key: "cveId", title: "CVE", render: (r) => <span className="font-mono text-ink">{r.cveId}</span> },
    { key: "hostname", title: t("common.host"), render: (r) => <span className="font-medium text-ink">{r.hostname || r.hostId}</span> },
    { key: "component", title: t("vuln.remediationTasks.colComponent"), render: (r) => <span className="text-muted">{r.component || "—"}</span> },
    { key: "status", title: t("common.status"), render: (r) => statusTag(r.status) },
    { key: "verifyStatus", title: t("vuln.remediationTasks.colVerify"), render: (r) => verifyTag(r.verifyStatus) },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          {r.status === "pending" && (
            <Button variant="ghost" className="h-8 px-3" onClick={() => setConfirming(r)}>{t("vuln.remediationTasks.actionConfirm")}</Button>
          )}
          {(r.status === "pending" || r.status === "confirmed" || r.status === "running") && (
            <Button variant="ghost" className="h-8 px-3" onClick={() => setCancelling(r)}>{t("vuln.remediationTasks.actionCancel")}</Button>
          )}
          {r.status === "failed" && (
            <Button variant="ghost" className="h-8 px-3" onClick={() => setRetrying(r)}>{t("vuln.remediationTasks.actionRetry")}</Button>
          )}
          <Button variant="ghost" className="h-8 px-3" onClick={() => setDetailId(r.id)}>{t("common.details")}</Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-5 mb-5">
        <StatCard compact label={t("vuln.remediationTasks.statTotal")} value={stats?.total ?? 0} error={statsError} icon={ListChecks} tone="default" />
        <StatCard compact label={t("vuln.remediationTasks.statPending")} value={stats?.pending ?? 0} error={statsError} icon={Clock} tone="warning" />
        <StatCard compact label={t("vuln.remediationTasks.statRunning")} value={stats?.running ?? 0} error={statsError} icon={Loader} tone="default" />
        <StatCard compact label={t("vuln.remediationTasks.statSuccess")} value={stats?.success ?? 0} error={statsError} icon={CheckCircle} tone="success" />
        <StatCard compact label={t("vuln.remediationTasks.statFailed")} value={stats?.failed ?? 0} error={statsError} icon={XCircle} tone="danger" />
      </div>

      <div className="space-y-4">
        <FilterBar>
          <Select value={params.status} onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))} options={statusOptions} />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("vuln.remediationTasks.empty")}
            onRowClick={(r) => setDetailId(r.id)}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      <Drawer open={detailId != null} onClose={() => setDetailId(null)} title={t("vuln.remediationTasks.detailTitle")} width={560}>
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold font-mono text-ink">{detail.cveId}</h2>
              <div className="flex items-center gap-2">
                {statusTag(detail.status)}
                {verifyTag(detail.verifyStatus)}
              </div>
            </div>

            <div className="space-y-2">
              <Field label={t("common.host")} value={detail.hostname || detail.hostId} />
              <Field label="IP" value={<span className="tabular-nums">{detail.ip || "—"}</span>} />
              <Field label={t("vuln.remediationTasks.fieldComponent")} value={detail.component || "—"} />
              <Field label={t("vuln.remediationTasks.fieldFixedVersion")} value={<span className="font-mono">{detail.fixedVersion || "—"}</span>} />
              <Field label={t("vuln.remediationTasks.fieldExitCode")} value={<span className="tabular-nums">{detail.exitCode ?? "—"}</span>} />
              <Field label={t("vuln.remediationTasks.fieldFinishedAt")} value={<span className="tabular-nums">{detail.finishedAt || "—"}</span>} />
            </div>

            {detail.command && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("vuln.remediationTasks.fieldCommand")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                  {detail.command}
                </pre>
              </div>
            )}
            {detail.execOutput && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("vuln.remediationTasks.fieldExecOutput")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                  {detail.execOutput}
                </pre>
              </div>
            )}
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!confirming}
        title={t("vuln.remediationTasks.confirmTitle")}
        desc={confirming ? t("vuln.remediationTasks.confirmDesc", { cve: confirming.cveId, host: confirming.hostname || confirming.hostId }) : undefined}
        loading={confirmMutation.isPending}
        onConfirm={() => confirming && confirmMutation.mutate(confirming.id)}
        onCancel={() => setConfirming(null)}
      />
      <ConfirmDialog
        open={!!cancelling}
        title={t("vuln.remediationTasks.cancelTitle")}
        desc={cancelling ? t("vuln.remediationTasks.cancelDesc", { cve: cancelling.cveId }) : undefined}
        loading={cancelMutation.isPending}
        onConfirm={() => cancelling && cancelMutation.mutate(cancelling.id)}
        onCancel={() => setCancelling(null)}
      />
      <ConfirmDialog
        open={!!retrying}
        title={t("vuln.remediationTasks.retryTitle")}
        desc={retrying ? t("vuln.remediationTasks.retryDesc", { cve: retrying.cveId }) : undefined}
        loading={retryMutation.isPending}
        onConfirm={() => retrying && retryMutation.mutate(retrying.id)}
        onCancel={() => setRetrying(null)}
      />
    </>
  );
}
