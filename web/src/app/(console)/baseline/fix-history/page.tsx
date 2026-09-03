"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { baselineApi } from "@/lib/api/baseline";
import type { BaselineFixHistory } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  status: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

const buildStatusOptions = (t: TFunction) => [
  { label: t("common.allStatus"), value: "" },
  { label: t("baseline.fixHistory.statusPending"), value: "pending" },
  { label: t("baseline.fixHistory.statusRunning"), value: "running" },
  { label: t("baseline.fixHistory.statusCompleted"), value: "completed" },
  { label: t("baseline.fixHistory.statusFailed"), value: "failed" },
];

const buildStatusMeta = (t: TFunction): Record<BaselineFixHistory["status"], { tone: Tone; label: string }> => ({
  pending: { tone: "info", label: t("baseline.fixHistory.statusPending") },
  running: { tone: "info", label: t("baseline.fixHistory.statusRunning") },
  completed: { tone: "success", label: t("baseline.fixHistory.statusCompleted") },
  failed: { tone: "danger", label: t("baseline.fixHistory.statusFailed") },
});

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="text-ink">{value}</span>
    </div>
  );
}

export default function BaselineFixHistoryPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const statusOptions = buildStatusOptions(t);
  const statusMeta = buildStatusMeta(t);
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, status: "" });

  const { data, isLoading } = useQuery({
    queryKey: ["bl-fix-history", params],
    queryFn: () =>
      baselineApi.listFixHistory({
        page: params.page,
        page_size: params.page_size,
        status: params.status || undefined,
      }),
  });

  const [detail, setDetail] = useState<BaselineFixHistory | null>(null);
  const [cancelling, setCancelling] = useState<BaselineFixHistory | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["bl-fix-history"] });

  const cancelMutation = useMutation({
    mutationFn: (taskId: string) => baselineApi.cancelFixTask(taskId),
    onSuccess: () => {
      invalidate();
      setCancelling(null);
      setDetail(null);
      toast.success(t("baseline.fixHistory.cancelled"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const isCancelable = (t: BaselineFixHistory) => t.status === "running" || t.status === "pending";

  const columns: Column<BaselineFixHistory>[] = [
    { key: "task_id", title: t("baseline.fixHistory.colTaskId"), render: (r) => <span className="font-mono text-sm font-medium text-ink">{r.task_id}</span> },
    { key: "hosts", title: t("baseline.fixHistory.colHostCount"), render: (r) => <span className="tabular-nums">{r.host_ids?.length ?? 0}</span> },
    { key: "rules", title: t("baseline.fixHistory.colRuleCount"), render: (r) => <span className="tabular-nums">{r.rule_ids?.length ?? 0}</span> },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => <StatusTag tone={statusMeta[r.status].tone}>{statusMeta[r.status].label}</StatusTag>,
    },
    {
      key: "result",
      title: t("baseline.fixHistory.colResult"),
      render: (r) => (
        <span className="text-sm tabular-nums text-muted">
          {t("baseline.fixHistory.result", { success: r.success_count, failed: r.failed_count, total: r.total_count })}
        </span>
      ),
    },
    { key: "progress", title: t("baseline.fixHistory.colProgress"), render: (r) => <span className="tabular-nums">{r.progress}%</span> },
    { key: "created_by", title: t("baseline.fixHistory.colCreatedBy"), render: (r) => <span className="text-faint">{r.created_by || "—"}</span> },
    { key: "created_at", title: t("common.createdAt"), render: (r) => <span className="text-faint tabular-nums">{r.created_at}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <button
          type="button"
          className="text-sm text-muted transition-colors hover:text-ink"
          onClick={(e) => {
            e.stopPropagation();
            setDetail(r);
          }}
        >
          {t("common.details")}
        </button>
      ),
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <FilterBar>
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
            rowKey={(r) => r.task_id}
            loading={isLoading}
            emptyText={t("baseline.fixHistory.empty")}
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
        title={t("baseline.fixHistory.detailTitle")}
        width={560}
        footer={
          detail && isCancelable(detail) ? (
            <Button variant="danger" onClick={() => detail && setCancelling(detail)}>
              {t("baseline.fixHistory.cancelTask")}
            </Button>
          ) : undefined
        }
      >
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="font-mono text-lg font-bold text-ink">{detail.task_id}</h2>
              <StatusTag tone={statusMeta[detail.status].tone}>{statusMeta[detail.status].label}</StatusTag>
            </div>

            <div className="space-y-2">
              <Field label={t("baseline.fixHistory.fieldHostCount")} value={<span className="tabular-nums">{detail.host_ids?.length ?? 0}</span>} />
              <Field label={t("baseline.fixHistory.fieldRuleCount")} value={<span className="tabular-nums">{detail.rule_ids?.length ?? 0}</span>} />
              <Field label={t("baseline.fixHistory.fieldProgress")} value={<span className="tabular-nums">{detail.progress}%</span>} />
              <Field
                label={t("baseline.fixHistory.fieldResult")}
                value={
                  <span className="tabular-nums">
                    {t("baseline.fixHistory.result", { success: detail.success_count, failed: detail.failed_count, total: detail.total_count })}
                  </span>
                }
              />
              <Field label={t("baseline.fixHistory.fieldCreatedBy")} value={detail.created_by || "—"} />
              <Field label={t("common.createdAt")} value={<span className="tabular-nums">{detail.created_at}</span>} />
              <Field label={t("baseline.fixHistory.fieldCompletedAt")} value={<span className="tabular-nums">{detail.completed_at || "—"}</span>} />
            </div>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!cancelling}
        danger
        title={t("baseline.fixHistory.cancelTitle")}
        desc={cancelling ? t("baseline.fixHistory.cancelConfirmDesc", { taskId: cancelling.task_id }) : undefined}
        confirmText={t("baseline.fixHistory.cancelConfirm")}
        loading={cancelMutation.isPending}
        onConfirm={() => cancelling && cancelMutation.mutate(cancelling.task_id)}
        onCancel={() => setCancelling(null)}
      />
    </>
  );
}
