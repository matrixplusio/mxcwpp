"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { baselineApi } from "@/lib/api/baseline";
import type { BaselineTask } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

type StatusTone = "success" | "warning" | "danger" | "info" | "neutral";

const buildStatusMeta = (t: TFunction): Record<BaselineTask["status"], { label: string; tone: StatusTone }> => ({
  created: { label: t("baseline.tasks.statusCreated"), tone: "info" },
  pending: { label: t("baseline.tasks.statusPending"), tone: "info" },
  running: { label: t("baseline.tasks.statusRunning"), tone: "info" },
  completed: { label: t("baseline.tasks.statusCompleted"), tone: "success" },
  failed: { label: t("baseline.tasks.statusFailed"), tone: "danger" },
  cancelled: { label: t("baseline.tasks.statusCancelled"), tone: "neutral" },
});

const buildStatusOptions = (t: TFunction) => [
  { label: t("common.allStatus"), value: "" },
  { label: t("baseline.tasks.statusCreated"), value: "created" },
  { label: t("baseline.tasks.statusPending"), value: "pending" },
  { label: t("baseline.tasks.statusRunning"), value: "running" },
  { label: t("baseline.tasks.statusCompleted"), value: "completed" },
  { label: t("baseline.tasks.statusFailed"), value: "failed" },
  { label: t("baseline.tasks.statusCancelled"), value: "cancelled" },
];

interface ListParams {
  page: number;
  page_size: number;
  status: string;
}

export default function BaselineTasksPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const queryClient = useQueryClient();
  const openDetail = (taskId: string) => router.push(`/baseline/tasks/detail?id=${encodeURIComponent(taskId)}`);
  const statusMeta = buildStatusMeta(t);
  const statusOptions = buildStatusOptions(t);
  const getStatusMeta = (status: BaselineTask["status"]) =>
    statusMeta[status] ?? { label: status, tone: "neutral" as const };
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, status: "" });

  const { data, isLoading, isError } = useQuery({
    queryKey: ["bl-tasks", params],
    queryFn: () =>
      baselineApi.listTasks({
        page: params.page,
        page_size: params.page_size,
        status: params.status || undefined,
      }),
  });

  const [cancelling, setCancelling] = useState<BaselineTask | null>(null);

  const cancelMutation = useMutation({
    mutationFn: (taskId: string) => baselineApi.cancelTask(taskId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bl-tasks"] });
      setCancelling(null);
      toast.success(t("baseline.tasks.cancelled"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const canCancel = (t: BaselineTask) => t.status === "running" || t.status === "pending";

  const columns: Column<BaselineTask>[] = [
    {
      key: "name",
      title: t("baseline.tasks.colName"),
      render: (r) => (
        <div>
          <div className="font-medium text-ink">{r.name || "—"}</div>
          <div className="text-xs text-faint">{r.task_id}</div>
        </div>
      ),
    },
    {
      key: "type",
      title: t("common.type"),
      render: (r) => <StatusTag tone="neutral">{r.type || "—"}</StatusTag>,
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => {
        const meta = getStatusMeta(r.status);
        return <StatusTag tone={meta.tone}>{meta.label}</StatusTag>;
      },
    },
    {
      key: "progress",
      title: t("baseline.tasks.colProgress"),
      align: "right",
      render: (r) => (
        <span className="tabular-nums text-muted">
          {r.completed_host_count ?? 0}/{r.matched_host_count ?? 0}
        </span>
      ),
    },
    {
      key: "created_at",
      title: t("common.createdAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.created_at}</span>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-3">
          {canCancel(r) && (
            <button
              type="button"
              className="text-sm text-danger transition-colors hover:opacity-80"
              onClick={(e) => {
                e.stopPropagation();
                setCancelling(r);
              }}
            >
              {t("baseline.tasks.actionCancel")}
            </button>
          )}
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={(e) => {
              e.stopPropagation();
              openDetail(r.task_id);
            }}
          >
            {t("common.details")}
          </button>
        </div>
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
          {isError ? (
            <div className="p-6 text-sm text-danger">{t("baseline.loadError")}</div>
          ) : (
            <>
              <DataTable
                columns={columns}
                rows={data?.items ?? []}
                rowKey={(r) => r.task_id}
                loading={isLoading}
                emptyText={t("baseline.tasks.empty")}
                onRowClick={(r) => openDetail(r.task_id)}
              />
              <Pagination
                page={params.page}
                pageSize={params.page_size}
                total={data?.total ?? 0}
                onChange={(page) => setParams((p) => ({ ...p, page }))}
              />
            </>
          )}
        </Card>
      </div>

      <ConfirmDialog
        open={!!cancelling}
        title={t("baseline.tasks.cancelTitle")}
        desc={cancelling ? t("baseline.tasks.cancelConfirmDesc", { name: cancelling.name || cancelling.task_id }) : undefined}
        confirmText={t("baseline.tasks.cancelConfirm")}
        loading={cancelMutation.isPending}
        onConfirm={() => cancelling && cancelMutation.mutate(cancelling.task_id)}
        onCancel={() => setCancelling(null)}
      />
    </>
  );
}
