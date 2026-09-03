"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { fimApi } from "@/lib/api/fim";
import type { FimTask, FimTaskHostStatus } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { Modal } from "@/components/ui/Modal";
import { FormField } from "@/components/ui/FormField";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  status: string;
}

const buildStatusFilterOptions = (t: TFunction) => [
  { label: t("fim.tasks.allStatus"), value: "" },
  { label: t("fim.tasks.statusPending"), value: "pending" },
  { label: t("fim.tasks.statusRunning"), value: "running" },
  { label: t("fim.tasks.statusCompleted"), value: "completed" },
  { label: t("fim.tasks.statusFailed"), value: "failed" },
];

type StatusTone = "success" | "danger" | "info";
const STATUS_TONE: Record<string, StatusTone> = {
  pending: "info",
  running: "info",
  completed: "success",
  failed: "danger",
};

const HOST_STATUS_TONE: Record<string, "success" | "danger" | "info" | "neutral"> = {
  dispatched: "info",
  completed: "success",
  timeout: "danger",
  failed: "danger",
};

export default function FimTasksPage() {
  const { t } = useTranslation();
  const statusFilterOptions = buildStatusFilterOptions(t);
  const statusTag = (status: string) => {
    const tone = STATUS_TONE[status] ?? ("info" as StatusTone);
    return <StatusTag tone={tone}>{t(`fim.tasks.status${status.charAt(0).toUpperCase()}${status.slice(1)}`, status)}</StatusTag>;
  };
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, status: "" });

  const { data, isLoading } = useQuery({
    queryKey: ["fim-tasks", params],
    queryFn: () => fimApi.listTasks(params),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["fim-tasks"] });

  // ---- detail ----
  const [detail, setDetail] = useState<FimTask | null>(null);
  const detailQuery = useQuery({
    queryKey: ["fim-task", detail?.task_id],
    queryFn: () => fimApi.getTask(detail!.task_id),
    enabled: !!detail,
  });

  // ---- create task ----
  const [createOpen, setCreateOpen] = useState(false);
  const [policyId, setPolicyId] = useState("");
  const policiesQuery = useQuery({
    queryKey: ["fim-policies", { page: 1, page_size: 100, name: "", enabled: "" }],
    queryFn: () => fimApi.listPolicies({ page: 1, page_size: 100 }),
    enabled: createOpen,
  });
  const policyOptions = (policiesQuery.data?.items ?? []).map((p) => ({ label: p.name, value: p.policy_id }));

  const createMutation = useMutation({
    mutationFn: () => fimApi.createTask({ policy_id: policyId }),
    onSuccess: () => {
      invalidate();
      setCreateOpen(false);
      toast.success(t("fim.tasks.created"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // ---- run task ----
  const runMutation = useMutation({
    mutationFn: (taskId: string) => fimApi.runTask(taskId),
    onSuccess: () => {
      invalidate();
      toast.success(t("fim.tasks.runTriggered"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<FimTask>[] = [
    {
      key: "task_id",
      title: t("fim.tasks.colTaskId"),
      render: (r) => <span className="font-mono font-medium text-ink">{r.task_id}</span>,
    },
    { key: "policy_id", title: t("fim.tasks.colPolicy"), render: (r) => <span className="text-faint">{r.policy_id}</span> },
    { key: "status", title: t("common.status"), render: (r) => statusTag(r.status) },
    {
      key: "progress",
      title: t("fim.tasks.colProgress"),
      render: (r) => (
        <span className="tabular-nums text-muted">{`${r.completed_host_count}/${r.dispatched_host_count}`}</span>
      ),
    },
    {
      key: "total_events",
      title: t("fim.tasks.colEventCount"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.total_events}</span>,
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
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={(e) => {
              e.stopPropagation();
              setDetail(r);
            }}
          >
            {t("fim.tasks.actionDetail")}
          </button>
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink disabled:opacity-50"
            disabled={runMutation.isPending}
            onClick={(e) => {
              e.stopPropagation();
              runMutation.mutate(r.task_id);
            }}
          >
            {t("fim.tasks.actionRun")}
          </button>
        </div>
      ),
    },
  ];

  const hostColumns: Column<FimTaskHostStatus>[] = [
    { key: "hostname", title: t("fim.tasks.colHost"), render: (r) => <span className="font-medium text-ink">{r.hostname}</span> },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => {
        const tone = HOST_STATUS_TONE[r.status] ?? ("neutral" as const);
        return <StatusTag tone={tone}>{t(`fim.tasks.host${r.status.charAt(0).toUpperCase()}${r.status.slice(1)}`, r.status)}</StatusTag>;
      },
    },
    {
      key: "total_entries",
      title: t("fim.tasks.colEntries"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.total_entries}</span>,
    },
    {
      key: "changes",
      title: t("fim.tasks.colChanges"),
      align: "right",
      render: (r) => (
        <span className="tabular-nums text-muted">{`${r.added_count}/${r.removed_count}/${r.changed_count}`}</span>
      ),
    },
    {
      key: "run_time_sec",
      title: t("fim.tasks.colRunTime"),
      align: "right",
      render: (r) => <span className="tabular-nums text-muted">{r.run_time_sec}</span>,
    },
  ];

  const detailTask = detailQuery.data?.task ?? detail;

  return (
    <>
      <div className="space-y-4">
        <FilterBar extra={<Button onClick={() => setCreateOpen(true)}>{t("fim.tasks.create")}</Button>}>
          <Select
            value={params.status}
            onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))}
            options={statusFilterOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.task_id}
            loading={isLoading}
            emptyText={t("fim.tasks.empty")}
            onRowClick={(r) => setDetail(r)}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      {/* 详情 Drawer */}
      <Drawer
        open={!!detail}
        onClose={() => setDetail(null)}
        title={detail ? t("fim.tasks.detailTitleNamed", { id: detail.task_id }) : t("fim.tasks.detailTitle")}
        width={720}
      >
        {detailTask && (
          <div className="space-y-5">
            <div className="rounded-card border border-border bg-surface-muted/50 p-4">
              <div className="flex items-center gap-2">
                {statusTag(detailTask.status)}
                <span className="font-mono font-semibold text-ink">{detailTask.task_id}</span>
              </div>
              <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                <Field label={t("fim.tasks.fieldPolicy")} value={detailTask.policy_id} />
                <Field label={t("fim.tasks.fieldTargetType")} value={detailTask.target_type} />
                <Field
                  label={t("fim.tasks.fieldProgress")}
                  value={`${detailTask.completed_host_count}/${detailTask.dispatched_host_count}`}
                />
                <Field label={t("fim.tasks.fieldEventCount")} value={String(detailTask.total_events)} />
                <Field label={t("common.createdAt")} value={detailTask.created_at} />
                <Field label={t("fim.tasks.fieldExecutedAt")} value={detailTask.executed_at || "—"} />
                <Field label={t("fim.tasks.fieldCompletedAt")} value={detailTask.completed_at || "—"} />
              </dl>
            </div>

            <div>
              <h4 className="mb-2 text-[13px] font-semibold text-muted">{t("fim.tasks.hostStatusTitle")}</h4>
              {detailQuery.isLoading && <div className="text-sm text-muted">{t("fim.tasks.loading")}</div>}
              {detailQuery.isError && <div className="text-sm text-danger">{t("fim.tasks.loadError")}</div>}
              {detailQuery.data && (
                <DataTable
                  columns={hostColumns}
                  rows={detailQuery.data.host_statuses ?? []}
                  rowKey={(r) => r.id}
                  emptyText={t("fim.tasks.emptyHosts")}
                />
              )}
            </div>
          </div>
        )}
      </Drawer>

      {/* 新建任务 */}
      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={t("fim.tasks.create")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => createMutation.mutate()} disabled={!policyId || createMutation.isPending}>
              {createMutation.isPending ? t("fim.tasks.creating") : t("common.create")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("fim.tasks.fieldPolicy")} required>
            <Select
              value={policyId}
              onChange={setPolicyId}
              options={policyOptions}
              placeholder={t("fim.tasks.selectPolicy")}
              className="w-full"
            />
          </FormField>
        </div>
      </Modal>
    </>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-faint">{label}</dt>
      <dd className="text-ink">{value}</dd>
    </div>
  );
}
