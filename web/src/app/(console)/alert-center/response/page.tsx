"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { EmptyState } from "@/components/ui/EmptyState";
import { Modal } from "@/components/ui/Modal";
import { toast } from "@/components/ui/toast";
import { responseActionsApi } from "@/lib/api/response-actions";
import type { ResponseAction, ResponseStatus } from "@/lib/api/types";
import { ShieldAlert } from "lucide-react";

/** 各状态的展示样式。失败与"未执行"必须一眼能分开。 */
const statusTone: Record<ResponseStatus, string> = {
  pending: "bg-warning/10 text-warning",
  approved: "bg-primary/10 text-primary",
  rejected: "bg-muted/10 text-muted",
  executed: "bg-success/10 text-success",
  failed: "bg-danger/10 text-danger",
  rolled_back: "bg-muted/10 text-muted",
};

/**
 * 处置审批页。
 *
 * 隔离主机会切断业务流量，所以处置改成了"申请 → 他人审批 → 执行"。
 * 没有这个页面，值班就得用 curl 批准隔离——闸门建了也用不起来。
 */
export default function ResponseActionsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string>("pending");
  const [rejecting, setRejecting] = useState<ResponseAction | null>(null);
  const [rejectReason, setRejectReason] = useState("");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["response-actions", statusFilter],
    queryFn: () => responseActionsApi.list({ status: statusFilter || undefined }),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["response-actions"] });
  const onError = (e: Error) => toast.error(e.message);

  const approve = useMutation({
    mutationFn: (id: number) => responseActionsApi.approve(id),
    onSuccess: () => {
      invalidate();
      toast.success(t("alerts.response.approved"));
    },
    onError,
  });
  const reject = useMutation({
    mutationFn: (v: { id: number; reason: string }) => responseActionsApi.reject(v.id, v.reason),
    onSuccess: () => {
      invalidate();
      setRejecting(null);
      setRejectReason("");
      toast.success(t("alerts.response.rejected"));
    },
    onError,
  });
  const execute = useMutation({
    mutationFn: (id: number) => responseActionsApi.execute(id),
    onSuccess: () => {
      invalidate();
      toast.success(t("alerts.response.executed"));
    },
    onError,
  });
  const rollback = useMutation({
    mutationFn: (id: number) => responseActionsApi.rollback(id),
    onSuccess: () => {
      invalidate();
      toast.success(t("alerts.response.rolledBack"));
    },
    onError,
  });

  const columns: Column<ResponseAction>[] = [
    {
      key: "action",
      title: t("alerts.response.colAction"),
      render: (r) => (
        <div>
          <div className="font-medium text-ink">
            {t(`alerts.response.action_${r.action}` as never, { defaultValue: r.action }) as string}
          </div>
          <div className="font-mono text-xs text-faint">{r.target}</div>
        </div>
      ),
    },
    {
      key: "reason",
      title: t("alerts.response.colReason"),
      render: (r) => <span className="text-sm text-muted">{r.reason}</span>,
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => (
        <div>
          <span className={`rounded-control px-1.5 py-0.5 text-xs ${statusTone[r.status]}`}>
            {t(`alerts.response.status_${r.status}` as never, { defaultValue: r.status }) as string}
          </span>
          {/* 失败原因必须展示：否则只知道没生效，不知道为什么。 */}
          {r.status === "failed" && r.error_msg && (
            <div className="mt-1 text-xs text-danger">{r.error_msg}</div>
          )}
          {r.status === "rejected" && r.reject_reason && (
            <div className="mt-1 text-xs text-muted">{r.reject_reason}</div>
          )}
        </div>
      ),
    },
    {
      key: "requested_by",
      title: t("alerts.response.colRequester"),
      render: (r) => (
        <div className="text-sm">
          <div className="text-ink">{r.requested_by}</div>
          {/* 直接渲染后端返回的本地时间串，与全站一致。*/}
          <div className="text-xs text-faint tabular-nums">{r.requested_at}</div>
        </div>
      ),
    },
    {
      key: "approved_by",
      title: t("alerts.response.colApprover"),
      render: (r) => <span className="text-sm text-muted">{r.approved_by || "—"}</span>,
    },
    {
      key: "ops",
      title: t("common.actions"),
      render: (r) => (
        <div className="flex gap-1.5">
          {r.status === "pending" && (
            <>
              {/* 申请人不能审批自己的申请，后端会拒绝并给出提示。 */}
              <Button onClick={() => approve.mutate(r.id)} disabled={approve.isPending}>
                {t("alerts.response.approve")}
              </Button>
              <Button variant="ghost" onClick={() => setRejecting(r)}>
                {t("alerts.response.reject")}
              </Button>
            </>
          )}
          {r.status === "approved" && (
            <Button onClick={() => execute.mutate(r.id)} disabled={execute.isPending}>
              {t("alerts.response.execute")}
            </Button>
          )}
          {r.status === "executed" && (
            <Button variant="ghost" onClick={() => rollback.mutate(r.id)} disabled={rollback.isPending}>
              {t("alerts.response.rollback")}
            </Button>
          )}
        </div>
      ),
    },
  ];

  const filters: { key: string; label: string }[] = [
    { key: "pending", label: t("alerts.response.status_pending") },
    { key: "approved", label: t("alerts.response.status_approved") },
    { key: "executed", label: t("alerts.response.status_executed") },
    { key: "", label: t("common.all") },
  ];

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex items-start gap-2.5">
          <ShieldAlert size={18} className="mt-0.5 shrink-0 text-warning" />
          <p className="text-sm text-muted">{t("alerts.response.intro")}</p>
        </div>
      </Card>

      <div className="flex gap-2">
        {filters.map((f) => (
          <button
            key={f.key || "all"}
            type="button"
            onClick={() => setStatusFilter(f.key)}
            className={`rounded-control px-2.5 py-1 text-sm transition-colors ${
              statusFilter === f.key ? "bg-primary/10 text-primary" : "text-muted hover:text-ink"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {!isLoading && !isError && (data?.items?.length ?? 0) === 0 ? (
        <EmptyState title={t("alerts.response.empty")} />
      ) : (
        <DataTable
          columns={columns}
          rows={data?.items ?? []}
          rowKey={(r) => r.id}
          loading={isLoading}
          emptyText={t("alerts.response.empty")}
        />
      )}

      <Modal
        open={!!rejecting}
        title={t("alerts.response.rejectTitle")}
        onClose={() => {
          setRejecting(null);
          setRejectReason("");
        }}
      >
        <div className="space-y-3">
          <div className="text-sm text-muted">{rejecting?.reason}</div>
          <textarea
            className="w-full rounded-control border border-line bg-surface p-2.5 text-sm text-ink outline-none focus:border-primary"
            rows={3}
            value={rejectReason}
            placeholder={t("alerts.response.rejectPlaceholder")}
            onChange={(e) => setRejectReason(e.target.value)}
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setRejecting(null)}>
              {t("common.cancel")}
            </Button>
            {/* 驳回必须写原因，否则申请人不知道该改什么。 */}
            <Button
              disabled={rejectReason.trim() === "" || reject.isPending}
              onClick={() =>
                rejecting && reject.mutate({ id: rejecting.id, reason: rejectReason.trim() })
              }
            >
              {t("alerts.response.reject")}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
