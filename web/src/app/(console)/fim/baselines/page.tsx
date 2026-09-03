"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { fimApi } from "@/lib/api/fim";
import type { FimBaseline, FimBaselineEntry } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  status: string;
}

const buildStatusFilterOptions = (t: TFunction) => [
  { label: t("fim.baselines.allStatus"), value: "" },
  { label: t("fim.baselines.statusPending"), value: "pending" },
  { label: t("fim.baselines.statusApproved"), value: "approved" },
  { label: t("fim.baselines.statusOutdated"), value: "outdated" },
];

type StatusTone = "success" | "warning" | "neutral";
const STATUS_TONE: Record<string, StatusTone> = {
  pending: "warning",
  approved: "success",
  outdated: "neutral",
};

export default function FimBaselinesPage() {
  const { t } = useTranslation();
  const statusFilterOptions = buildStatusFilterOptions(t);
  const statusTag = (status: string) => {
    const tone = STATUS_TONE[status] ?? ("neutral" as StatusTone);
    return <StatusTag tone={tone}>{t(`fim.baselines.status${status.charAt(0).toUpperCase()}${status.slice(1)}`, status)}</StatusTag>;
  };
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, status: "" });

  const { data, isLoading } = useQuery({
    queryKey: ["fim-baselines", params],
    queryFn: () => fimApi.listBaselines(params),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["fim-baselines"] });

  // ---- detail ----
  const [detail, setDetail] = useState<FimBaseline | null>(null);
  const detailQuery = useQuery({
    queryKey: ["fim-baseline", detail?.id],
    queryFn: () => fimApi.getBaseline(detail!.id, { entry_page: 1, entry_page_size: 50 }),
    enabled: !!detail,
  });

  // ---- approve ----
  const [approving, setApproving] = useState<FimBaseline | null>(null);
  const approveMutation = useMutation({
    mutationFn: (id: number) => fimApi.approveBaseline(id),
    onSuccess: () => {
      invalidate();
      setApproving(null);
      toast.success(t("fim.baselines.approved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<FimBaseline>[] = [
    {
      key: "hostname",
      title: t("fim.baselines.colHost"),
      render: (r) => (
        <div>
          <div className="font-medium text-ink">{r.hostname}</div>
          <div className="text-xs text-faint">{r.host_id}</div>
        </div>
      ),
    },
    { key: "policy_id", title: t("fim.baselines.colPolicy"), render: (r) => <span className="text-muted">{r.policy_id}</span> },
    {
      key: "version",
      title: t("common.version"),
      render: (r) => <span className="font-mono text-ink">v{r.version}</span>,
    },
    { key: "status", title: t("common.status"), render: (r) => statusTag(r.status) },
    {
      key: "entry_count",
      title: t("fim.baselines.colEntryCount"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.entry_count}</span>,
    },
    { key: "approved_by", title: t("fim.baselines.colApprovedBy"), render: (r) => <span className="text-faint">{r.approved_by || "—"}</span> },
    {
      key: "approved_at",
      title: t("fim.baselines.colApprovedAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.approved_at || "—"}</span>,
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
            {t("fim.baselines.actionDetail")}
          </button>
          {r.status === "pending" && (
            <button
              type="button"
              className="text-sm text-primary transition-colors hover:opacity-80"
              onClick={(e) => {
                e.stopPropagation();
                setApproving(r);
              }}
            >
              {t("fim.baselines.actionApprove")}
            </button>
          )}
        </div>
      ),
    },
  ];

  const entryColumns: Column<FimBaselineEntry>[] = [
    { key: "file_path", title: t("fim.baselines.colFilePath"), render: (r) => <span className="font-mono text-ink">{r.file_path}</span> },
    {
      key: "file_size",
      title: t("fim.baselines.colSize"),
      align: "right",
      render: (r) => <span className="tabular-nums text-muted">{r.file_size}</span>,
    },
    { key: "file_mode", title: t("fim.baselines.colMode"), render: (r) => <span className="font-mono text-muted">{r.file_mode}</span> },
    {
      key: "owner",
      title: t("fim.baselines.colOwner"),
      render: (r) => <span className="tabular-nums text-muted">{`${r.uid}:${r.gid}`}</span>,
    },
    {
      key: "sha256",
      title: "SHA256",
      render: (r) => <span className="font-mono text-xs text-faint">{r.sha256.slice(0, 16)}…</span>,
    },
  ];

  const detailBaseline = detailQuery.data?.baseline ?? detail;

  return (
    <>
      <div className="space-y-4">
        <FilterBar>
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
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("fim.baselines.empty")}
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
        title={detail ? t("fim.baselines.detailTitleNamed", { host: detail.hostname }) : t("fim.baselines.detailTitle")}
        width={760}
      >
        {detailBaseline && (
          <div className="space-y-5">
            <div className="rounded-card border border-border bg-surface-muted/50 p-4">
              <div className="flex items-center gap-2">
                {statusTag(detailBaseline.status)}
                <span className="font-semibold text-ink">{detailBaseline.hostname}</span>
                <span className="font-mono text-sm text-muted">v{detailBaseline.version}</span>
              </div>
              <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                <Field label={t("fim.baselines.fieldHostId")} value={detailBaseline.host_id} />
                <Field label={t("fim.baselines.fieldPolicy")} value={detailBaseline.policy_id} />
                <Field label={t("fim.baselines.fieldTask")} value={detailBaseline.task_id} />
                <Field label={t("fim.baselines.fieldEntryCount")} value={String(detailBaseline.entry_count)} />
                <Field label={t("fim.baselines.fieldApprovedBy")} value={detailBaseline.approved_by || "—"} />
                <Field label={t("fim.baselines.fieldApprovedAt")} value={detailBaseline.approved_at || "—"} />
                <Field label={t("common.createdAt")} value={detailBaseline.created_at} />
              </dl>
            </div>

            <div>
              <h4 className="mb-2 text-[13px] font-semibold text-muted">{t("fim.baselines.entriesTitle")}</h4>
              {detailQuery.isLoading && <div className="text-sm text-muted">{t("fim.baselines.loading")}</div>}
              {detailQuery.isError && <div className="text-sm text-danger">{t("fim.baselines.loadError")}</div>}
              {detailQuery.data && (
                <DataTable
                  columns={entryColumns}
                  rows={detailQuery.data.entries ?? []}
                  rowKey={(r) => r.id}
                  emptyText={t("fim.baselines.emptyEntries")}
                />
              )}
            </div>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!approving}
        title={t("fim.baselines.approveTitle")}
        desc={approving ? t("fim.baselines.approveConfirmDesc", { host: approving.hostname, version: approving.version }) : undefined}
        danger={false}
        confirmText={t("fim.baselines.actionApprove")}
        loading={approveMutation.isPending}
        onConfirm={() => approving && approveMutation.mutate(approving.id)}
        onCancel={() => setApproving(null)}
      />
    </>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-faint">{label}</dt>
      <dd className="break-all text-ink">{value}</dd>
    </div>
  );
}
