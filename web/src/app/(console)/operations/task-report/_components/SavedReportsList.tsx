"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { reportsApi } from "@/lib/api/reports";
import type { GeneratedReportItem } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { toast } from "@/components/ui/toast";

function fmtDateTime(iso: string, locale?: string): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(locale ?? "zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

interface Props {
  type: string;
  onView: (id: number) => void;
}

export function SavedReportsList({ type, onView }: Props) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [deletingId, setDeletingId] = useState<number | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["saved-reports", type],
    queryFn: () => reportsApi.listGenerated(type),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => reportsApi.deleteGenerated(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["saved-reports", type] });
      setDeletingId(null);
      toast.success(t("operations.taskReport.savedReports.deleteSuccess"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<GeneratedReportItem>[] = [
    {
      key: "title",
      title: t("operations.taskReport.savedReports.colTitle"),
      render: (r) => <span className="text-ink">{r.title || "—"}</span>,
    },
    {
      key: "report_id",
      title: t("operations.taskReport.savedReports.colReportId"),
      render: (r) => (
        <span className="font-mono text-xs text-muted">{r.report_id || "—"}</span>
      ),
    },
    {
      key: "period",
      title: t("operations.taskReport.savedReports.colPeriod"),
      render: (r) => <span className="text-sm text-muted">{r.period || "—"}</span>,
    },
    {
      key: "created_at",
      title: t("operations.taskReport.savedReports.colCreatedAt"),
      render: (r) => (
        <span className="tabular-nums text-sm text-muted">
          {fmtDateTime(r.created_at, i18n.language)}
        </span>
      ),
    },
    {
      key: "actions",
      title: t("operations.taskReport.savedReports.colActions"),
      align: "right",
      width: "180px",
      render: (r) => (
        <div className="flex items-center justify-end gap-2">
          <Button
            variant="ghost"
            onClick={(e) => {
              e.stopPropagation();
              onView(r.id);
            }}
          >
            {t("operations.taskReport.savedReports.actionView")}
          </Button>
          <Button
            variant="danger"
            onClick={(e) => {
              e.stopPropagation();
              setDeletingId(r.id);
            }}
          >
            {t("operations.taskReport.savedReports.actionDelete")}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <Card>
        <DataTable
          columns={columns}
          rows={data?.items ?? []}
          rowKey={(r) => r.id}
          loading={isLoading}
          emptyText={t("operations.taskReport.savedReports.empty")}
        />
      </Card>

      <ConfirmDialog
        open={deletingId !== null}
        title={t("operations.taskReport.savedReports.deleteTitle")}
        desc={t("operations.taskReport.savedReports.deleteDesc")}
        danger
        loading={deleteMutation.isPending}
        onConfirm={() => {
          if (deletingId !== null) deleteMutation.mutate(deletingId);
        }}
        onCancel={() => setDeletingId(null)}
      />
    </>
  );
}
