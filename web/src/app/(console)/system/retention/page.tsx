"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { systemApi } from "@/lib/api/system";
import type { RetentionPolicy } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Modal } from "@/components/ui/Modal";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

export default function RetentionPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["sys-retention"],
    queryFn: () => systemApi.listRetention(),
  });

  const [editing, setEditing] = useState<RetentionPolicy | null>(null);
  const [days, setDays] = useState("");

  const openEdit = (r: RetentionPolicy) => {
    setEditing(r);
    setDays(String(r.retention_days));
  };

  const saveMutation = useMutation({
    mutationFn: () => systemApi.updateRetention(editing!.ch_table, Number(days)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sys-retention"] });
      setEditing(null);
      toast.success(t("system.retention.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<RetentionPolicy>[] = [
    { key: "display_name", title: t("system.retention.colPolicy"), render: (r) => <span className="font-medium text-ink">{r.display_name}</span> },
    { key: "description", title: t("system.retention.colDescription"), render: (r) => <span className="text-muted">{r.description || "—"}</span> },
    {
      key: "retention_days",
      title: t("system.retention.colRetentionDays"),
      render: (r) => <StatusTag tone="info">{t("system.retention.days", { n: r.retention_days })}</StatusTag>,
    },
    { key: "updated_by", title: t("system.retention.colUpdatedBy"), render: (r) => <span className="text-faint">{r.updated_by || "—"}</span> },
    { key: "updated_at", title: t("system.retention.colUpdatedAt"), render: (r) => <span className="text-faint tabular-nums">{r.updated_at}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <Button variant="ghost" className="h-8 px-3" onClick={() => openEdit(r)}>
          {t("common.edit")}
        </Button>
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
          emptyText={t("system.retention.empty")}
        />
      </Card>

      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title={t("system.retention.editTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditing(null)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
              {saveMutation.isPending ? t("common.saving") : t("common.save")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("system.retention.colPolicy")}>
            <p className="text-sm text-ink">{editing?.display_name}</p>
          </FormField>
          <FormField label={t("system.retention.fieldRetentionDays")} required>
            <Input type="number" value={days} onChange={(e) => setDays(e.target.value)} />
          </FormField>
        </div>
      </Modal>
    </>
  );
}
