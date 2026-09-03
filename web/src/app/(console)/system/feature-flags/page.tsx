"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { systemApi } from "@/lib/api/system";
import type { FeatureFlag } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Modal } from "@/components/ui/Modal";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

export default function FeatureFlagsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["sys-feature-flags"],
    queryFn: () => systemApi.listFeatureFlags(),
  });

  const [editing, setEditing] = useState<FeatureFlag | null>(null);
  const [value, setValue] = useState("");

  const openEdit = (r: FeatureFlag) => {
    setEditing(r);
    setValue(r.value);
  };

  const saveMutation = useMutation({
    mutationFn: () => systemApi.updateFeatureFlag(editing!.key, value),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sys-feature-flags"] });
      setEditing(null);
      toast.success(t("system.featureFlags.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<FeatureFlag>[] = [
    { key: "key", title: t("system.featureFlags.colKey"), render: (r) => <span className="font-mono text-sm text-ink">{r.key}</span> },
    { key: "description", title: t("system.featureFlags.colDescription"), render: (r) => <span className="text-muted">{r.description || "—"}</span> },
    {
      key: "value",
      title: t("system.featureFlags.colValue"),
      render: (r) => <StatusTag tone={r.value === r.default_value ? "neutral" : "info"}>{r.value}</StatusTag>,
    },
    { key: "default_value", title: t("system.featureFlags.colDefault"), render: (r) => <span className="text-faint">{r.default_value}</span> },
    { key: "updated_by", title: t("system.featureFlags.colUpdatedBy"), render: (r) => <span className="text-faint">{r.updated_by || "—"}</span> },
    { key: "updated_at", title: t("system.featureFlags.colUpdatedAt"), render: (r) => <span className="text-faint tabular-nums">{r.updated_at}</span> },
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
          emptyText={t("system.featureFlags.empty")}
        />
      </Card>

      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title={t("system.featureFlags.editTitle")}
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
          <FormField label={t("system.featureFlags.colKey")}>
            <p className="font-mono text-sm text-ink">{editing?.key}</p>
          </FormField>
          <FormField label={t("system.featureFlags.colDescription")}>
            <p className="text-sm text-muted">{editing?.description || "—"}</p>
          </FormField>
          <FormField label={t("system.featureFlags.fieldValue")} required>
            <Input value={value} onChange={(e) => setValue(e.target.value)} />
            <p className="mt-1 text-xs text-faint">{t("system.featureFlags.defaultHint", { value: editing?.default_value })}</p>
          </FormField>
        </div>
      </Modal>
    </>
  );
}
