"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { vulnApi } from "@/lib/api/vuln";
import type { VulnDataSource } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { Switch } from "@/components/ui/Switch";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

const buildRegionLabel = (t: TFunction): Record<string, string> => ({
  cn: t("vuln.dataSources.regionCn"),
  global: t("vuln.dataSources.regionGlobal"),
});
const buildCategoryLabel = (t: TFunction): Record<string, string> => ({
  cn_official: t("vuln.dataSources.categoryCnOfficial"),
  os_advisory: t("vuln.dataSources.categoryOsAdvisory"),
  cve_metadata: t("vuln.dataSources.categoryCveMetadata"),
  exploit: t("vuln.dataSources.categoryExploit"),
});
const buildStatusLabel = (t: TFunction): Record<VulnDataSource["lastStatus"], string> => ({
  never: t("vuln.dataSources.statusNever"),
  running: t("vuln.dataSources.statusRunning"),
  success: t("vuln.dataSources.statusSuccess"),
  failed: t("vuln.dataSources.statusFailed"),
});
const statusTone = (s: VulnDataSource["lastStatus"]): "success" | "danger" | "warning" | "neutral" => {
  if (s === "success") return "success";
  if (s === "failed") return "danger";
  if (s === "running") return "warning";
  return "neutral";
};

interface SourceForm {
  enabled: boolean;
  baseUrl: string;
}

export default function DataSourcesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const REGION_LABEL = buildRegionLabel(t);
  const CATEGORY_LABEL = buildCategoryLabel(t);
  const STATUS_LABEL = buildStatusLabel(t);
  const { data, isLoading } = useQuery({
    queryKey: ["vuln-sources"],
    queryFn: () => vulnApi.listDataSources(),
  });

  const [editing, setEditing] = useState<VulnDataSource | null>(null);
  const [form, setForm] = useState<SourceForm>({ enabled: true, baseUrl: "" });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["vuln-sources"] });

  const openEdit = (s: VulnDataSource) => {
    setEditing(s);
    setForm({ enabled: s.enabled, baseUrl: s.baseUrl });
  };

  const saveMutation = useMutation({
    mutationFn: () => vulnApi.updateDataSource(editing!.id, { enabled: form.enabled, baseUrl: form.baseUrl }),
    onSuccess: () => {
      invalidate();
      setEditing(null);
      toast.success(t("vuln.dataSources.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => vulnApi.updateDataSource(id, { enabled }),
    onSuccess: () => {
      invalidate();
      toast.success(t("vuln.dataSources.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const testMutation = useMutation({
    mutationFn: (id: number) => vulnApi.testDataSource(id),
    onSuccess: (res) => {
      if (res.reachable) toast.success(res.http_status ? t("vuln.dataSources.reachableHttp", { status: res.http_status }) : t("vuln.dataSources.reachable"));
      else toast.error(res.error ? t("vuln.dataSources.unreachableErr", { error: res.error }) : t("vuln.dataSources.unreachable"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const syncMutation = useMutation({
    mutationFn: (id: number) => vulnApi.syncDataSource(id),
    // 后端 SuccessMessage 只回 {code,message}(无 data),unwrap 得 undefined;不读 res.message 避免崩
    onSuccess: () => {
      invalidate();
      toast.success(t("vuln.dataSources.syncTriggered"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<VulnDataSource>[] = [
    {
      key: "displayName",
      title: t("common.name"),
      render: (r) => (
        <div>
          <div className="font-medium text-ink">{r.displayName}</div>
          <div className="text-xs text-faint">{r.name}</div>
        </div>
      ),
    },
    { key: "region", title: t("vuln.dataSources.colRegion"), render: (r) => <span className="text-muted">{REGION_LABEL[r.region] ?? r.region}</span> },
    {
      key: "category",
      title: t("common.category"),
      render: (r) => <StatusTag tone="neutral">{CATEGORY_LABEL[r.category] ?? r.category}</StatusTag>,
    },
    {
      key: "baseUrl",
      title: t("vuln.dataSources.colAddress"),
      render: (r) => <span className="block max-w-[220px] truncate font-mono text-xs text-muted">{r.baseUrl}</span>,
    },
    {
      key: "enabled",
      title: t("common.enabled"),
      render: (r) => (
        <Switch
          checked={r.enabled}
          disabled={toggleMutation.isPending}
          onChange={(b) => toggleMutation.mutate({ id: r.id, enabled: b })}
        />
      ),
    },
    {
      key: "lastStatus",
      title: t("vuln.dataSources.colLastStatus"),
      render: (r) => <StatusTag tone={statusTone(r.lastStatus)}>{STATUS_LABEL[r.lastStatus] ?? r.lastStatus}</StatusTag>,
    },
    { key: "lastCount", title: t("vuln.dataSources.colLastCount"), render: (r) => <span className="tabular-nums text-ink">{r.lastCount}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink disabled:opacity-50"
            disabled={testMutation.isPending}
            onClick={(e) => {
              e.stopPropagation();
              testMutation.mutate(r.id);
            }}
          >
            {t("vuln.dataSources.actionTest")}
          </button>
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink disabled:opacity-50"
            disabled={syncMutation.isPending}
            onClick={(e) => {
              e.stopPropagation();
              syncMutation.mutate(r.id);
            }}
          >
            {t("vuln.dataSources.actionSync")}
          </button>
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={(e) => {
              e.stopPropagation();
              openEdit(r);
            }}
          >
            {t("common.edit")}
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <Card>
        <DataTable
          columns={columns}
          rows={data ?? []}
          rowKey={(r) => r.id}
          loading={isLoading}
          emptyText={t("vuln.dataSources.empty")}
        />
      </Card>

      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title={editing ? t("vuln.dataSources.editTitleNamed", { name: editing.displayName }) : t("vuln.dataSources.editTitle")}
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
          <FormField label={t("common.enabled")}>
            <Switch checked={form.enabled} onChange={(b) => setForm((f) => ({ ...f, enabled: b }))} />
          </FormField>
          <FormField label={t("vuln.dataSources.fieldAddress")}>
            <Input value={form.baseUrl} onChange={(e) => setForm((f) => ({ ...f, baseUrl: e.target.value }))} />
          </FormField>
        </div>
      </Modal>
    </>
  );
}
