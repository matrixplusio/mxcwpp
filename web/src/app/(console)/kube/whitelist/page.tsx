"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { kubeApi } from "@/lib/api/kube";
import type { KubeWhitelist } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  [k: string]: unknown;
}

interface WhitelistForm {
  name: string;
  clusterId: string;
  alarmTypes: string;
  namespace: string;
  podPattern: string;
}

const emptyForm: WhitelistForm = { name: "", clusterId: "", alarmTypes: "", namespace: "", podPattern: "" };

const buildStatusMeta = (t: TFunction): Record<string, { tone: "success" | "neutral"; label: string }> => ({
  enabled: { tone: "success", label: t("kube.whitelist.statusEnabled") },
  disabled: { tone: "neutral", label: t("kube.whitelist.statusDisabled") },
});

export default function KubeWhitelistPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20 });

  const statusMeta = buildStatusMeta(t);
  const statusTag = (s: string) => statusMeta[s] ?? { tone: "neutral" as const, label: s };

  const { data, isLoading } = useQuery({
    queryKey: ["kube-whitelist", params],
    queryFn: () => kubeApi.listWhitelist(params),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<KubeWhitelist | null>(null);
  const [form, setForm] = useState<WhitelistForm>(emptyForm);
  const [deleting, setDeleting] = useState<KubeWhitelist | null>(null);

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (w: KubeWhitelist) => {
    setEditing(w);
    setForm({
      name: w.name,
      clusterId: w.clusterId,
      alarmTypes: (w.alarmTypes ?? []).join(", "),
      namespace: w.namespace,
      podPattern: w.podPattern,
    });
    setDrawerOpen(true);
  };

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["kube-whitelist"] });

  const saveMutation = useMutation({
    mutationFn: () => {
      const body: Partial<KubeWhitelist> = {
        name: form.name,
        clusterId: form.clusterId,
        alarmTypes: form.alarmTypes
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        namespace: form.namespace,
        podPattern: form.podPattern,
      };
      return editing ? kubeApi.updateWhitelist(editing.id, body) : kubeApi.createWhitelist(body);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("kube.whitelist.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => kubeApi.deleteWhitelist(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("kube.whitelist.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<KubeWhitelist>[] = [
    { key: "name", title: t("kube.whitelist.colName"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    { key: "clusterName", title: t("kube.whitelist.colCluster"), render: (r) => r.clusterName || "—" },
    {
      key: "alarmTypes",
      title: t("kube.whitelist.colAlarmTypes"),
      render: (r) => <span className="text-muted">{(r.alarmTypes ?? []).length ? (r.alarmTypes ?? []).join(", ") : "—"}</span>,
    },
    { key: "namespace", title: t("kube.common.colNamespace"), render: (r) => <span className="font-mono text-sm text-muted">{r.namespace || "—"}</span> },
    { key: "podPattern", title: t("kube.whitelist.colPodPattern"), render: (r) => <span className="font-mono text-sm text-muted">{r.podPattern || "—"}</span> },
    { key: "hitCount", title: t("kube.whitelist.colHitCount"), render: (r) => <span className="tabular-nums">{r.hitCount}</span> },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => <StatusTag tone={statusTag(r.status).tone}>{statusTag(r.status).label}</StatusTag>,
    },
    {
      key: "createdAt",
      title: t("kube.whitelist.colCreatedAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.createdAt}</span>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2">
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
          <button
            type="button"
            className="text-sm text-danger transition-colors hover:opacity-80"
            onClick={(e) => {
              e.stopPropagation();
              setDeleting(r);
            }}
          >
            {t("common.delete")}
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <FilterBar extra={<Button onClick={openCreate}>{t("kube.whitelist.create")}</Button>}>
          <span className="text-sm text-muted">{t("kube.whitelist.subtitle")}</span>
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("kube.whitelist.empty")}
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
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={editing ? t("kube.whitelist.editTitle") : t("kube.whitelist.createTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setDrawerOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
              {saveMutation.isPending ? t("common.saving") : t("common.save")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("kube.whitelist.fieldName")} required>
            <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <FormField label={t("kube.whitelist.fieldCluster")}>
            <Input value={form.clusterId} onChange={(e) => setForm((f) => ({ ...f, clusterId: e.target.value }))} placeholder={t("kube.whitelist.fieldClusterPlaceholder")} />
          </FormField>
          <FormField label={t("kube.whitelist.fieldAlarmTypes")}>
            <Input
              value={form.alarmTypes}
              onChange={(e) => setForm((f) => ({ ...f, alarmTypes: e.target.value }))}
              placeholder={t("kube.whitelist.fieldAlarmTypesPlaceholder")}
            />
          </FormField>
          <FormField label={t("kube.whitelist.fieldNamespace")}>
            <Input value={form.namespace} onChange={(e) => setForm((f) => ({ ...f, namespace: e.target.value }))} />
          </FormField>
          <FormField label={t("kube.whitelist.fieldPodPattern")}>
            <Input value={form.podPattern} onChange={(e) => setForm((f) => ({ ...f, podPattern: e.target.value }))} />
          </FormField>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("kube.whitelist.deleteTitle")}
        desc={deleting ? t("kube.whitelist.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
