"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Boxes, CheckCircle2, Server, Layers } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { kubeApi } from "@/lib/api/kube";
import type { KubeCluster } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
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

interface ClusterForm {
  name: string;
  apiServer: string;
  version: string;
}
const emptyForm: ClusterForm = { name: "", apiServer: "", version: "" };

const runningStatuses = new Set(["running", "healthy"]);

function statusTone(status: string): "success" | "warning" | "neutral" {
  if (runningStatuses.has(status)) return "success";
  if (status === "abnormal" || status === "error") return "warning";
  return "neutral";
}

function healthColor(score: number): string {
  if (score >= 80) return "text-success";
  if (score >= 60) return "text-warning";
  return "text-danger";
}


export default function KubeClustersPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20 });

  const { data, isLoading } = useQuery({
    queryKey: ["kube-clusters", params],
    queryFn: () => kubeApi.listClusters(params),
  });
  const stats = data?.stats;

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<KubeCluster | null>(null);
  const [form, setForm] = useState<ClusterForm>(emptyForm);
  const [deleting, setDeleting] = useState<KubeCluster | null>(null);
  const [regenerating, setRegenerating] = useState<KubeCluster | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["kube-clusters"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (c: KubeCluster) => {
    setEditing(c);
    setForm({ name: c.name, apiServer: c.apiServer, version: c.version });
    setDrawerOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: () => {
      const body: Partial<KubeCluster> = {
        name: form.name,
        apiServer: form.apiServer,
        version: form.version,
      };
      return editing ? kubeApi.updateCluster(editing.id, body) : kubeApi.createCluster(body);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("kube.clusters.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => kubeApi.deleteCluster(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("kube.clusters.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const regenerateMutation = useMutation({
    mutationFn: (id: number) => kubeApi.regenerateClusterToken(id),
    onSuccess: () => {
      setRegenerating(null);
      toast.success(t("kube.clusters.tokenRegenerated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<KubeCluster>[] = [
    { key: "name", title: t("kube.clusters.colName"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => <StatusTag tone={statusTone(r.status)}>{r.status || "—"}</StatusTag>,
    },
    { key: "version", title: t("kube.clusters.colVersion"), render: (r) => <span className="font-mono text-ink">{r.version || "—"}</span> },
    { key: "nodeCount", title: t("kube.clusters.colNodeCount"), align: "right", render: (r) => <span className="tabular-nums">{r.nodeCount ?? 0}</span> },
    { key: "podCount", title: t("kube.clusters.colPodCount"), align: "right", render: (r) => <span className="tabular-nums">{r.podCount ?? 0}</span> },
    {
      key: "namespaceCount",
      title: t("kube.clusters.colNamespaceCount"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.namespaceCount ?? 0}</span>,
    },
    {
      key: "healthScore",
      title: t("kube.clusters.colHealth"),
      align: "right",
      render: (r) => (
        <span className={`tabular-nums font-semibold ${healthColor(r.healthScore ?? 0)}`}>{r.healthScore ?? 0}</span>
      ),
    },
    {
      key: "apiServer",
      title: t("kube.clusters.colApiServer"),
      render: (r) => <span className="font-mono text-muted truncate block max-w-[200px]">{r.apiServer || "—"}</span>,
    },
    {
      key: "createdAt",
      title: t("kube.clusters.colCreatedAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.createdAt}</span>,
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
              openEdit(r);
            }}
          >
            {t("common.edit")}
          </button>
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={(e) => {
              e.stopPropagation();
              setRegenerating(r);
            }}
          >
            {t("kube.clusters.actionResetToken")}
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
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 mb-5">
        <StatCard compact label={t("kube.clusters.statTotal")} value={stats?.total ?? 0} icon={Boxes} tone="default" />
        <StatCard compact label={t("kube.clusters.statRunning")} value={stats?.running ?? 0} icon={CheckCircle2} tone="success" />
        <StatCard compact label={t("kube.clusters.statNodes")} value={stats?.nodes ?? 0} icon={Server} tone="default" />
        <StatCard compact label={t("kube.clusters.statPods")} value={stats?.pods ?? 0} icon={Layers} tone="default" />
      </div>

      <div className="space-y-4">
        <FilterBar extra={<Button onClick={openCreate}>{t("kube.clusters.connect")}</Button>}>
          <></>
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id ?? r.name}
            loading={isLoading}
            emptyText={t("kube.clusters.empty")}
            onRowClick={(r) => router.push(`/kube/clusters/detail?id=${r.id}`)}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      {/* 接入 / 编辑集群 */}
      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={editing ? t("kube.clusters.editTitle") : t("kube.clusters.createTitle")}
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
          <FormField label={t("kube.clusters.colName")} required>
            <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <FormField label={t("kube.clusters.colApiServer")}>
            <Input
              value={form.apiServer}
              onChange={(e) => setForm((f) => ({ ...f, apiServer: e.target.value }))}
              placeholder={t("kube.clusters.fieldApiServerPlaceholder")}
            />
          </FormField>
          <FormField label={t("kube.clusters.colVersion")}>
            <Input
              value={form.version}
              onChange={(e) => setForm((f) => ({ ...f, version: e.target.value }))}
              placeholder={t("kube.clusters.fieldVersionPlaceholder")}
            />
          </FormField>
          <p className="text-xs text-faint">{t("kube.clusters.createHint")}</p>
        </div>
      </Drawer>

      {/* 删除集群 */}
      <ConfirmDialog
        open={!!deleting}
        title={t("kube.clusters.deleteTitle")}
        desc={deleting ? t("kube.clusters.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />

      {/* 重置 Token */}
      <ConfirmDialog
        open={!!regenerating}
        title={t("kube.clusters.regenTitle")}
        desc={regenerating ? t("kube.clusters.regenConfirmDesc", { name: regenerating.name }) : undefined}
        danger={false}
        confirmText={t("kube.clusters.regenConfirm")}
        loading={regenerateMutation.isPending}
        onConfirm={() => regenerating && regenerateMutation.mutate(regenerating.id)}
        onCancel={() => setRegenerating(null)}
      />
    </>
  );
}
