"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ArrowLeft, Server, Layers, Boxes, Activity } from "lucide-react";
import { kubeApi } from "@/lib/api/kube";
import { Card } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { Tabs } from "@/components/ui/Tabs";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { FormField } from "@/components/ui/FormField";
import { StatusTag } from "@/components/ui/Tag";
import { EmptyState } from "@/components/ui/EmptyState";
import { toast } from "@/components/ui/toast";
import type { KubeNode, KubePod, KubeWorkload, KubeScannerState } from "@/lib/api/types";

type Tone = "success" | "danger" | "info" | "neutral" | "warning";

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs uppercase tracking-wide text-faint">{label}</span>
      <span className="text-sm text-ink break-all">{value}</span>
    </div>
  );
}

export default function ClusterDetailPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("overview");
  // 静态导出(output: export)不支持动态路由段，集群 id 通过查询参数 ?id= 传入，客户端读取
  const [clusterId, setClusterId] = useState(0);
  useEffect(() => {
    const v = new URLSearchParams(window.location.search).get("id");
    setClusterId(v ? Number(v) : 0);
  }, []);

  const clusterQ = useQuery({
    queryKey: ["kube-cluster", clusterId],
    queryFn: () => kubeApi.getCluster(clusterId),
    enabled: clusterId > 0,
  });
  const c = clusterQ.data;

  const tabs = [
    { key: "overview", label: t("kube.detail.tabOverview") },
    { key: "nodes", label: t("kube.detail.tabNodes") },
    { key: "pods", label: t("kube.detail.tabPods") },
    { key: "workloads", label: t("kube.detail.tabWorkloads") },
    { key: "gcp", label: t("kube.detail.tabGcp") },
    { key: "scanner", label: t("kube.scanner.title") },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => router.push("/kube/clusters")}
          className="inline-flex h-8 w-8 items-center justify-center rounded-control border border-border text-muted hover:text-ink"
          aria-label={t("common.back")}
        >
          <ArrowLeft size={16} />
        </button>
        <h1 className="text-lg font-semibold text-ink">{c?.name ?? `#${clusterId}`}</h1>
        {c && <StatusTag tone={c.status === "running" ? "success" : c.status === "offline" ? "danger" : "warning"}>{c.status}</StatusTag>}
        {c?.version && <span className="font-mono text-xs text-faint">{c.version}</span>}
      </div>

      <Tabs items={tabs} active={tab} onChange={setTab} />

      {tab === "overview" && <OverviewTab clusterId={clusterId} />}
      {tab === "nodes" && <NodesTab clusterId={clusterId} />}
      {tab === "pods" && <PodsTab clusterId={clusterId} />}
      {tab === "workloads" && <WorkloadsTab clusterId={clusterId} />}
      {tab === "gcp" && <GcpTab clusterId={clusterId} onChanged={() => queryClient.invalidateQueries({ queryKey: ["kube-cluster", clusterId] })} />}
      {tab === "scanner" && <ScannerTab clusterId={clusterId} />}
    </div>
  );
}

function OverviewTab({ clusterId }: { clusterId: number }) {
  const { t } = useTranslation();
  const { data: c } = useQuery({ queryKey: ["kube-cluster", clusterId], queryFn: () => kubeApi.getCluster(clusterId) });
  if (!c) return null;
  const health = c.healthScore ?? 0;
  const healthTone: "success" | "warning" | "danger" = health >= 80 ? "success" : health >= 50 ? "warning" : "danger";
  const s = c.summary;
  const r = c.risks;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard compact label={t("kube.clusters.colNodeCount")} value={s?.nodes ?? 0} icon={Server} />
        <StatCard compact label={t("kube.clusters.colPodCount")} value={s?.pods ?? 0} icon={Layers} />
        <StatCard compact label={t("kube.clusters.colNamespaceCount")} value={s?.namespaces ?? 0} icon={Boxes} />
        <StatCard compact label={t("kube.clusters.colHealth")} value={health} icon={Activity} tone={healthTone} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <h3 className="mb-4 text-sm font-semibold text-ink">{t("kube.detail.basicInfo")}</h3>
          <div className="grid gap-x-8 gap-y-4 sm:grid-cols-2">
            <Field label={t("kube.clusters.colVersion")} value={<span className="font-mono">{c.version || "—"}</span>} />
            <Field label="API Server" value={<span className="font-mono">{c.apiServer || "—"}</span>} />
            <Field
              label={t("kube.detail.gcpStatus")}
              value={c.gcpEnabled ? <StatusTag tone="success">{t("kube.detail.gcpOn")}</StatusTag> : <StatusTag tone="neutral">{t("kube.detail.gcpOff")}</StatusTag>}
            />
            <Field label={t("kube.clusters.colCreatedAt")} value={<span className="tabular-nums">{c.createdAt || "—"}</span>} />
            {c.lastHeartbeat && <Field label={t("kube.detail.lastHeartbeat")} value={<span className="tabular-nums">{c.lastHeartbeat}</span>} />}
            {c.remark && <Field label={t("kube.clusters.fieldRemark")} value={c.remark} />}
          </div>
        </Card>
        <Card className="p-5">
          <h3 className="mb-4 text-sm font-semibold text-ink">{t("kube.detail.posture")}</h3>
          <div className="grid grid-cols-2 gap-x-8 gap-y-4">
            <Field label={t("kube.detail.alarms")} value={<span className={`text-base font-semibold tabular-nums ${(r?.alarms ?? 0) > 0 ? "text-danger" : "text-ink"}`}>{r?.alarms ?? 0}</span>} />
            <Field label={t("kube.detail.baselineFail")} value={<span className={`text-base font-semibold tabular-nums ${(r?.baseline ?? 0) > 0 ? "text-warning" : "text-ink"}`}>{r?.baseline ?? 0}</span>} />
            <Field label={t("kube.detail.deployments")} value={<span className="text-base font-semibold tabular-nums text-ink">{s?.deployments ?? 0}</span>} />
            <Field label={t("kube.detail.services")} value={<span className="text-base font-semibold tabular-nums text-ink">{s?.services ?? 0}</span>} />
          </div>
        </Card>
      </div>
    </div>
  );
}

function NodesTab({ clusterId }: { clusterId: number }) {
  const { t } = useTranslation();
  const { data, isLoading } = useQuery({ queryKey: ["kube-nodes", clusterId], queryFn: () => kubeApi.getClusterNodes(clusterId) });
  const columns: Column<KubeNode>[] = [
    { key: "name", title: t("kube.detail.colNodeName"), render: (r) => <span className="font-mono text-sm text-ink">{r.name}</span> },
    { key: "status", title: t("common.status"), render: (r) => <StatusTag tone={r.status === "Ready" ? "success" : "danger"}>{r.status}</StatusTag> },
    { key: "roles", title: t("kube.detail.colRoles"), render: (r) => <span className="text-muted">{r.roles || "—"}</span> },
    { key: "ip", title: "IP", render: (r) => <span className="font-mono text-sm">{r.ip || "—"}</span> },
    { key: "cpu", title: "CPU%", align: "right", render: (r) => <span className="tabular-nums">{r.cpuPercent?.toFixed?.(1) ?? 0}</span> },
    { key: "mem", title: t("kube.detail.colMem"), align: "right", render: (r) => <span className="tabular-nums">{r.memoryPercent?.toFixed?.(1) ?? 0}</span> },
    { key: "pods", title: "Pods", align: "right", render: (r) => <span className="tabular-nums">{r.podCount ?? 0}</span> },
    { key: "kubelet", title: "Kubelet", render: (r) => <span className="font-mono text-xs text-faint">{r.kubeletVersion}</span> },
  ];
  return (
    <Card>
      <DataTable columns={columns} rows={data?.items ?? []} rowKey={(r) => r.name} loading={isLoading} emptyText={t("kube.detail.emptyNodes")} />
    </Card>
  );
}

function PodsTab({ clusterId }: { clusterId: number }) {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const { data, isLoading } = useQuery({ queryKey: ["kube-pods", clusterId, page], queryFn: () => kubeApi.getClusterPods(clusterId, { page, page_size: 20 }) });
  const columns: Column<KubePod>[] = [
    { key: "name", title: t("kube.detail.colPodName"), render: (r) => <span className="font-mono text-sm text-ink">{r.name}</span> },
    { key: "namespace", title: t("kube.common.colNamespace"), render: (r) => <span className="font-mono text-sm text-muted">{r.namespace}</span> },
    { key: "status", title: t("common.status"), render: (r) => <StatusTag tone={r.status === "Running" || r.status === "Succeeded" ? "success" : r.status === "Pending" ? "info" : "danger"}>{r.status}</StatusTag> },
    { key: "ready", title: t("kube.detail.colReady"), align: "right", render: (r) => <span className="tabular-nums">{r.readyContainers}/{r.totalContainers}</span> },
    { key: "restarts", title: t("kube.detail.colRestarts"), align: "right", render: (r) => <span className="tabular-nums">{r.restarts}</span> },
    { key: "node", title: t("kube.detail.colNode"), render: (r) => <span className="font-mono text-xs text-faint">{r.nodeName || "—"}</span> },
    { key: "age", title: t("kube.detail.colAge"), render: (r) => <span className="text-faint">{r.age}</span> },
  ];
  return (
    <Card>
      <DataTable columns={columns} rows={data?.items ?? []} rowKey={(r) => r.namespace + "/" + r.name} loading={isLoading} emptyText={t("kube.detail.emptyPods")} />
      <Pagination page={page} pageSize={20} total={data?.total ?? 0} onChange={setPage} />
    </Card>
  );
}

function WorkloadsTab({ clusterId }: { clusterId: number }) {
  const { t } = useTranslation();
  const { data, isLoading } = useQuery({ queryKey: ["kube-workloads", clusterId], queryFn: () => kubeApi.getClusterWorkloads(clusterId) });
  const columns: Column<KubeWorkload>[] = [
    { key: "name", title: t("kube.detail.colWorkloadName"), render: (r) => <span className="font-mono text-sm text-ink">{r.name}</span> },
    { key: "type", title: t("kube.detail.colType"), render: (r) => <StatusTag tone="neutral">{r.type}</StatusTag> },
    { key: "namespace", title: t("kube.common.colNamespace"), render: (r) => <span className="font-mono text-sm text-muted">{r.namespace}</span> },
    { key: "replicas", title: t("kube.detail.colReplicas"), align: "right", render: (r) => <span className="tabular-nums">{r.readyReplicas}/{r.desiredReplicas}</span> },
    { key: "images", title: t("kube.detail.colImages"), render: (r) => <span className="block max-w-md truncate font-mono text-xs text-muted">{r.images}</span> },
    { key: "createdAt", title: t("kube.clusters.colCreatedAt"), render: (r) => <span className="text-faint tabular-nums">{r.createdAt}</span> },
  ];
  return (
    <Card>
      <DataTable columns={columns} rows={data?.items ?? []} rowKey={(r) => r.namespace + "/" + r.type + "/" + r.name} loading={isLoading} emptyText={t("kube.detail.emptyWorkloads")} />
    </Card>
  );
}

function GcpTab({ clusterId, onChanged }: { clusterId: number; onChanged: () => void }) {
  const { t } = useTranslation();
  const { data: c } = useQuery({ queryKey: ["kube-cluster", clusterId], queryFn: () => kubeApi.getCluster(clusterId) });
  const [projectId, setProjectId] = useState("");
  const [subscription, setSubscription] = useState("");
  const [location, setLocation] = useState("");
  const [clusterName, setClusterName] = useState("");
  const [credentialsJson, setCredentialsJson] = useState("");

  useEffect(() => {
    if (c) {
      setProjectId(c.gcpProjectId ?? "");
      setSubscription(c.gcpSubscription ?? "");
      setLocation(c.gcpLocation ?? "");
      setClusterName(c.gcpClusterName ?? "");
    }
  }, [c]);

  const saveMutation = useMutation({
    mutationFn: () => kubeApi.updateClusterGCP(clusterId, { projectId, subscription, location, clusterName, credentialsJson: credentialsJson || undefined }),
    onSuccess: () => { onChanged(); setCredentialsJson(""); toast.success(t("kube.detail.gcpSaved")); },
    onError: (e: Error) => toast.error(e.message),
  });
  const disableMutation = useMutation({
    mutationFn: () => kubeApi.deleteClusterGCP(clusterId),
    onSuccess: () => { onChanged(); toast.success(t("kube.detail.gcpDisabled")); },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Card className="p-5">
      <div className="space-y-5">
        <div className="flex flex-wrap items-center gap-3">
          <h3 className="text-sm font-semibold text-ink">{t("kube.detail.tabGcp")}</h3>
          {c?.gcpEnabled ? <StatusTag tone="success">{t("kube.detail.gcpOn")}</StatusTag> : <StatusTag tone="neutral">{t("kube.detail.gcpOff")}</StatusTag>}
        </div>
        <p className="text-sm text-muted">{t("kube.detail.gcpHint")}</p>
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField label="GCP Project ID" required>
            <Input value={projectId} onChange={(e) => setProjectId(e.target.value)} placeholder="my-gcp-project" />
          </FormField>
          <FormField label={t("kube.detail.gcpSubscription")}>
            <Input value={subscription} onChange={(e) => setSubscription(e.target.value)} placeholder="mxcwpp-gke-audit-sub（仅审计需要）" />
          </FormField>
          <FormField label={t("kube.detail.gcpLocation")}>
            <Input value={location} onChange={(e) => setLocation(e.target.value)} placeholder="asia-east2 / asia-east2-a" />
          </FormField>
          <FormField label={t("kube.detail.gcpClusterName")}>
            <Input value={clusterName} onChange={(e) => setClusterName(e.target.value)} placeholder="缺省取集群名" />
          </FormField>
        </div>
        <FormField label={t("kube.detail.gcpCreds")}>
          <textarea
            value={credentialsJson}
            onChange={(e) => setCredentialsJson(e.target.value)}
            rows={6}
            placeholder={c?.gcpEnabled ? t("kube.detail.gcpCredsKeep") : t("kube.detail.gcpCredsPlaceholder")}
            className="w-full rounded-control border border-border bg-surface px-3 py-2 font-mono text-xs text-ink outline-none focus:border-primary"
          />
        </FormField>
        <div className="flex gap-2 border-t border-border pt-4">
          <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending || !projectId.trim()}>
            {saveMutation.isPending ? t("common.submitting") : t("common.save")}
          </Button>
          {c?.gcpEnabled && (
            <Button variant="ghost" onClick={() => disableMutation.mutate()} disabled={disableMutation.isPending}>
              {t("kube.detail.gcpDisable")}
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}

function ScannerTab({ clusterId }: { clusterId: number }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const statusQ = useQuery({
    queryKey: ["kube-scanner-status", clusterId],
    queryFn: () => kubeApi.scannerStatus(clusterId),
    refetchInterval: (q) => {
      const s = q.state.data?.state;
      return s === "installing" || s === "uninstalling" ? 5000 : false;
    },
  });
  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["kube-scanner-status", clusterId] });
    queryClient.invalidateQueries({ queryKey: ["kube-images"] });
  };
  const installM = useMutation({ mutationFn: () => kubeApi.scannerInstall(clusterId), onSuccess: () => { invalidate(); toast.success(t("kube.scanner.installSubmitted")); }, onError: (e: Error) => toast.error(e.message) });
  const syncM = useMutation({ mutationFn: () => kubeApi.scannerSync(clusterId), onSuccess: (r) => { invalidate(); toast.success(t("kube.scanner.synced", { count: r.reports })); }, onError: (e: Error) => toast.error(e.message) });
  const uninstallM = useMutation({ mutationFn: () => kubeApi.scannerUninstall(clusterId), onSuccess: () => { invalidate(); toast.success(t("kube.scanner.uninstallSubmitted")); }, onError: (e: Error) => toast.error(e.message) });

  const state: KubeScannerState = statusQ.data?.state ?? "not_installed";
  const busy = installM.isPending || uninstallM.isPending || syncM.isPending;
  const tone: Tone = state === "ready" ? "success" : state === "degraded" ? "danger" : state === "not_installed" ? "neutral" : "info";

  return (
    <Card className="p-5">
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <div className="flex items-center gap-2">
            <StatusTag tone={tone}>{t(`kube.scanner.state.${state}`)}</StatusTag>
            {statusQ.data?.operatorVersion && <span className="text-xs text-faint">{statusQ.data.operatorVersion}</span>}
            {statusQ.data?.webhookEnabled && <StatusTag tone="info">{t("kube.scanner.webhookOn")}</StatusTag>}
          </div>
          {(state === "ready" || state === "degraded") && (
            <div className="flex gap-5 text-sm text-muted">
              <span>{t("kube.scanner.lastSync")}: <span className="tabular-nums text-ink">{statusQ.data?.lastSyncAt || t("kube.scanner.never")}</span></span>
              <span>{t("kube.scanner.reports")}: <span className="tabular-nums text-ink">{statusQ.data?.lastReportCount ?? 0}</span></span>
            </div>
          )}
          <div className="ml-auto flex gap-2">
            {state === "not_installed" && <Button onClick={() => installM.mutate()} disabled={busy}>{t("kube.scanner.deploy")}</Button>}
            {(state === "ready" || state === "degraded") && (
              <>
                <Button onClick={() => syncM.mutate()} disabled={busy}>{syncM.isPending ? t("common.submitting") : t("kube.scanner.sync")}</Button>
                <Button variant="ghost" onClick={() => uninstallM.mutate()} disabled={busy}>{t("kube.scanner.uninstall")}</Button>
              </>
            )}
          </div>
        </div>
        {statusQ.data?.lastError && <p className="text-xs text-danger break-all">{statusQ.data.lastError}</p>}
        {state === "not_installed" && <EmptyState title={t("kube.scanner.title")} desc={t("kube.scanner.hint")} />}
      </div>
    </Card>
  );
}
