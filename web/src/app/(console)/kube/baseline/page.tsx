"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ListChecks, CheckCircle2, XCircle, Percent } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { kubeApi } from "@/lib/api/kube";
import type { KubeBaselineTask } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { ClusterFilter } from "@/components/kube/ClusterFilter";
import { Button } from "@/components/ui/Button";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

type Tone = "success" | "warning" | "danger" | "info" | "neutral";
const taskStatusTone = (s: string): Tone => (s === "done" ? "success" : s === "failed" ? "danger" : "info");
const fmtRate = (v: number | undefined) => `${Math.round(v == null ? 0 : v <= 1 ? v * 100 : v)}%`;

export default function KubeBaselinePage() {
  const { t } = useTranslation();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, cluster_id: "" });

  const { data, isLoading } = useQuery({
    queryKey: ["kube-baseline-tasks", params],
    queryFn: () =>
      kubeApi.listBaselineTasks({ page: params.page, page_size: params.page_size, cluster_id: params.cluster_id || undefined }),
  });
  const latest = data?.items?.[0];

  const [detecting, setDetecting] = useState(false);
  const detectMutation = useMutation({
    mutationFn: () => kubeApi.runBaselineDetect({ cluster_id: Number(params.cluster_id) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["kube-baseline-tasks"] });
      setDetecting(false);
      toast.success(t("kube.baseline.detectTriggered"));
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const onDetect = () => {
    if (!params.cluster_id) {
      toast.error(t("kube.baseline.selectClusterFirst"));
      return;
    }
    setDetecting(true);
  };

  const openTask = (id: number) => router.push(`/kube/baseline/task?id=${id}`);

  const columns: Column<KubeBaselineTask>[] = [
    { key: "startedAt", title: t("kube.baseline.colStartedAt"), render: (r) => <span className="text-faint tabular-nums">{r.startedAt}</span> },
    { key: "clusterName", title: t("kube.common.colCluster"), render: (r) => <span className="font-medium text-ink">{r.clusterName}</span> },
    { key: "status", title: t("common.status"), render: (r) => <StatusTag tone={taskStatusTone(r.status)}>{t(`kube.baseline.taskStatus.${r.status}`)}</StatusTag> },
    { key: "total", title: t("kube.baseline.colTotal"), align: "right", render: (r) => <span className="tabular-nums">{r.total}</span> },
    { key: "passed", title: t("kube.baseline.statPassed"), align: "right", render: (r) => <span className="tabular-nums text-success">{r.passed}</span> },
    { key: "failed", title: t("kube.baseline.statFailed"), align: "right", render: (r) => <span className="tabular-nums text-danger">{r.failed}</span> },
    { key: "passRate", title: t("kube.baseline.statPassRate"), align: "right", render: (r) => <span className="tabular-nums font-semibold">{fmtRate(r.passRate)}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <Button variant="ghost" className="h-8 px-3" onClick={(e) => { e.stopPropagation(); openTask(r.id); }}>
          {t("common.details")}
        </Button>
      ),
    },
  ];

  return (
    <>
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard compact label={t("kube.baseline.statTotalChecks")} value={latest?.total ?? 0} icon={ListChecks} tone="default" />
        <StatCard compact label={t("kube.baseline.statPassed")} value={latest?.passed ?? 0} icon={CheckCircle2} tone="success" />
        <StatCard compact label={t("kube.baseline.statFailed")} value={latest?.failed ?? 0} icon={XCircle} tone="danger" />
        <StatCard compact label={t("kube.baseline.statPassRate")} value={fmtRate(latest?.passRate)} icon={Percent} tone="success" />
      </div>

      <div className="space-y-4">
        <FilterBar extra={<Button onClick={onDetect} disabled={detectMutation.isPending}>{detectMutation.isPending ? t("common.submitting") : t("kube.baseline.detect")}</Button>}>
          <ClusterFilter value={params.cluster_id} onChange={(v) => setParams((p) => ({ ...p, cluster_id: v, page: 1 }))} />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("kube.baseline.emptyTasks")}
            onRowClick={(r) => openTask(r.id)}
          />
          <Pagination page={params.page} pageSize={params.page_size} total={data?.total ?? 0} onChange={(page) => setParams((p) => ({ ...p, page }))} />
        </Card>
      </div>

      <ConfirmDialog
        open={detecting}
        title={t("kube.baseline.detectTitle")}
        desc={t("kube.baseline.detectConfirmDesc")}
        loading={detectMutation.isPending}
        onConfirm={() => detectMutation.mutate()}
        onCancel={() => setDetecting(false)}
      />
    </>
  );
}
