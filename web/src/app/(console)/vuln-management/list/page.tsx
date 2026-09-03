"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ShieldAlert, AlertOctagon, AlertTriangle, Server, Layers, ShieldCheck, ShieldX, Percent } from "lucide-react";
import { vulnApi } from "@/lib/api/vuln";
import type { Severity, Vulnerability } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";
import { useUrlState } from "@/hooks/useUrlState";

interface ListParams {
  page: number;
  page_size: number;
  search: string;
  severity: string;
  status: string;
  asset_type: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";
const KNOWN_SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const isSeverity = (s: string): s is Severity => (KNOWN_SEVERITIES as string[]).includes(s);

const buildStatusMeta = (t: TFunction): Record<string, { tone: Tone; label: string }> => ({
  unpatched: { tone: "danger", label: t("vuln.status.unpatched") },
  patched: { tone: "success", label: t("vuln.status.patched") },
  ignored: { tone: "neutral", label: t("vuln.status.ignored") },
});

const buildSeverityOptions = (t: TFunction) => [
  { label: t("vuln.list.allSeverity"), value: "" },
  { label: t("common.severity.critical"), value: "critical" },
  { label: t("common.severity.high"), value: "high" },
  { label: t("common.severity.medium"), value: "medium" },
  { label: t("common.severity.low"), value: "low" },
];
const buildStatusOptions = (t: TFunction) => [
  { label: t("vuln.list.allStatus"), value: "" },
  { label: t("vuln.status.unpatched"), value: "unpatched" },
  { label: t("vuln.status.patched"), value: "patched" },
  { label: t("vuln.status.ignored"), value: "ignored" },
];
const buildAssetTypeOptions = (t: TFunction) => [
  { label: t("vuln.list.allAssetType"), value: "" },
  { label: t("vuln.list.assetTypeOs"), value: "os" },
  { label: t("vuln.list.assetTypeApplication"), value: "application" },
  { label: t("vuln.list.assetTypeMiddleware"), value: "middleware" },
];
// 包类型: 默认只看系统包(OS/rpm/dnf/yum/apt), 应用依赖(golang/maven/npm/pypi)默认隐藏。
const buildPackageTypeOptions = (t: TFunction) => [
  { label: t("vuln.list.packageTypeOs"), value: "os" },
  { label: t("vuln.list.packageTypeApp"), value: "app" },
  { label: t("vuln.list.packageTypeAll"), value: "all" },
];

export default function VulnListPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const queryClient = useQueryClient();
  const openDetail = (id: number) => router.push(`/vuln-management/list/detail?id=${id}`);
  const statusMeta = buildStatusMeta(t);
  const statusTag = (status: string) => {
    const meta = statusMeta[status] ?? { tone: "neutral" as Tone, label: status || "—" };
    return <StatusTag tone={meta.tone}>{meta.label}</StatusTag>;
  };
  const severityOptions = buildSeverityOptions(t);
  const statusOptions = buildStatusOptions(t);
  const assetTypeOptions = buildAssetTypeOptions(t);
  const packageTypeOptions = buildPackageTypeOptions(t);
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    search: "",
    severity: "",
    status: "",
    asset_type: "",
    package_type: "os",
  });

  const { data, isLoading, isError } = useQuery({
    queryKey: ["vuln-list", params],
    queryFn: () =>
      vulnApi.listVulns({
        page: params.page,
        page_size: params.page_size,
        search: params.search || undefined,
        severity: params.severity || undefined,
        status: params.status || undefined,
        asset_type: params.asset_type || undefined,
        package_type: params.package_type || undefined,
      }),
  });
  // 取不到就明说取不到：`?? 0` 会把"后端没答上来"渲染成 0，
  // 看板上读起来像"环境干净"。
  const statState = { error: isError, loading: isLoading };
  const stats = data?.stats;

  const [ignoring, setIgnoring] = useState<Vulnerability | null>(null);
  const [unignoring, setUnignoring] = useState<Vulnerability | null>(null);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["vuln-list"] });
    queryClient.invalidateQueries({ queryKey: ["vuln-detail"] });
  };

  const ignoreMutation = useMutation({
    mutationFn: (id: number) => vulnApi.ignoreVuln(id),
    onSuccess: () => {
      invalidate();
      setIgnoring(null);
      toast.success(t("vuln.list.ignored"));
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const unignoreMutation = useMutation({
    mutationFn: (id: number) => vulnApi.unignoreVuln(id),
    onSuccess: () => {
      invalidate();
      setUnignoring(null);
      toast.success(t("vuln.list.unignored"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<Vulnerability>[] = [
    { key: "cveId", title: "CVE", render: (r) => <span className="font-medium font-mono text-ink">{r.cveId}</span> },
    {
      key: "severity",
      title: t("common.level"),
      render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : <StatusTag tone="neutral">{r.severity || "—"}</StatusTag>),
    },
    { key: "cvssScore", title: "CVSS", render: (r) => <span className="tabular-nums">{r.cvssScore?.toFixed(1) ?? "—"}</span> },
    { key: "component", title: t("vuln.list.colComponent"), render: (r) => <span className="text-muted">{r.matchedComponent || r.component || "—"}</span> },
    { key: "affectedHosts", title: t("vuln.list.colAffectedHosts"), render: (r) => <span className="tabular-nums">{r.affectedHosts ?? 0}</span> },
    { key: "status", title: t("common.status"), render: (r) => statusTag(r.status) },
    {
      key: "fixedVersion",
      title: t("vuln.list.colFixedVersion"),
      render: (r) => <span className="font-mono text-faint">{r.fixedVersion || "—"}</span>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          {r.status === "ignored" ? (
            <Button variant="ghost" className="h-8 px-3" onClick={() => setUnignoring(r)}>
              {t("vuln.list.actionUnignore")}
            </Button>
          ) : (
            <Button variant="ghost" className="h-8 px-3" onClick={() => setIgnoring(r)}>
              {t("vuln.list.actionIgnore")}
            </Button>
          )}
          <Button variant="ghost" className="h-8 px-3" onClick={() => openDetail(r.id)}>
            {t("common.details")}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5 mb-3">
        <StatCard compact label={t("vuln.list.statTotal")} value={stats?.total ?? 0} {...statState} icon={ShieldAlert} tone="default" />
        <StatCard compact label={t("vuln.list.statHostInstances")} value={stats?.hostInstances ?? 0} {...statState} icon={Layers} tone="default" />
        <StatCard compact label={t("vuln.list.statPatched")} value={stats?.patched ?? 0} {...statState} icon={ShieldCheck} tone="success" />
        <StatCard compact label={t("vuln.list.statUnpatched")} value={stats?.unpatched ?? 0} {...statState} icon={ShieldX} tone="danger" />
        <StatCard compact label={t("vuln.list.statRate")} value={`${(stats?.remediationRate ?? 0).toFixed(1)}%`} {...statState} icon={Percent} tone="success" />
      </div>
      <div className="grid grid-cols-3 gap-3 md:grid-cols-3 mb-5">
        <StatCard compact label={t("vuln.list.statCritical")} value={stats?.critical ?? 0} {...statState} icon={AlertOctagon} tone="danger" />
        <StatCard compact label={t("vuln.list.statHigh")} value={stats?.high ?? 0} {...statState} icon={AlertTriangle} tone="warning" />
        <StatCard compact label={t("vuln.list.statAffectedHosts")} value={stats?.affectedHosts ?? 0} {...statState} icon={Server} tone="default" />
      </div>

      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={params.search}
            onChange={(v) => setParams((p) => ({ ...p, search: v, page: 1 }))}
            placeholder={t("vuln.list.searchPlaceholder")}
          />
          <Select value={params.package_type} onChange={(v) => setParams((p) => ({ ...p, package_type: v, page: 1 }))} options={packageTypeOptions} />
          <Select value={params.severity} onChange={(v) => setParams((p) => ({ ...p, severity: v, page: 1 }))} options={severityOptions} />
          <Select value={params.status} onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))} options={statusOptions} />
          <Select value={params.asset_type} onChange={(v) => setParams((p) => ({ ...p, asset_type: v, page: 1 }))} options={assetTypeOptions} />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("vuln.list.empty")}
            onRowClick={(r) => openDetail(r.id)}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      <ConfirmDialog
        open={!!ignoring}
        title={t("vuln.list.ignoreTitle")}
        desc={ignoring ? t("vuln.list.ignoreConfirmDesc", { cve: ignoring.cveId }) : undefined}
        loading={ignoreMutation.isPending}
        onConfirm={() => ignoring && ignoreMutation.mutate(ignoring.id)}
        onCancel={() => setIgnoring(null)}
      />
      <ConfirmDialog
        open={!!unignoring}
        title={t("vuln.list.unignoreTitle")}
        desc={unignoring ? t("vuln.list.unignoreConfirmDesc", { cve: unignoring.cveId }) : undefined}
        loading={unignoreMutation.isPending}
        onConfirm={() => unignoring && unignoreMutation.mutate(unignoring.id)}
        onCancel={() => setUnignoring(null)}
      />
    </>
  );
}
