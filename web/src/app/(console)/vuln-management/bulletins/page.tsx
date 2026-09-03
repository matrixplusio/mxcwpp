"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Megaphone, Clock, ShieldAlert, AlertTriangle } from "lucide-react";
import { vulnApi } from "@/lib/api/vuln";
import type { Severity, VulnBulletin } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";
import { useUrlState } from "@/hooks/useUrlState";

interface ListParams {
  page: number;
  page_size: number;
  priority: string;
  status: string;
  search: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";
const KNOWN_SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const isSeverity = (s: string): s is Severity => (KNOWN_SEVERITIES as string[]).includes(s);

const priorityMeta: Record<string, Tone> = { P0: "danger", P1: "danger", P2: "warning", P3: "neutral" };
const priorityTag = (p: string) => <StatusTag tone={priorityMeta[p] ?? "neutral"}>{p || "—"}</StatusTag>;

const buildStatusMeta = (t: TFunction): Record<string, { tone: Tone; label: string }> => ({
  active: { tone: "danger", label: t("vuln.bulletins.statusActive") },
  acknowledged: { tone: "warning", label: t("vuln.bulletins.statusAcknowledged") },
  resolved: { tone: "success", label: t("vuln.bulletins.statusResolved") },
  ignored: { tone: "neutral", label: t("vuln.bulletins.statusIgnored") },
});

const buildPriorityOptions = (t: TFunction) => [
  { label: t("vuln.bulletins.allPriority"), value: "" },
  { label: "P0", value: "P0" },
  { label: "P1", value: "P1" },
  { label: "P2", value: "P2" },
  { label: "P3", value: "P3" },
];
const buildStatusOptions = (t: TFunction) => [
  { label: t("vuln.bulletins.allStatus"), value: "" },
  { label: t("vuln.bulletins.statusActive"), value: "active" },
  { label: t("vuln.bulletins.statusAcknowledged"), value: "acknowledged" },
  { label: t("vuln.bulletins.statusResolved"), value: "resolved" },
  { label: t("vuln.bulletins.statusIgnored"), value: "ignored" },
];

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-24 shrink-0 text-muted">{label}</span>
      <span className="text-ink break-all">{value}</span>
    </div>
  );
}

export default function BulletinsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const statusMeta = buildStatusMeta(t);
  const statusTag = (status: string) => {
    const meta = statusMeta[status] ?? { tone: "neutral" as Tone, label: status || "—" };
    return <StatusTag tone={meta.tone}>{meta.label}</StatusTag>;
  };
  const priorityOptions = buildPriorityOptions(t);
  const statusOptions = buildStatusOptions(t);
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    priority: "",
    status: "",
    search: "",
  });

  const { data: stats, isError: statsError } = useQuery({
    queryKey: ["bulletin-stats"],
    queryFn: () => vulnApi.bulletinStatistics(),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["bulletins", params],
    queryFn: () =>
      vulnApi.listBulletins({
        page: params.page,
        page_size: params.page_size,
        priority: params.priority || undefined,
        status: params.status || undefined,
        search: params.search || undefined,
      }),
  });

  const [detailId, setDetailId] = useState<number | null>(null);
  const [ack, setAck] = useState<VulnBulletin | null>(null);
  const [resolve, setResolve] = useState<VulnBulletin | null>(null);
  const [ignore, setIgnore] = useState<VulnBulletin | null>(null);
  const [reopen, setReopen] = useState<VulnBulletin | null>(null);

  const detail = data?.items.find((b) => b.id === detailId) ?? null;

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["bulletins"] });
    queryClient.invalidateQueries({ queryKey: ["bulletin-stats"] });
  };

  const ackMutation = useMutation({
    mutationFn: (id: number) => vulnApi.ackBulletin(id),
    onSuccess: () => { invalidate(); setAck(null); toast.success(t("vuln.bulletins.acked")); },
    onError: (e: Error) => toast.error(e.message),
  });
  const resolveMutation = useMutation({
    mutationFn: (id: number) => vulnApi.resolveBulletin(id),
    onSuccess: () => { invalidate(); setResolve(null); toast.success(t("vuln.bulletins.resolved")); },
    onError: (e: Error) => toast.error(e.message),
  });
  const ignoreMutation = useMutation({
    mutationFn: (id: number) => vulnApi.ignoreBulletin(id),
    onSuccess: () => { invalidate(); setIgnore(null); toast.success(t("vuln.bulletins.ignored")); },
    onError: (e: Error) => toast.error(e.message),
  });
  const reopenMutation = useMutation({
    mutationFn: (id: number) => vulnApi.reopenBulletin(id),
    onSuccess: () => { invalidate(); setReopen(null); toast.success(t("vuln.bulletins.reopened")); },
    onError: (e: Error) => toast.error(e.message),
  });

  const byPriority = stats?.by_priority ?? {};

  const columns: Column<VulnBulletin>[] = [
    { key: "bulletinNo", title: t("vuln.bulletins.colBulletinNo"), render: (r) => <span className="font-medium font-mono text-ink">{r.bulletinNo}</span> },
    { key: "cveId", title: "CVE", render: (r) => <span className="font-mono text-muted">{r.cveId}</span> },
    { key: "priority", title: t("vuln.bulletins.colPriority"), render: (r) => priorityTag(r.priority) },
    {
      key: "severity",
      title: t("common.level"),
      render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : <StatusTag tone="neutral">{r.severity || "—"}</StatusTag>),
    },
    { key: "cvssScore", title: "CVSS", render: (r) => <span className="tabular-nums">{r.cvssScore?.toFixed(1) ?? "—"}</span> },
    { key: "status", title: t("common.status"), render: (r) => statusTag(r.status) },
    {
      key: "slaBreached",
      title: "SLA",
      render: (r) => (r.slaBreached ? <StatusTag tone="danger">{t("vuln.bulletins.slaBreached")}</StatusTag> : <span className="text-faint">—</span>),
    },
    { key: "affectedAssets", title: t("vuln.bulletins.colAffectedAssets"), render: (r) => <span className="tabular-nums">{r.affectedAssets ?? 0}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          {r.status === "active" && (
            <Button variant="ghost" className="h-8 px-3" onClick={() => setAck(r)}>{t("vuln.bulletins.actionAck")}</Button>
          )}
          {(r.status === "active" || r.status === "acknowledged") && (
            <>
              <Button variant="ghost" className="h-8 px-3" onClick={() => setResolve(r)}>{t("vuln.bulletins.actionResolve")}</Button>
              <Button variant="ghost" className="h-8 px-3" onClick={() => setIgnore(r)}>{t("vuln.bulletins.actionIgnore")}</Button>
            </>
          )}
          {(r.status === "resolved" || r.status === "ignored") && (
            <Button variant="ghost" className="h-8 px-3" onClick={() => setReopen(r)}>{t("vuln.bulletins.actionReopen")}</Button>
          )}
          <Button variant="ghost" className="h-8 px-3" onClick={() => setDetailId(r.id)}>{t("common.details")}</Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 mb-5">
        <StatCard compact label={t("vuln.bulletins.statActive")} value={stats?.active ?? 0} error={statsError} icon={Megaphone} tone="danger" />
        <StatCard compact label={t("vuln.bulletins.statSlaBreached")} value={stats?.sla_breached ?? 0} error={statsError} icon={Clock} tone="warning" />
        <StatCard compact label={t("vuln.bulletins.statP0")} value={byPriority.P0 ?? 0} error={statsError} icon={ShieldAlert} tone="danger" />
        <StatCard compact label={t("vuln.bulletins.statP1")} value={byPriority.P1 ?? 0} error={statsError} icon={AlertTriangle} tone="warning" />
      </div>

      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={params.search}
            onChange={(v) => setParams((p) => ({ ...p, search: v, page: 1 }))}
            placeholder={t("vuln.bulletins.searchPlaceholder")}
          />
          <Select value={params.priority} onChange={(v) => setParams((p) => ({ ...p, priority: v, page: 1 }))} options={priorityOptions} />
          <Select value={params.status} onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))} options={statusOptions} />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("vuln.bulletins.empty")}
            onRowClick={(r) => setDetailId(r.id)}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      <Drawer open={detailId != null} onClose={() => setDetailId(null)} title={t("vuln.bulletins.detailTitle")} width={560}>
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold font-mono text-ink">{detail.bulletinNo}</h2>
              <div className="flex items-center gap-2">
                {priorityTag(detail.priority)}
                {isSeverity(detail.severity) ? <SeverityTag level={detail.severity} /> : <StatusTag tone="neutral">{detail.severity}</StatusTag>}
                {statusTag(detail.status)}
                {detail.slaBreached && <StatusTag tone="danger">{t("vuln.bulletins.slaBreachedTag")}</StatusTag>}
              </div>
            </div>

            <div className="space-y-2">
              <Field label="CVE" value={<span className="font-mono">{detail.cveId}</span>} />
              <Field label="CVSS" value={<span className="tabular-nums">{detail.cvssScore?.toFixed(1) ?? "—"}</span>} />
              <Field label={t("vuln.bulletins.fieldComponent")} value={detail.component || "—"} />
              <Field label={t("vuln.bulletins.fieldAffectedVersions")} value={detail.affectedVersions || "—"} />
              <Field label={t("vuln.bulletins.fieldFixedVersion")} value={<span className="font-mono">{detail.fixedVersion || "—"}</span>} />
              <Field label={t("vuln.bulletins.fieldAffectedAssets")} value={<span className="tabular-nums">{detail.affectedAssets ?? 0}</span>} />
              <Field label={t("vuln.bulletins.fieldSource")} value={detail.source || "—"} />
              <Field label={t("vuln.bulletins.fieldNotifiedAt")} value={<span className="tabular-nums">{detail.notifiedAt || "—"}</span>} />
            </div>

            {detail.description && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("vuln.bulletins.fieldDescription")}</div>
                <p className="text-sm leading-relaxed text-muted">{detail.description}</p>
              </div>
            )}
            {detail.fixSuggestion && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("vuln.bulletins.fieldFixSuggestion")}</div>
                <div className="rounded-r-control border-l-4 border-primary bg-primary/5 p-3 text-sm leading-relaxed text-ink">
                  {detail.fixSuggestion}
                </div>
              </div>
            )}
            {detail.workaround && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("vuln.bulletins.fieldWorkaround")}</div>
                <p className="text-sm leading-relaxed text-muted">{detail.workaround}</p>
              </div>
            )}
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!ack}
        title={t("vuln.bulletins.ackTitle")}
        desc={ack ? t("vuln.bulletins.ackConfirmDesc", { no: ack.bulletinNo }) : undefined}
        loading={ackMutation.isPending}
        onConfirm={() => ack && ackMutation.mutate(ack.id)}
        onCancel={() => setAck(null)}
      />
      <ConfirmDialog
        open={!!resolve}
        title={t("vuln.bulletins.resolveTitle")}
        desc={resolve ? t("vuln.bulletins.resolveConfirmDesc", { no: resolve.bulletinNo }) : undefined}
        loading={resolveMutation.isPending}
        onConfirm={() => resolve && resolveMutation.mutate(resolve.id)}
        onCancel={() => setResolve(null)}
      />
      <ConfirmDialog
        open={!!ignore}
        title={t("vuln.bulletins.ignoreTitle")}
        desc={ignore ? t("vuln.bulletins.ignoreConfirmDesc", { no: ignore.bulletinNo }) : undefined}
        loading={ignoreMutation.isPending}
        onConfirm={() => ignore && ignoreMutation.mutate(ignore.id)}
        onCancel={() => setIgnore(null)}
      />
      <ConfirmDialog
        open={!!reopen}
        title={t("vuln.bulletins.reopenTitle")}
        desc={reopen ? t("vuln.bulletins.reopenConfirmDesc", { no: reopen.bulletinNo }) : undefined}
        loading={reopenMutation.isPending}
        onConfirm={() => reopen && reopenMutation.mutate(reopen.id)}
        onCancel={() => setReopen(null)}
      />
    </>
  );
}
