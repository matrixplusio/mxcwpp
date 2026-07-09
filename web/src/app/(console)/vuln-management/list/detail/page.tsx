"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ArrowLeft } from "lucide-react";
import { vulnApi } from "@/lib/api/vuln";
import type { Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { EmptyState } from "@/components/ui/EmptyState";
import { toast } from "@/components/ui/toast";

interface AffectedHost {
  hostId: string;
  hostname: string;
  ip: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";
const KNOWN_SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const isSeverity = (s: string): s is Severity => (KNOWN_SEVERITIES as string[]).includes(s);

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs uppercase tracking-wide text-faint">{label}</span>
      <span className="text-sm text-ink break-words">{value}</span>
    </div>
  );
}

export default function VulnDetailPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [vulnId, setVulnId] = useState<number | null>(null);
  const [ignoring, setIgnoring] = useState(false);
  const [unignoring, setUnignoring] = useState(false);

  useEffect(() => {
    const raw = new URLSearchParams(window.location.search).get("id");
    setVulnId(raw ? Number(raw) : null);
  }, []);

  const { data: detail, isLoading } = useQuery({
    queryKey: ["vuln-detail", vulnId],
    queryFn: () => vulnApi.getVuln(vulnId as number),
    enabled: vulnId != null,
  });

  const statusMeta: Record<string, { tone: Tone; label: string }> = {
    unpatched: { tone: "danger", label: t("vuln.status.unpatched") },
    patched: { tone: "success", label: t("vuln.status.patched") },
    ignored: { tone: "neutral", label: t("vuln.status.ignored") },
  };
  const statusTag = (status: string) => {
    const meta = statusMeta[status] ?? { tone: "neutral" as Tone, label: status || "—" };
    return <StatusTag tone={meta.tone}>{meta.label}</StatusTag>;
  };

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["vuln-list"] });
    queryClient.invalidateQueries({ queryKey: ["vuln-detail"] });
  };
  const ignoreMutation = useMutation({
    mutationFn: (id: number) => vulnApi.ignoreVuln(id),
    onSuccess: () => {
      invalidate();
      setIgnoring(false);
      toast.success(t("vuln.list.ignored"));
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const unignoreMutation = useMutation({
    mutationFn: (id: number) => vulnApi.unignoreVuln(id),
    onSuccess: () => {
      invalidate();
      setUnignoring(false);
      toast.success(t("vuln.list.unignored"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const hostColumns: Column<AffectedHost>[] = [
    {
      key: "hostname",
      title: t("vuln.list.colAffectedHostName"),
      render: (r) => <span className="text-ink">{r.hostname || r.hostId}</span>,
    },
    {
      key: "ip",
      title: "IP",
      render: (r) => <span className="font-mono text-xs text-muted tabular-nums">{r.ip || "—"}</span>,
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => router.push("/vuln-management/list")}
          className="inline-flex h-8 w-8 items-center justify-center rounded-control border border-border text-muted hover:text-ink"
          aria-label={t("common.back")}
        >
          <ArrowLeft size={16} />
        </button>
        <h1 className="text-lg font-semibold text-ink">{t("vuln.list.detailTitle")}</h1>
        {detail && <span className="font-mono font-medium text-ink">{detail.cveId}</span>}
        {detail && (isSeverity(detail.severity) ? <SeverityTag level={detail.severity} /> : <StatusTag tone="neutral">{detail.severity}</StatusTag>)}
        {detail && statusTag(detail.status)}
        <div className="ml-auto">
          {detail && detail.status === "ignored" ? (
            <Button variant="ghost" onClick={() => setUnignoring(true)}>{t("vuln.list.actionUnignore")}</Button>
          ) : detail ? (
            <Button onClick={() => setIgnoring(true)}>{t("vuln.list.actionIgnore")}</Button>
          ) : null}
        </div>
      </div>

      {!detail && !isLoading ? (
        <EmptyState title={t("vuln.list.empty")} />
      ) : detail ? (
        <>
          <Card>
            <div className="grid grid-cols-2 gap-x-6 gap-y-4 p-5 md:grid-cols-5">
              <Field label="CVSS" value={<span className="tabular-nums">{detail.cvssScore?.toFixed(1) ?? "—"}</span>} />
              <Field label={t("vuln.list.fieldComponent")} value={<span className="break-all">{detail.component || "—"}</span>} />
              <Field label={t("vuln.list.fieldCurrentVersion")} value={<span className="font-mono">{detail.currentVersion || "—"}</span>} />
              <Field label={t("vuln.list.fieldFixedVersion")} value={<span className="font-mono">{detail.fixedVersion || "—"}</span>} />
              <Field label={t("vuln.list.fieldAffectedHosts")} value={<span className="tabular-nums">{detail.affectedHosts ?? 0}</span>} />
            </div>
            {detail.description && (
              <div className="border-t border-border px-5 py-4">
                <div className="mb-1 text-xs uppercase tracking-wide text-faint">{t("vuln.list.fieldDescription")}</div>
                <p className="text-sm leading-relaxed text-ink/80">{detail.description}</p>
              </div>
            )}
          </Card>

          <div>
            <h3 className="mb-2 text-sm font-semibold text-ink">
              {t("vuln.list.affectedHostsTitle")}
              <span className="ml-2 text-xs font-normal text-faint tabular-nums">{detail.hosts?.length ?? 0}</span>
            </h3>
            <Card>
              <DataTable
                columns={hostColumns}
                rows={(detail.hosts ?? []) as AffectedHost[]}
                rowKey={(r) => r.hostId}
                emptyText={t("vuln.list.noAffectedHosts")}
              />
            </Card>
          </div>
        </>
      ) : null}

      <ConfirmDialog
        open={ignoring}
        title={t("vuln.list.ignoreTitle")}
        desc={detail ? t("vuln.list.ignoreConfirmDesc", { cve: detail.cveId }) : undefined}
        loading={ignoreMutation.isPending}
        onConfirm={() => detail && ignoreMutation.mutate(detail.id)}
        onCancel={() => setIgnoring(false)}
      />
      <ConfirmDialog
        open={unignoring}
        title={t("vuln.list.unignoreTitle")}
        desc={detail ? t("vuln.list.unignoreConfirmDesc", { cve: detail.cveId }) : undefined}
        loading={unignoreMutation.isPending}
        onConfirm={() => detail && unignoreMutation.mutate(detail.id)}
        onCancel={() => setUnignoring(false)}
      />
    </div>
  );
}
