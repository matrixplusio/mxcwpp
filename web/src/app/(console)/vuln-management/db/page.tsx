"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Database, AlertTriangle, ShieldCheck, Cpu } from "lucide-react";
import { vulnApi } from "@/lib/api/vuln";
import type { VulnDbImport } from "@/lib/api/types";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import { StatusTag } from "@/components/ui/Tag";

function fmtSize(n: number): string {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}
function statusTone(s: string): "success" | "danger" | "warning" | "neutral" {
  if (s === "success" || s === "completed") return "success";
  if (s === "failed") return "danger";
  if (s === "pending" || s === "running") return "warning";
  return "neutral";
}

export default function VulnDbPage() {
  const { t } = useTranslation();
  const { data: stats, isError: statsError } = useQuery({ queryKey: ["vuln-db-stats"], queryFn: () => vulnApi.vulnDbStats() });
  const { data: imports, isLoading } = useQuery({ queryKey: ["vuln-db-imports"], queryFn: () => vulnApi.listVulnDbImports() });
  const [importOpen, setImportOpen] = useState(false);

  const columns: Column<VulnDbImport>[] = [
    { key: "fileName", title: t("vuln.db.colFileName"), render: (r) => <span className="font-medium text-ink">{r.fileName}</span> },
    { key: "fileSize", title: t("vuln.db.colFileSize"), render: (r) => <span className="text-muted tabular-nums">{fmtSize(r.fileSize)}</span> },
    { key: "status", title: t("common.status"), render: (r) => <StatusTag tone={statusTone(r.status)}>{r.status}</StatusTag> },
    { key: "importedCount", title: t("vuln.db.colImportedCount"), render: (r) => <span className="text-ink tabular-nums">{r.importedCount}</span> },
    { key: "createdBy", title: t("vuln.db.colCreatedBy"), render: (r) => <span className="text-faint">{r.createdBy || "—"}</span> },
    { key: "createdAt", title: t("common.time"), align: "right", render: (r) => <span className="text-faint tabular-nums">{r.createdAt}</span> },
  ];

  return (
    <>
      <div className="space-y-5">
        <div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatCard compact label={t("vuln.db.statTotal")} value={stats?.totalCount ?? 0} error={statsError} icon={Database} tone="default" />
            <StatCard compact label={t("vuln.db.statUnpatched")} value={stats?.unpatchedCount ?? 0} error={statsError} icon={AlertTriangle} tone="warning" />
            <StatCard compact label={t("vuln.db.statPatched")} value={stats?.patchedCount ?? 0} error={statsError} icon={ShieldCheck} tone="success" />
            <StatCard compact label={t("vuln.db.statMode")} value={stats?.mode ?? "—"} error={statsError} icon={Cpu} tone="default" />
          </div>
          {stats?.lastUpdated && <p className="mt-2 text-xs text-faint">{t("vuln.db.lastUpdated", { time: stats.lastUpdated })}</p>}
        </div>

        <Card>
          <CardHeader title={t("vuln.db.importRecords")} extra={<Button onClick={() => setImportOpen(true)}>{t("vuln.db.import")}</Button>} />
          <DataTable columns={columns} rows={imports?.items ?? []} rowKey={(r) => r.id} loading={isLoading} emptyText={t("vuln.db.empty")} />
          <Pagination page={1} pageSize={imports?.items?.length || 20} total={imports?.total ?? 0} onChange={() => {}} />
        </Card>
      </div>

      <Modal open={importOpen} onClose={() => setImportOpen(false)} title={t("vuln.db.importTitle")}
        footer={<Button variant="ghost" onClick={() => setImportOpen(false)}>{t("vuln.db.gotIt")}</Button>}>
        <div className="space-y-3 text-sm text-muted">
          <p>{t("vuln.db.importHint")}</p>
          <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink">curl -F file=@vuln-db.tar.gz \
  -H &quot;Authorization: Bearer $TOKEN&quot; \
  http://&lt;server&gt;/api/v1/vulnerabilities/cache/imports</pre>
          <p className="text-faint">{t("vuln.db.importNote")}</p>
        </div>
      </Modal>
    </>
  );
}
