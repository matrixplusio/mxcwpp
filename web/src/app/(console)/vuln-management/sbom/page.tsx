"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Package } from "lucide-react";
import { vulnApi } from "@/lib/api/vuln";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import { EmptyState } from "@/components/ui/EmptyState";

export default function SbomPage() {
  const { t } = useTranslation();
  const { data, isLoading } = useQuery({ queryKey: ["sbom-projects"], queryFn: () => vulnApi.listSbomProjects() });
  const [importOpen, setImportOpen] = useState(false);
  const projects = data ?? [];

  return (
    <>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted">{t("vuln.sbom.subtitle")}</span>
          <Button onClick={() => setImportOpen(true)}>{t("vuln.sbom.import")}</Button>
        </div>

        {isLoading ? (
          <Card><div className="py-10 text-center text-muted">{t("common.loading")}</div></Card>
        ) : projects.length === 0 ? (
          <Card><EmptyState title={t("vuln.sbom.empty")} desc="" /></Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {projects.map((p) => (
              <Card key={p.projectName} className="p-5">
                <div className="mb-4 flex items-center gap-2">
                  <div className="flex h-9 w-9 items-center justify-center rounded-control bg-gradient-to-br from-primary/15 to-primary/5 text-primary">
                    <Package size={18} />
                  </div>
                  <span className="truncate text-base font-semibold text-ink">{p.projectName}</span>
                </div>
                <div className="grid grid-cols-2 gap-3 text-center">
                  <div><div className="text-xl font-bold text-ink tabular-nums">{p.componentCount}</div><div className="mt-0.5 text-xs text-muted">{t("vuln.sbom.componentCount")}</div></div>
                  <div><div className="text-xl font-bold text-ink tabular-nums">{p.vulnCount}</div><div className="mt-0.5 text-xs text-muted">{t("vuln.sbom.vulnCount")}</div></div>
                  <div><div className="text-xl font-bold text-danger tabular-nums">{p.criticalCount}</div><div className="mt-0.5 text-xs text-muted">{t("vuln.sbom.critical")}</div></div>
                  <div><div className="text-xl font-bold text-warning tabular-nums">{p.highCount}</div><div className="mt-0.5 text-xs text-muted">{t("vuln.sbom.high")}</div></div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>

      <Modal open={importOpen} onClose={() => setImportOpen(false)} title={t("vuln.sbom.importTitle")}
        footer={<Button variant="ghost" onClick={() => setImportOpen(false)}>{t("vuln.sbom.gotIt")}</Button>}>
        <div className="space-y-3 text-sm text-muted">
          <p>{t("vuln.sbom.importHint")}</p>
          <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink">curl -F file=@sbom.cdx.json \
  -F project=my-app \
  -H &quot;Authorization: Bearer $TOKEN&quot; \
  http://&lt;server&gt;/api/v1/sbom/import</pre>
          <p className="text-faint">{t("vuln.sbom.importNote")}</p>
        </div>
      </Modal>
    </>
  );
}
