"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function VulnManagementLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/vuln-management\/?/, "").split("/")[0] || "list";

  const navItems = [
    { key: "bulletins", label: t("vuln.tab.bulletins"), href: "/vuln-management/bulletins" },
    { key: "list", label: t("vuln.tab.list"), href: "/vuln-management/list" },
    { key: "scan-schedules", label: t("vuln.tab.scanSchedules"), href: "/vuln-management/scan-schedules" },
    { key: "remediation", label: t("vuln.tab.remediation"), href: "/vuln-management/remediation" },
    { key: "remediation-tasks", label: t("vuln.tab.remediationTasks"), href: "/vuln-management/remediation-tasks" },
    { key: "remediation-policies", label: t("vuln.tab.remediationPolicies"), href: "/vuln-management/remediation-policies" },
    { key: "db", label: t("vuln.tab.db"), href: "/vuln-management/db" },
    { key: "data-sources", label: t("vuln.tab.dataSources"), href: "/vuln-management/data-sources" },
    { key: "sbom", label: t("vuln.tab.sbom"), href: "/vuln-management/sbom" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("vuln.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("vuln.desc")}</p>
      </div>
      <div className="overflow-x-auto pb-1">
        <TabLink items={navItems} activeKey={activeKey} />
      </div>
      <div className="mt-6">{children}</div>
    </div>
  );
}
