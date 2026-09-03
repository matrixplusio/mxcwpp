"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function OperationsLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/operations\/?/, "").split("/")[0] || "components";

  const navItems = [
    { key: "components", label: t("operations.tab.components"), href: "/operations/components" },
    { key: "inspection", label: t("operations.tab.inspection"), href: "/operations/inspection" },
    { key: "backup", label: t("operations.tab.backup"), href: "/operations/backup" },
    { key: "migration", label: t("operations.tab.migration"), href: "/operations/migration" },
    { key: "reports", label: t("operations.tab.reports"), href: "/operations/reports" },
    { key: "task-report", label: t("operations.tab.taskReport"), href: "/operations/task-report" },
    { key: "install", label: t("operations.tab.install"), href: "/operations/install" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("operations.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("operations.desc")}</p>
      </div>
      <TabLink items={navItems} activeKey={activeKey} />
      <div className="mt-6">{children}</div>
    </div>
  );
}
