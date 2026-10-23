"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function MonitoringLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/monitoring\/?/, "").split("/")[0] || "host";

  const navItems = [
    { key: "host", label: t("monitoring.tab.host"), href: "/monitoring/host" },
    { key: "services", label: t("monitoring.tab.services"), href: "/monitoring/services" },
    { key: "service-alerts", label: t("monitoring.tab.serviceAlerts"), href: "/monitoring/service-alerts" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("monitoring.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("monitoring.desc")}</p>
      </div>
      <TabLink items={navItems} activeKey={activeKey} />
      <div className="mt-6">{children}</div>
    </div>
  );
}
