"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function AlertCenterLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/alert-center\/?/, "").split("/")[0] || "alerts";

  const navItems = [
    { key: "alerts", label: t("alerts.tab.alerts"), href: "/alert-center/alerts" },
    { key: "whitelist", label: t("alerts.tab.whitelist"), href: "/alert-center/whitelist" },
    { key: "suggestions", label: t("alerts.tab.suggestions"), href: "/alert-center/suggestions" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("alerts.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("alerts.desc")}</p>
      </div>
      <TabLink items={navItems} activeKey={activeKey} />
      <div className="mt-6">{children}</div>
    </div>
  );
}
