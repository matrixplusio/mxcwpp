"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function FimLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/fim\/?/, "").split("/")[0] || "dashboard";

  const navItems = [
    { key: "dashboard", label: t("fim.tab.dashboard"), href: "/fim/dashboard" },
    { key: "policies", label: t("fim.tab.policies"), href: "/fim/policies" },
    { key: "events", label: t("fim.tab.events"), href: "/fim/events" },
    { key: "tasks", label: t("fim.tab.tasks"), href: "/fim/tasks" },
    { key: "baselines", label: t("fim.tab.baselines"), href: "/fim/baselines" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("fim.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("fim.desc")}</p>
      </div>
      <div className="overflow-x-auto">
        <TabLink items={navItems} activeKey={activeKey} />
      </div>
      <div className="mt-6">{children}</div>
    </div>
  );
}
