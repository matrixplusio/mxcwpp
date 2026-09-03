"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function SystemLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/system\/?/, "").split("/")[0] || "users";

  const navItems = [
    { key: "users", label: t("system.tab.users"), href: "/system/users" },
    { key: "rbac", label: t("system.tab.rbac"), href: "/system/rbac" },
    { key: "notifications", label: t("system.tab.notifications"), href: "/system/notifications" },
    { key: "settings", label: t("system.tab.settings"), href: "/system/settings" },
    { key: "retention", label: t("system.tab.retention"), href: "/system/retention" },
    { key: "feature-flags", label: t("system.tab.featureFlags"), href: "/system/feature-flags" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("system.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("system.desc")}</p>
      </div>
      <TabLink items={navItems} activeKey={activeKey} />
      <div className="mt-6">{children}</div>
    </div>
  );
}
