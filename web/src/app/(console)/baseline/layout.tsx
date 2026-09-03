"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function BaselineLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/baseline\/?/, "").split("/")[0] || "policies";

  const navItems = [
    { key: "policies", label: t("baseline.tab.policies"), href: "/baseline/policies" },
    { key: "groups", label: t("baseline.tab.groups"), href: "/baseline/groups" },
    { key: "tasks", label: t("baseline.tab.tasks"), href: "/baseline/tasks" },
    { key: "fix", label: t("baseline.tab.fix"), href: "/baseline/fix" },
    { key: "fix-history", label: t("baseline.tab.fixHistory"), href: "/baseline/fix-history" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("baseline.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("baseline.desc")}</p>
      </div>
      <div className="overflow-x-auto pb-1">
        <TabLink items={navItems} activeKey={activeKey} />
      </div>
      <div className="mt-6">{children}</div>
    </div>
  );
}
