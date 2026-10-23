"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function AssetsLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/assets\/?/, "").split("/")[0] || "hosts";

  const navItems = [
    { key: "hosts", label: t("assets.tab.hosts"), href: "/assets/hosts" },
    { key: "fingerprint", label: t("assets.tab.fingerprint"), href: "/assets/fingerprint" },
    { key: "business-lines", label: t("assets.tab.businessLines"), href: "/assets/business-lines" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("assets.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("assets.desc")}</p>
      </div>
      <TabLink items={navItems} activeKey={activeKey} />
      <div className="mt-6">{children}</div>
    </div>
  );
}
