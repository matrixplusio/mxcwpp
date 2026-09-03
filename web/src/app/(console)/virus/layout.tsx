"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function VirusLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/virus\/?/, "").split("/")[0] || "scan";

  const navItems = [
    { key: "scan", label: t("virus.tab.scan"), href: "/virus/scan" },
    { key: "quarantine", label: t("virus.tab.quarantine"), href: "/virus/quarantine" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("virus.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("virus.desc")}</p>
      </div>
      <TabLink items={navItems} activeKey={activeKey} />
      <div className="mt-6">{children}</div>
    </div>
  );
}
