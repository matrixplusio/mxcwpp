"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function DetectionLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/detection\/?/, "").split("/")[0] || "edr-events";

  const navItems = [
    { key: "edr-events", label: t("detection.tab.edrEvents"), href: "/detection/edr-events" },
    { key: "rules", label: t("detection.tab.rules"), href: "/detection/rules" },
    { key: "threat-intel", label: t("detection.tab.threatIntel"), href: "/detection/threat-intel" },
    { key: "intel-schedules", label: t("detection.tab.intelSchedules"), href: "/detection/intel-schedules" },
    { key: "storylines", label: t("detection.tab.storylines"), href: "/detection/storylines" },
    { key: "hunting", label: t("detection.tab.hunting"), href: "/detection/hunting" },
    { key: "anomaly", label: t("detection.tab.anomaly"), href: "/detection/anomaly" },
    { key: "bde", label: t("detection.tab.bde"), href: "/detection/bde" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("detection.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("detection.desc")}</p>
      </div>
      <div className="overflow-x-auto">
        <TabLink items={navItems} activeKey={activeKey} />
      </div>
      <div className="mt-6">{children}</div>
    </div>
  );
}
