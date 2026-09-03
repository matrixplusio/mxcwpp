"use client";
import { usePathname } from "next/navigation";
import { useTranslation } from "react-i18next";
import { TabLink } from "@/components/ui/Tabs";

export default function KubeLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const activeKey = pathname.replace(/^\/kube\/?/, "").split("/")[0] || "clusters";

  const navItems = [
    { key: "clusters", label: t("kube.tab.clusters"), href: "/kube/clusters" },
    { key: "alarms", label: t("kube.tab.alarms"), href: "/kube/alarms" },
    { key: "events", label: t("kube.tab.events"), href: "/kube/events" },
    { key: "baseline", label: t("kube.tab.baseline"), href: "/kube/baseline" },
    { key: "baseline-rules", label: t("kube.tab.baselineRules"), href: "/kube/baseline-rules" },
    { key: "whitelist", label: t("kube.tab.whitelist"), href: "/kube/whitelist" },
    { key: "image-scan", label: t("kube.tab.imageScan"), href: "/kube/image-scan" },
    { key: "registries", label: t("kube.tab.registries"), href: "/kube/registries" },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-xl font-bold text-ink">{t("kube.title")}</h1>
        <p className="mt-1 text-sm text-muted">{t("kube.desc")}</p>
      </div>
      <div className="overflow-x-auto pb-1">
        <TabLink items={navItems} activeKey={activeKey} />
      </div>
      <div className="mt-6">{children}</div>
    </div>
  );
}
