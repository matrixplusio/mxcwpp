"use client";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/ui/PageHeader";
import { Tabs } from "@/components/ui/Tabs";
import { useUrlState } from "@/hooks/useUrlState";
import { BaselineTaskReport } from "./_views/BaselineTaskReport";
import { AntivirusTaskReport } from "./_views/AntivirusTaskReport";
import { VulnTaskReport } from "./_views/VulnTaskReport";
import { RemediationTaskReport } from "./_views/RemediationTaskReport";
import { KubeTaskReport } from "./_views/KubeTaskReport";

const TAB_KEYS = [
  "baseline",
  "antivirus",
  "vuln",
  "remediation",
  "container",
] as const;
type TabKey = (typeof TAB_KEYS)[number];

function ComingSoonPlaceholder({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center rounded-card border border-dashed border-border bg-surface py-24 text-muted">
      {label}
    </div>
  );
}

export default function TaskReportPage() {
  const { t } = useTranslation();
  const [urlState, setUrlState] = useUrlState({ tab: "baseline" });
  const activeTab = TAB_KEYS.includes(urlState.tab as TabKey)
    ? (urlState.tab as TabKey)
    : "baseline";

  const tabItems = [
    { key: "baseline", label: t("operations.taskReport.tabBaseline") },
    { key: "antivirus", label: t("operations.taskReport.tabAntivirus") },
    { key: "vuln", label: t("operations.taskReport.tabVuln") },
    { key: "remediation", label: t("operations.taskReport.tabRemediation") },
    { key: "container", label: t("operations.taskReport.tabContainer") },
  ];

  function renderActiveTab() {
    switch (activeTab) {
      case "baseline":
        return <BaselineTaskReport />;
      case "antivirus":
        return <AntivirusTaskReport />;
      case "vuln":
        return <VulnTaskReport />;
      case "remediation":
        return <RemediationTaskReport />;
      case "container":
        return <KubeTaskReport />;
    }
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title={t("operations.taskReport.pageTitle")}
        desc={t("operations.taskReport.pageDesc")}
      />
      <Tabs
        items={tabItems}
        active={activeTab}
        onChange={(key) => setUrlState({ tab: key })}
      />
      <div className="mt-4">{renderActiveTab()}</div>
    </div>
  );
}
