"use client";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Tabs } from "@/components/ui/Tabs";
import { Button } from "@/components/ui/Button";
import { RangePicker, lastNDays } from "@/components/ui/RangePicker";
import type { DateRange } from "@/components/ui/RangePicker";
import { useUrlState } from "@/hooks/useUrlState";
import { OverviewReport } from "./_views/OverviewReport";
import { AntivirusReport } from "./_views/AntivirusReport";
import { VulnerabilityReport } from "./_views/VulnerabilityReport";
import { KubeReport } from "./_views/KubeReport";
import { EdrReport } from "./_views/EdrReport";

const TAB_KEYS = ["overview", "antivirus", "vuln", "kube", "edr"] as const;
type TabKey = (typeof TAB_KEYS)[number];

function ComingSoonPlaceholder({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center rounded-card border border-dashed border-border bg-surface py-24 text-muted">
      {label}
    </div>
  );
}

export default function ReportsPage() {
  const { t } = useTranslation();
  const [urlState, setUrlState] = useUrlState({ tab: "overview" });
  const activeTab = TAB_KEYS.includes(urlState.tab as TabKey) ? (urlState.tab as TabKey) : "overview";

  const [range, setRange] = useState<DateRange>(() => lastNDays(7));
  const [refreshKey, setRefreshKey] = useState(0);

  const tabItems = [
    { key: "overview", label: t("operations.reports.tabOverview") },
    { key: "antivirus", label: t("operations.reports.tabAntivirus") },
    { key: "vuln", label: t("operations.reports.tabVuln") },
    { key: "kube", label: t("operations.reports.tabKube") },
    { key: "edr", label: t("operations.reports.tabEdr") },
  ];

  function handleRefresh() {
    setRefreshKey((k) => k + 1);
  }

  function renderActiveTab() {
    switch (activeTab) {
      case "overview":
        return <OverviewReport key={refreshKey} range={range} />;
      case "antivirus":
        return <AntivirusReport key={refreshKey} range={range} />;
      case "vuln":
        return <VulnerabilityReport key={refreshKey} range={range} />;
      case "kube":
        return <KubeReport key={refreshKey} range={range} />;
      case "edr":
        return <EdrReport key={refreshKey} range={range} />;
    }
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title={t("operations.reports.pageTitle")}
        desc={t("operations.reports.pageDesc")}
        extra={
          <div className="flex items-center gap-3">
            <RangePicker value={range} onChange={setRange} />
            <Button variant="ghost" onClick={handleRefresh}>
              <RefreshCw size={15} />
              {t("common.refresh")}
            </Button>
          </div>
        }
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
