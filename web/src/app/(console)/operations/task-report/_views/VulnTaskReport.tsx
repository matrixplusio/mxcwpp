"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ShieldAlert, ShieldCheck, EyeOff, Server } from "lucide-react";
import { reportsApi } from "@/lib/api/reports";
import type { DateRange } from "@/lib/api/reports";
import type { VulnExecutiveReport } from "@/lib/api/types";
import { ExecutiveReport } from "../_components/ExecutiveReport";
import { SavedReportsList } from "../_components/SavedReportsList";
import { DataTable } from "@/components/ui/DataTable";
import type { Column } from "@/components/ui/DataTable";
import { StatCard } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { StatusTag } from "@/components/ui/Tag";
import { Tabs } from "@/components/ui/Tabs";
import { RangePicker, lastNDays } from "@/components/ui/RangePicker";

// ─── Section sub-components ───────────────────────────────────────────────────

function StatisticsContent({ d }: { d: VulnExecutiveReport }) {
  const { t } = useTranslation();
  const s = d.statistics;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatCard
          label={t("operations.taskReport.vuln.totalVulns")}
          value={s.totalVulns}
          icon={ShieldAlert}
          compact
        />
        <StatCard
          label={t("operations.taskReport.vuln.unpatchedVulns")}
          value={s.unpatchedVulns}
          icon={ShieldAlert}
          tone="danger"
          compact
        />
        <StatCard
          label={t("operations.taskReport.vuln.fixedVulns")}
          value={s.fixedVulns}
          icon={ShieldCheck}
          tone="success"
          compact
        />
        <StatCard
          label={t("operations.taskReport.vuln.ignoredVulns")}
          value={s.ignoredVulns}
          icon={EyeOff}
          compact
        />
        <StatCard
          label={t("operations.taskReport.vuln.affectedHosts")}
          value={s.affectedHosts}
          icon={Server}
          tone="warning"
          compact
        />
      </div>
      {Object.keys(s.bySeverity).length > 0 && (
        <div className="space-y-2">
          <p className="text-xs uppercase tracking-wide text-faint">
            {t("operations.taskReport.distSeverity")}
          </p>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm md:grid-cols-4">
            {Object.entries(s.bySeverity).map(([sev, cnt]) => (
              <div
                key={sev}
                className="flex justify-between border-b border-border/40 py-1"
              >
                <span className="capitalize text-muted">
                  {t(`common.severity.${sev}`, { defaultValue: sev })}
                </span>
                <span className="tabular-nums text-ink">{cnt}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ComponentDistContent({ d }: { d: VulnExecutiveReport }) {
  const items = d.statistics.byComponent;
  if (!items || items.length === 0) return null;
  const total = items.reduce((a, b) => a + b.count, 0);
  return (
    <div className="space-y-2">
      {items.slice(0, 15).map((item) => {
        const pct = total > 0 ? Math.round((item.count / total) * 100) : 0;
        return (
          <div key={item.component} className="space-y-1">
            <div className="flex justify-between text-xs text-muted">
              <span>{item.component}</span>
              <span>
                {item.count} ({pct}%)
              </span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-surface-muted">
              <div
                className="h-1.5 rounded-full bg-warning transition-all"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function HostDetailsContent({ d }: { d: VulnExecutiveReport }) {
  const { t } = useTranslation();
  type Row = VulnExecutiveReport["hostDetails"][number];
  const columns: Column<Row>[] = [
    {
      key: "hostname",
      title: t("operations.taskReport.vuln.hostname"),
      render: (r) => <span className="font-medium text-ink">{r.hostname}</span>,
    },
    {
      key: "ip",
      title: t("operations.taskReport.vuln.ip"),
      render: (r) => r.ip || "-",
    },
    {
      key: "vulnCount",
      title: t("operations.taskReport.vuln.vulnCount"),
      align: "right",
      render: (r) => r.vulnCount,
    },
    {
      key: "criticalCount",
      title: t("operations.taskReport.vuln.criticalCount"),
      align: "right",
      render: (r) => r.criticalCount,
    },
    {
      key: "highCount",
      title: t("operations.taskReport.vuln.highCount"),
      align: "right",
      render: (r) => r.highCount,
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={d.hostDetails}
      rowKey={(r) => r.hostId}
    />
  );
}

function TopVulnsContent({ d }: { d: VulnExecutiveReport }) {
  const { t } = useTranslation();
  type Row = VulnExecutiveReport["topVulns"][number];
  const columns: Column<Row>[] = [
    {
      key: "cveId",
      title: t("operations.taskReport.vuln.cveId"),
      render: (r) => (
        <span className="font-mono text-sm text-ink">{r.cveId}</span>
      ),
    },
    {
      key: "severity",
      title: t("operations.taskReport.vuln.severity"),
      render: (r) => (
        <StatusTag
          tone={
            r.severity === "critical"
              ? "danger"
              : r.severity === "high"
                ? "warning"
                : "neutral"
          }
        >
          {t(`common.severity.${r.severity}`, { defaultValue: r.severity })}
        </StatusTag>
      ),
    },
    {
      key: "cvssScore",
      title: t("operations.taskReport.vuln.cvssScore"),
      align: "right",
      render: (r) => r.cvssScore?.toFixed(1) ?? "-",
    },
    {
      key: "component",
      title: t("operations.taskReport.vuln.component"),
      render: (r) => r.component || "-",
    },
    {
      key: "affectedHosts",
      title: t("operations.taskReport.vuln.affectedHostsCol"),
      align: "right",
      render: (r) => r.affectedHosts,
    },
    {
      key: "description",
      title: t("operations.taskReport.vuln.description"),
      render: (r) => (
        <span className="line-clamp-2 text-sm text-muted">
          {r.description || "-"}
        </span>
      ),
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={d.topVulns}
      rowKey={(r) => r.cveId}
    />
  );
}

// ─── Detail renderer (shared by generate and saved paths) ─────────────────────

function VulnDetailView({
  d,
  range,
  onBack,
}: {
  d: VulnExecutiveReport;
  range?: DateRange;
  onBack: () => void;
}) {
  const { t } = useTranslation();
  const [exporting, setExporting] = useState(false);

  async function handleExport() {
    if (!range) return;
    setExporting(true);
    try {
      await reportsApi.downloadPdf(
        "/reports/vulnerability/pdf",
        { start_time: range.start, end_time: range.end },
        "vuln-report.pdf",
      );
    } finally {
      setExporting(false);
    }
  }

  return (
    <ExecutiveReport
      meta={{
        title: d.meta.reportTitle,
        subtitleEn: "Vulnerability Assessment Report",
        infoRows: [
          {
            label: t("operations.taskReport.vuln.infoReportId"),
            value: d.meta.reportId,
          },
          {
            label: t("operations.taskReport.vuln.infoGeneratedAt"),
            value: d.meta.generatedAt,
          },
          {
            label: t("operations.taskReport.vuln.infoReportPeriod"),
            value: d.meta.reportPeriod,
          },
          {
            label: t("operations.taskReport.vuln.infoCheckTarget"),
            value: d.meta.checkTarget,
          },
          {
            label: t("operations.taskReport.vuln.infoComplianceRate"),
            value: `${d.summary.complianceRate.toFixed(1)}%`,
          },
        ],
        company: d.meta.companyName || undefined,
      }}
      banner={{
        tone: d.summary.hasCriticalVuln
          ? "danger"
          : d.summary.hasHighVuln
            ? "warning"
            : "success",
        text: d.summary.overallConclusion || d.summary.vulnOverview,
      }}
      sections={[
        {
          title: t("operations.taskReport.vuln.secPeriod"),
          content: <p className="text-sm text-ink">{d.meta.reportPeriod}</p>,
        },
        {
          title: t("operations.taskReport.vuln.secStats"),
          content: <StatisticsContent d={d} />,
        },
        {
          title: t("operations.taskReport.vuln.secComponents"),
          content: <ComponentDistContent d={d} />,
        },
        {
          title: t("operations.taskReport.vuln.secHosts"),
          content:
            d.hostDetails && d.hostDetails.length > 0 ? (
              <HostDetailsContent d={d} />
            ) : null,
        },
        {
          title: t("operations.taskReport.vuln.secTopVulns"),
          content:
            d.topVulns && d.topVulns.length > 0 ? (
              <TopVulnsContent d={d} />
            ) : null,
        },
      ]}
      recommendation={
        d.recommendation
          ? {
              assessment: d.recommendation.overallAssessment,
              suggestions: d.recommendation.actionSuggestions ?? [],
              disclaimer: d.recommendation.disclaimer || undefined,
            }
          : undefined
      }
      onBack={onBack}
      onExportPdf={range ? handleExport : undefined}
      exporting={exporting}
    />
  );
}

// ─── Generate sub-tab ─────────────────────────────────────────────────────────

function GenerateTab() {
  const { t } = useTranslation();
  const [range, setRange] = useState<DateRange>(lastNDays(30));
  const [queriedRange, setQueriedRange] = useState<DateRange | null>(null);

  const { data, isFetching, isError, error } = useQuery({
    queryKey: ["vuln-executive", queriedRange],
    queryFn: () => reportsApi.vulnExecutive(queriedRange!),
    enabled: !!queriedRange,
  });

  if (queriedRange && data) {
    return (
      <VulnDetailView
        d={data}
        range={queriedRange}
        onBack={() => setQueriedRange(null)}
      />
    );
  }

  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-center gap-3">
        <RangePicker value={range} onChange={setRange} />
        <Button
          variant="primary"
          onClick={() => setQueriedRange({ ...range })}
          disabled={isFetching}
        >
          {isFetching
            ? t("operations.taskReport.loading")
            : t("operations.taskReport.vuln.generateBtn")}
        </Button>
      </div>
      {isError && (
        <p className="mt-4 text-sm text-danger">
          {(error as Error)?.message ?? t("operations.taskReport.emptyData")}
        </p>
      )}
    </Card>
  );
}

// ─── Saved Reports sub-tab ────────────────────────────────────────────────────

function SavedTab() {
  const { t } = useTranslation();
  const [viewingId, setViewingId] = useState<number | null>(null);

  const { data: savedDetail, isLoading } = useQuery({
    queryKey: ["saved-report-detail", viewingId],
    queryFn: () => reportsApi.getGenerated(viewingId!),
    enabled: !!viewingId,
  });

  if (viewingId) {
    if (isLoading || !savedDetail) {
      return (
        <Card className="p-10 text-center text-muted">
          {t("operations.taskReport.vuln.loadingDetail")}
        </Card>
      );
    }
    const d = savedDetail as unknown as VulnExecutiveReport;
    return <VulnDetailView d={d} onBack={() => setViewingId(null)} />;
  }

  return (
    <SavedReportsList type="vulnerability" onView={(id) => setViewingId(id)} />
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

type SubTab = "generate" | "saved";

export function VulnTaskReport() {
  const { t } = useTranslation();
  const [subTab, setSubTab] = useState<SubTab>("generate");

  const subTabItems = [
    {
      key: "generate",
      label: t("operations.taskReport.vuln.subTabGenerate"),
    },
    {
      key: "saved",
      label: t("operations.taskReport.vuln.subTabSavedReports"),
    },
  ];

  return (
    <div className="space-y-4">
      <Tabs
        items={subTabItems}
        active={subTab}
        onChange={(key) => setSubTab(key as SubTab)}
      />
      <div>{subTab === "generate" ? <GenerateTab /> : <SavedTab />}</div>
    </div>
  );
}
