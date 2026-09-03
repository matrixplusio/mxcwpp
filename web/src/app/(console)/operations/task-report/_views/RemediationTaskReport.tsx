"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { CheckCircle2, XCircle, Clock, Percent, Timer } from "lucide-react";
import { reportsApi } from "@/lib/api/reports";
import type { DateRange } from "@/lib/api/reports";
import type { RemediationExecutiveReport } from "@/lib/api/types";
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

// ─── MTTR formatter ───────────────────────────────────────────────────────────

function formatMttr(hours: number): string {
  if (hours < 1 / 60) return `${Math.round(hours * 3600)}s`;
  if (hours < 1) return `${Math.round(hours * 60)}m`;
  if (hours < 24) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

// ─── Section sub-components ───────────────────────────────────────────────────

function StatisticsContent({ d }: { d: RemediationExecutiveReport }) {
  const { t } = useTranslation();
  const s = d.statistics;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatCard
          label={t("operations.taskReport.remediation.remediationRate")}
          value={`${s.remediationRate.toFixed(1)}%`}
          icon={Percent}
          tone="success"
          compact
        />
        <StatCard
          label={t("operations.taskReport.remediation.successRate")}
          value={`${s.successRate.toFixed(1)}%`}
          icon={CheckCircle2}
          tone="success"
          compact
        />
        <StatCard
          label={t("operations.taskReport.remediation.mttr")}
          value={formatMttr(s.mttrHours)}
          icon={Timer}
          compact
        />
        <StatCard
          label={t("operations.taskReport.remediation.pendingTasks")}
          value={s.pendingTasks}
          icon={Clock}
          tone="warning"
          compact
        />
        <StatCard
          label={t("operations.taskReport.remediation.failedTasks")}
          value={s.failedTasks}
          icon={XCircle}
          tone="danger"
          compact
        />
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm md:grid-cols-4">
        {(
          [
            [t("operations.taskReport.remediation.totalTasks"), s.totalTasks],
            [t("operations.taskReport.remediation.successTasks"), s.successTasks],
            [t("operations.taskReport.remediation.totalVulns"), s.totalVulns],
            [t("operations.taskReport.remediation.patchedVulns"), s.patchedVulns],
          ] as [string, number][]
        ).map(([label, value]) => (
          <div
            key={label}
            className="flex justify-between border-b border-border/40 py-1"
          >
            <span className="text-muted">{label}</span>
            <span className="tabular-nums text-ink">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function BySeverityContent({ d }: { d: RemediationExecutiveReport }) {
  const { t } = useTranslation();
  const items = d.statistics.bySeverity;
  if (!items || items.length === 0) return null;
  type Row = (typeof items)[number];
  const columns: Column<Row>[] = [
    {
      key: "severity",
      title: t("operations.taskReport.remediation.severity"),
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
      key: "total",
      title: t("operations.taskReport.remediation.total"),
      align: "right",
      render: (r) => r.total,
    },
    {
      key: "fixed",
      title: t("operations.taskReport.remediation.fixed"),
      align: "right",
      render: (r) => r.fixed,
    },
    {
      key: "rate",
      title: t("operations.taskReport.remediation.rate"),
      align: "right",
      render: (r) => `${r.rate.toFixed(1)}%`,
    },
  ];
  return (
    <DataTable columns={columns} rows={items} rowKey={(r) => r.severity} />
  );
}

function ByComponentContent({ d }: { d: RemediationExecutiveReport }) {
  const { t } = useTranslation();
  const items = d.statistics.byComponent;
  if (!items || items.length === 0) return null;
  type Row = (typeof items)[number];
  const columns: Column<Row>[] = [
    {
      key: "component",
      title: t("operations.taskReport.remediation.component"),
      render: (r) => (
        <span className="font-medium text-ink">{r.component}</span>
      ),
    },
    {
      key: "total",
      title: t("operations.taskReport.remediation.total"),
      align: "right",
      render: (r) => r.total,
    },
    {
      key: "fixed",
      title: t("operations.taskReport.remediation.fixed"),
      align: "right",
      render: (r) => r.fixed,
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={items}
      rowKey={(r) => r.component}
    />
  );
}

function HostDetailsContent({ d }: { d: RemediationExecutiveReport }) {
  const { t } = useTranslation();
  type Row = RemediationExecutiveReport["hostDetails"][number];
  const columns: Column<Row>[] = [
    {
      key: "hostname",
      title: t("operations.taskReport.remediation.hostname"),
      render: (r) => (
        <span className="font-medium text-ink">{r.hostname}</span>
      ),
    },
    {
      key: "ip",
      title: t("operations.taskReport.remediation.ip"),
      render: (r) => r.ip || "-",
    },
    {
      key: "total",
      title: t("operations.taskReport.remediation.hostTotal"),
      align: "right",
      render: (r) => r.total,
    },
    {
      key: "success",
      title: t("operations.taskReport.remediation.hostSuccess"),
      align: "right",
      render: (r) => r.success,
    },
    {
      key: "failed",
      title: t("operations.taskReport.remediation.hostFailed"),
      align: "right",
      render: (r) => r.failed,
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

function TaskDetailsContent({ d }: { d: RemediationExecutiveReport }) {
  const { t } = useTranslation();
  type Row = RemediationExecutiveReport["taskDetails"][number];
  const columns: Column<Row>[] = [
    {
      key: "cveId",
      title: t("operations.taskReport.remediation.cveId"),
      render: (r) => (
        <span className="font-mono text-sm text-ink">{r.cveId}</span>
      ),
    },
    {
      key: "hostname",
      title: t("operations.taskReport.remediation.hostname"),
      render: (r) => r.hostname || "-",
    },
    {
      key: "component",
      title: t("operations.taskReport.remediation.component"),
      render: (r) => r.component || "-",
    },
    {
      key: "status",
      title: t("operations.taskReport.remediation.status"),
      render: (r) => (
        <StatusTag
          tone={
            r.status === "success"
              ? "success"
              : r.status === "failed"
                ? "danger"
                : "neutral"
          }
        >
          {r.status}
        </StatusTag>
      ),
    },
    {
      key: "finishedAt",
      title: t("operations.taskReport.remediation.finishedAt"),
      render: (r) => r.finishedAt || "-",
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={d.taskDetails}
      rowKey={(r) => String(r.id)}
    />
  );
}

// ─── Detail renderer (shared by generate and saved paths) ─────────────────────

function RemediationDetailView({
  d,
  onBack,
}: {
  d: RemediationExecutiveReport;
  onBack: () => void;
}) {
  const { t } = useTranslation();

  return (
    <ExecutiveReport
      meta={{
        title: d.meta.reportTitle,
        subtitleEn: "Vulnerability Remediation Report",
        infoRows: [
          {
            label: t("operations.taskReport.remediation.infoReportId"),
            value: d.meta.reportId,
          },
          {
            label: t("operations.taskReport.remediation.infoGeneratedAt"),
            value: d.meta.generatedAt,
          },
          {
            label: t("operations.taskReport.remediation.infoReportPeriod"),
            value: d.meta.reportPeriod,
          },
          {
            label: t("operations.taskReport.remediation.infoCheckTarget"),
            value: d.meta.checkTarget,
          },
        ],
        company: d.meta.companyName || undefined,
      }}
      banner={{
        tone: d.summary.hasFailedTasks
          ? "danger"
          : d.summary.hasUnpatchedVulns
            ? "warning"
            : "success",
        text: d.summary.overallConclusion || d.summary.remediationOverview,
      }}
      sections={[
        {
          title: t("operations.taskReport.remediation.secStats"),
          content: <StatisticsContent d={d} />,
        },
        {
          title: t("operations.taskReport.remediation.secBySeverity"),
          content: <BySeverityContent d={d} />,
        },
        {
          title: t("operations.taskReport.remediation.secByComponent"),
          content: <ByComponentContent d={d} />,
        },
        {
          title: t("operations.taskReport.remediation.secHosts"),
          content:
            d.hostDetails && d.hostDetails.length > 0 ? (
              <HostDetailsContent d={d} />
            ) : null,
        },
        {
          title: t("operations.taskReport.remediation.secTasks"),
          content:
            d.taskDetails && d.taskDetails.length > 0 ? (
              <TaskDetailsContent d={d} />
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
      // No PDF endpoint for remediation
    />
  );
}

// ─── Generate sub-tab ─────────────────────────────────────────────────────────

function GenerateTab() {
  const { t } = useTranslation();
  const [range, setRange] = useState<DateRange>(lastNDays(30));
  const [queriedRange, setQueriedRange] = useState<DateRange | null>(null);

  const { data, isFetching, isError, error } = useQuery({
    queryKey: ["remediation-executive", queriedRange],
    queryFn: () => reportsApi.remediationExecutive(queriedRange!),
    enabled: !!queriedRange,
  });

  if (queriedRange && data) {
    return (
      <RemediationDetailView d={data} onBack={() => setQueriedRange(null)} />
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
            : t("operations.taskReport.remediation.generateBtn")}
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
          {t("operations.taskReport.remediation.loadingDetail")}
        </Card>
      );
    }
    const d = savedDetail as unknown as RemediationExecutiveReport;
    return <RemediationDetailView d={d} onBack={() => setViewingId(null)} />;
  }

  return (
    <SavedReportsList type="remediation" onView={(id) => setViewingId(id)} />
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

type SubTab = "generate" | "saved";

export function RemediationTaskReport() {
  const { t } = useTranslation();
  const [subTab, setSubTab] = useState<SubTab>("generate");

  const subTabItems = [
    {
      key: "generate",
      label: t("operations.taskReport.remediation.subTabGenerate"),
    },
    {
      key: "saved",
      label: t("operations.taskReport.remediation.subTabSavedReports"),
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
