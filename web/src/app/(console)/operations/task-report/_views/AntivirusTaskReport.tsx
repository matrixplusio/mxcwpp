"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Shield, AlertTriangle, Archive, Trash2, Minus } from "lucide-react";
import { reportsApi } from "@/lib/api/reports";
import type { AntivirusExecutiveReport, VirusScanTask } from "@/lib/api/types";
import { ExecutiveReport } from "../_components/ExecutiveReport";
import { SavedReportsList } from "../_components/SavedReportsList";
import { DataTable } from "@/components/ui/DataTable";
import type { Column } from "@/components/ui/DataTable";
import { StatCard } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { StatusTag } from "@/components/ui/Tag";
import { Tabs } from "@/components/ui/Tabs";

// ─── Section sub-components ───────────────────────────────────────────────────

function TaskInfoContent({ d }: { d: AntivirusExecutiveReport }) {
  const { t } = useTranslation();
  const info = d.taskInfo;
  const rows: [string, string][] = [
    [t("operations.taskReport.antivirus.taskId"), String(info.taskId)],
    [t("operations.taskReport.antivirus.taskNameLabel"), info.taskName],
    [t("operations.taskReport.antivirus.scanTypeLabel"), info.scanType],
    [t("operations.taskReport.antivirus.hostCountLabel"), String(info.hostCount)],
    [t("operations.taskReport.antivirus.scannedHosts"), String(info.scannedHosts)],
    [t("operations.taskReport.antivirus.threatCountLabel"), String(info.threatCount)],
    [t("operations.taskReport.antivirus.startedAt"), info.startedAt ?? "-"],
    [t("operations.taskReport.antivirus.finishedAt"), info.finishedAt ?? "-"],
  ];
  return (
    <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm md:grid-cols-4">
      {rows.map(([label, value]) => (
        <div key={label} className="flex flex-col gap-0.5">
          <span className="text-xs text-faint">{label}</span>
          <span className="text-ink">{value}</span>
        </div>
      ))}
    </div>
  );
}

function StatisticsContent({ d }: { d: AntivirusExecutiveReport }) {
  const { t } = useTranslation();
  const s = d.statistics;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatCard
          label={t("operations.taskReport.antivirus.totalThreats")}
          value={s.totalThreats}
          icon={Shield}
          compact
        />
        <StatCard
          label={t("operations.taskReport.antivirus.detectedThreats")}
          value={s.detectedThreats}
          icon={AlertTriangle}
          tone="danger"
          compact
        />
        <StatCard
          label={t("operations.taskReport.antivirus.quarantinedThreats")}
          value={s.quarantinedThreats}
          icon={Archive}
          tone="warning"
          compact
        />
        <StatCard
          label={t("operations.taskReport.antivirus.deletedThreats")}
          value={s.deletedThreats}
          icon={Trash2}
          tone="danger"
          compact
        />
        <StatCard
          label={t("operations.taskReport.antivirus.ignoredThreats")}
          value={s.ignoredThreats}
          icon={Minus}
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

function ThreatTypeContent({ d }: { d: AntivirusExecutiveReport }) {
  const s = d.statistics;
  if (!s.byThreatType || Object.keys(s.byThreatType).length === 0) return null;
  return (
    <div className="space-y-2">
      {Object.entries(s.byThreatType).map(([type, cnt]) => {
        const total = Object.values(s.byThreatType).reduce((a, b) => a + b, 0);
        const pct = total > 0 ? Math.round(((cnt as number) / total) * 100) : 0;
        return (
          <div key={type} className="space-y-1">
            <div className="flex justify-between text-xs text-muted">
              <span>{type}</span>
              <span>
                {cnt as number} ({pct}%)
              </span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-surface-muted">
              <div
                className="h-1.5 rounded-full bg-danger transition-all"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function HostDetailsContent({ d }: { d: AntivirusExecutiveReport }) {
  const { t } = useTranslation();
  type HostDetail = AntivirusExecutiveReport["hostDetails"][number];
  const columns: Column<HostDetail>[] = [
    {
      key: "hostname",
      title: t("operations.taskReport.antivirus.hostname"),
      render: (r) => <span className="font-medium text-ink">{r.hostname}</span>,
    },
    {
      key: "ip",
      title: t("operations.taskReport.antivirus.ip"),
      render: (r) => r.ip || "-",
    },
    {
      key: "threatCount",
      title: t("operations.taskReport.antivirus.hostThreatCount"),
      align: "right",
      render: (r) => r.threatCount,
    },
    {
      key: "criticalCount",
      title: t("operations.taskReport.antivirus.hostCriticalCount"),
      align: "right",
      render: (r) => r.criticalCount,
    },
    {
      key: "highCount",
      title: t("operations.taskReport.antivirus.hostHighCount"),
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

function TopThreatsContent({ d }: { d: AntivirusExecutiveReport }) {
  const { t } = useTranslation();
  type TopThreat = AntivirusExecutiveReport["topThreats"][number];
  const columns: Column<TopThreat>[] = [
    {
      key: "threatName",
      title: t("operations.taskReport.antivirus.threatName"),
      render: (r) => <span className="font-medium text-ink">{r.threatName}</span>,
    },
    {
      key: "severity",
      title: t("operations.taskReport.antivirus.severity"),
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
      key: "count",
      title: t("operations.taskReport.antivirus.threatCount"),
      align: "right",
      render: (r) => r.count,
    },
    {
      key: "affectedHosts",
      title: t("operations.taskReport.antivirus.affectedHosts"),
      align: "right",
      render: (r) => r.affectedHosts,
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={d.topThreats}
      rowKey={(r) => r.threatName}
    />
  );
}

// ─── Detail renderer (shared by scan-task and saved-report paths) ─────────────

function AntivirusDetailView({
  d,
  onBack,
}: {
  d: AntivirusExecutiveReport;
  onBack: () => void;
}) {
  const { t } = useTranslation();

  const threatTypeContent = <ThreatTypeContent d={d} />;

  return (
    <ExecutiveReport
      meta={{
        title: d.meta.reportTitle,
        subtitleEn: "Antivirus Scan Report",
        infoRows: [
          {
            label: t("operations.taskReport.antivirus.infoScanType"),
            value: d.meta.scanType,
          },
          {
            label: t("operations.taskReport.antivirus.infoCheckTarget"),
            value: d.meta.checkTarget,
          },
          {
            label: t("operations.taskReport.antivirus.infoReportId"),
            value: d.meta.reportId,
          },
          {
            label: t("operations.taskReport.antivirus.infoGeneratedAt"),
            value: d.meta.generatedAt,
          },
        ],
        company: d.meta.companyName || undefined,
      }}
      banner={{
        tone: d.summary.hasCriticalThreat
          ? "danger"
          : d.summary.hasHighThreat
            ? "warning"
            : "success",
        text: d.summary.overallConclusion || d.summary.threatOverview,
      }}
      sections={[
        {
          title: t("operations.taskReport.antivirus.secTaskInfo"),
          content: <TaskInfoContent d={d} />,
        },
        {
          title: t("operations.taskReport.antivirus.secStats"),
          content: <StatisticsContent d={d} />,
        },
        {
          title: t("operations.taskReport.antivirus.secThreatType"),
          content: threatTypeContent,
        },
        {
          title: t("operations.taskReport.antivirus.secHosts"),
          content:
            d.hostDetails && d.hostDetails.length > 0 ? (
              <HostDetailsContent d={d} />
            ) : null,
        },
        {
          title: t("operations.taskReport.antivirus.secTopThreats"),
          content:
            d.topThreats && d.topThreats.length > 0 ? (
              <TopThreatsContent d={d} />
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
      // PDF omitted: /reports/antivirus/pdf is a module-level endpoint (requires
      // start_time/end_time range), not a per-task endpoint — no onExportPdf prop.
    />
  );
}

// ─── Scan Tasks sub-tab ───────────────────────────────────────────────────────

function ScanTasksTab() {
  const { t } = useTranslation();
  const [selectedTaskId, setSelectedTaskId] = useState<number | null>(null);

  const { data: tasksData, isLoading: tasksLoading } = useQuery({
    queryKey: ["antivirus-tasks"],
    queryFn: () => reportsApi.antivirusTasks(),
  });

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ["antivirus-executive", selectedTaskId],
    queryFn: () => reportsApi.antivirusExecutive(selectedTaskId!),
    enabled: !!selectedTaskId,
  });

  if (selectedTaskId) {
    if (detailLoading || !detail) {
      return (
        <Card className="p-10 text-center text-muted">
          {t("operations.taskReport.antivirus.loadingDetail")}
        </Card>
      );
    }
    return (
      <AntivirusDetailView d={detail} onBack={() => setSelectedTaskId(null)} />
    );
  }

  if (tasksLoading) {
    return (
      <Card className="p-10 text-center text-muted">
        {t("operations.taskReport.loading")}
      </Card>
    );
  }

  const tasks = tasksData?.items ?? [];

  if (tasks.length === 0) {
    return (
      <EmptyState
        title={t("operations.taskReport.antivirus.noTasks")}
        desc=""
      />
    );
  }

  const columns: Column<VirusScanTask>[] = [
    {
      key: "name",
      title: t("operations.taskReport.antivirus.taskName"),
      render: (r) => <span className="font-medium text-ink">{r.name}</span>,
    },
    {
      key: "scanType",
      title: t("operations.taskReport.antivirus.scanType"),
      render: (r) => r.scanType || "-",
    },
    {
      key: "totalHosts",
      title: t("operations.taskReport.antivirus.hostCount"),
      align: "right",
      render: (r) => r.totalHosts,
    },
    {
      key: "threatCount",
      title: t("operations.taskReport.antivirus.threatCount"),
      align: "right",
      render: (r) => r.threatCount,
    },
    {
      key: "finishedAt",
      title: t("operations.taskReport.antivirus.completedAt"),
      render: (r) => r.finishedAt ?? "-",
    },
    {
      key: "status",
      title: t("operations.taskReport.antivirus.status"),
      render: (r) => <StatusTag tone="success">{r.status}</StatusTag>,
    },
    {
      key: "actions",
      title: t("operations.taskReport.antivirus.actions"),
      render: (r) => (
        <Button variant="ghost" onClick={() => setSelectedTaskId(r.id)}>
          {t("operations.taskReport.antivirus.viewReport")}
        </Button>
      ),
    },
  ];

  return (
    <Card>
      <DataTable columns={columns} rows={tasks} rowKey={(r) => r.id} />
    </Card>
  );
}

// ─── Saved Reports sub-tab ────────────────────────────────────────────────────

function SavedReportsTab() {
  const { t } = useTranslation();
  const [viewingId, setViewingId] = useState<number | null>(null);

  const { data: savedDetail, isLoading: savedLoading } = useQuery({
    queryKey: ["saved-report-detail", viewingId],
    queryFn: () => reportsApi.getGenerated(viewingId!),
    enabled: !!viewingId,
  });

  if (viewingId) {
    if (savedLoading || !savedDetail) {
      return (
        <Card className="p-10 text-center text-muted">
          {t("operations.taskReport.antivirus.loadingDetail")}
        </Card>
      );
    }
    // The saved report shape is the stored executive JSON — same as AntivirusExecutiveReport.
    // Cast with type assertion and rely on optional chaining for resilience.
    const d = savedDetail as unknown as AntivirusExecutiveReport;
    return (
      <AntivirusDetailView d={d} onBack={() => setViewingId(null)} />
    );
  }

  return (
    <SavedReportsList type="antivirus" onView={(id) => setViewingId(id)} />
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

type SubTab = "scanTasks" | "savedReports";

export function AntivirusTaskReport() {
  const { t } = useTranslation();
  const [subTab, setSubTab] = useState<SubTab>("scanTasks");

  const subTabItems = [
    {
      key: "scanTasks",
      label: t("operations.taskReport.antivirus.subTabScanTasks"),
    },
    {
      key: "savedReports",
      label: t("operations.taskReport.antivirus.subTabSavedReports"),
    },
  ];

  return (
    <div className="space-y-4">
      <Tabs
        items={subTabItems}
        active={subTab}
        onChange={(key) => setSubTab(key as SubTab)}
      />
      <div>
        {subTab === "scanTasks" ? <ScanTasksTab /> : <SavedReportsTab />}
      </div>
    </div>
  );
}
