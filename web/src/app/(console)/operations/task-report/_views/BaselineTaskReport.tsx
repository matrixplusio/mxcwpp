"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { CheckCircle, XCircle, AlertTriangle, Minus, ClipboardList } from "lucide-react";
import { reportsApi } from "@/lib/api/reports";
import type { ExecutiveTaskReport, BaselineTask } from "@/lib/api/types";
import { ExecutiveReport } from "../_components/ExecutiveReport";
import { DataTable } from "@/components/ui/DataTable";
import type { Column } from "@/components/ui/DataTable";
import { StatCard } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/EmptyState";
import { StatusTag } from "@/components/ui/Tag";

// ─── Section sub-components ───────────────────────────────────────────────────

function SummaryContent({ d }: { d: ExecutiveTaskReport }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-4">
      {d.summary.check_scope && (
        <p className="text-sm text-ink">{d.summary.check_scope}</p>
      )}
      <div className="flex items-center gap-2 text-sm">
        <span className="text-muted">
          {t("operations.taskReport.baseline.complianceRate")}:
        </span>
        <span className="font-semibold text-ink">
          {d.summary.compliance_rate.toFixed(1)}%
        </span>
      </div>
      {d.category_stats.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs uppercase tracking-wide text-faint">
            {t("operations.taskReport.baseline.categoryPassRate")}
          </p>
          {d.category_stats.map((cs) => (
            <div key={cs.category} className="space-y-1">
              <div className="flex justify-between text-xs text-muted">
                <span>{cs.category_name}</span>
                <span>{cs.pass_rate.toFixed(1)}%</span>
              </div>
              <div className="h-1.5 w-full rounded-full bg-surface-muted">
                <div
                  className="h-1.5 rounded-full bg-success transition-all"
                  style={{ width: `${Math.min(Math.max(cs.pass_rate, 0), 100)}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
      {d.summary.coverage_note && (
        <p className="text-xs text-muted">{d.summary.coverage_note}</p>
      )}
    </div>
  );
}

function TaskInfoContent({ d }: { d: ExecutiveTaskReport }) {
  const { t } = useTranslation();
  const info = d.task_info;
  const rows: [string, string][] = [
    [t("operations.taskReport.baseline.taskNameLabel"), info.task_name],
    [t("operations.taskReport.baseline.policyName"), info.policy_name],
    [t("operations.taskReport.baseline.executedAt"), info.executed_at ?? "-"],
    [t("operations.taskReport.baseline.completedAtLabel"), info.completed_at ?? "-"],
    [t("operations.taskReport.baseline.hostCountLabel"), String(info.host_count)],
    [t("operations.taskReport.baseline.ruleCount"), String(info.rule_count)],
    [t("operations.taskReport.baseline.statusLabel"), info.status],
  ];
  return (
    <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm md:grid-cols-3">
      {rows.map(([label, value]) => (
        <div key={label} className="flex flex-col gap-0.5">
          <span className="text-xs text-faint">{label}</span>
          <span className="text-ink">{value}</span>
        </div>
      ))}
    </div>
  );
}

function StatisticsContent({ d }: { d: ExecutiveTaskReport }) {
  const { t } = useTranslation();
  const s = d.statistics;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatCard
          label={t("operations.taskReport.baseline.passedChecks")}
          value={s.passed_checks}
          icon={CheckCircle}
          tone="success"
          compact
        />
        <StatCard
          label={t("operations.taskReport.baseline.failedChecks")}
          value={s.failed_checks}
          icon={XCircle}
          tone="danger"
          compact
        />
        <StatCard
          label={t("operations.taskReport.baseline.warningChecks")}
          value={s.warning_checks}
          icon={AlertTriangle}
          tone="warning"
          compact
        />
        <StatCard
          label={t("operations.taskReport.baseline.naChecks")}
          value={s.na_checks}
          icon={Minus}
          compact
        />
        <StatCard
          label={t("operations.taskReport.baseline.totalChecks")}
          value={s.total_checks}
          icon={ClipboardList}
          compact
        />
      </div>
      {/* pass_rate is already 0-100 from backend, do NOT ×100 */}
      <div className="flex items-center gap-2 text-sm">
        <span className="text-muted">
          {t("operations.taskReport.baseline.passRate")}:
        </span>
        <span className="font-semibold text-ink">
          {s.pass_rate.toFixed(1)}%
        </span>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm md:grid-cols-4">
        {Object.entries(s.by_severity).map(([sev, cnt]) => (
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
  );
}

function ScoreContent({ d }: { d: ExecutiveTaskReport }) {
  const sc = d.security_score;
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-4">
        <div
          className="flex h-16 w-16 shrink-0 items-center justify-center rounded-full border-4 text-2xl font-bold"
          style={{ borderColor: sc.grade_color, color: sc.grade_color }}
        >
          {Math.round(sc.score)}
        </div>
        <div>
          <div className="text-lg font-bold" style={{ color: sc.grade_color }}>
            {sc.grade}
          </div>
          <div className="text-sm text-muted">{sc.score_explanation}</div>
        </div>
      </div>
      {sc.security_note && (
        <p className="text-sm text-ink">{sc.security_note}</p>
      )}
    </div>
  );
}

function RiskItemsContent({ d }: { d: ExecutiveTaskReport }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-3">
      {d.risk_items.map((r, i) => (
        <div
          key={i}
          className="space-y-1 rounded-control border border-border p-3 text-sm"
        >
          <div className="flex items-start gap-2">
            <span className="font-medium text-ink">{r.description}</span>
            <span className="ml-auto shrink-0 text-xs font-medium text-muted">
              {r.severity_label || r.severity}
            </span>
          </div>
          {r.impact && <p className="text-muted">{r.impact}</p>}
          {r.recommendation && (
            <p className="text-xs text-faint">{r.recommendation}</p>
          )}
          <p className="text-xs text-faint">
            {t("operations.taskReport.baseline.affectedCount")}: {r.affected_count}
          </p>
        </div>
      ))}
    </div>
  );
}

function HostDetailsContent({ d }: { d: ExecutiveTaskReport }) {
  const { t } = useTranslation();
  const columns: Column<ExecutiveTaskReport["host_details"][number]>[] = [
    {
      key: "hostname",
      title: t("operations.taskReport.baseline.hostname"),
      render: (r) => <span className="font-medium text-ink">{r.hostname}</span>,
    },
    {
      key: "ip",
      title: t("operations.taskReport.baseline.ip"),
      render: (r) => r.ip || "-",
    },
    {
      key: "os_family",
      title: t("operations.taskReport.baseline.osFamily"),
      render: (r) => r.os_family || "-",
    },
    {
      key: "score",
      title: t("operations.taskReport.baseline.hostScore"),
      align: "right",
      render: (r) => Math.round(r.score),
    },
    {
      key: "passed",
      title: t("operations.taskReport.baseline.passedChecks"),
      align: "right",
      render: (r) => r.passed_count,
    },
    {
      key: "failed",
      title: t("operations.taskReport.baseline.failedChecks"),
      align: "right",
      render: (r) => r.failed_count,
    },
    {
      key: "status",
      title: t("operations.taskReport.baseline.hostStatus"),
      render: (r) => (
        <StatusTag tone="neutral">{r.status}</StatusTag>
      ),
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={d.host_details}
      rowKey={(r) => r.host_id}
    />
  );
}

function CoverageContent({ d }: { d: ExecutiveTaskReport }) {
  const { t } = useTranslation();
  const cov = d.coverage;
  return (
    <div className="space-y-4 text-sm">
      {cov.baseline_source && (
        <div>
          <p className="text-xs text-faint">
            {t("operations.taskReport.baseline.baselineSource")}
          </p>
          <p className="text-ink">{cov.baseline_source}</p>
        </div>
      )}
      {cov.covered_areas.length > 0 && (
        <div>
          <p className="mb-1 text-xs uppercase tracking-wide text-faint">
            {t("operations.taskReport.baseline.coveredAreas")}
          </p>
          <ul className="list-disc space-y-0.5 pl-5 text-ink">
            {cov.covered_areas.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
        </div>
      )}
      {cov.uncovered_areas.length > 0 && (
        <div>
          <p className="mb-1 text-xs uppercase tracking-wide text-faint">
            {t("operations.taskReport.baseline.uncoveredAreas")}
          </p>
          <ul className="list-disc space-y-0.5 pl-5 text-muted">
            {cov.uncovered_areas.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
        </div>
      )}
      {cov.improvement_note && (
        <p className="text-muted">{cov.improvement_note}</p>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function BaselineTaskReport() {
  const { t } = useTranslation();
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const { data: tasksData, isLoading: tasksLoading } = useQuery({
    queryKey: ["baseline-tasks-completed"],
    queryFn: () => reportsApi.completedBaselineTasks(),
  });

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ["baseline-executive", selectedTaskId],
    queryFn: () => reportsApi.taskExecutive(selectedTaskId!),
    enabled: !!selectedTaskId,
  });

  async function handleExportPdf() {
    if (!selectedTaskId) return;
    setExporting(true);
    try {
      await reportsApi.downloadPdf(
        `/reports/task/${selectedTaskId}/pdf`,
        {},
        `baseline-report-${selectedTaskId}.pdf`,
      );
    } finally {
      setExporting(false);
    }
  }

  // ── DETAIL STATE ──────────────────────────────────────────────────────────

  if (selectedTaskId) {
    if (detailLoading || !detail) {
      return (
        <Card className="p-10 text-center text-muted">
          {t("operations.taskReport.baseline.loadingDetail")}
        </Card>
      );
    }

    const d = detail;
    return (
      <ExecutiveReport
        meta={{
          title: d.meta.report_title,
          subtitleEn: "Security Baseline Assessment Report",
          infoRows: [
            {
              label: t("operations.taskReport.baseline.infoTarget"),
              value: d.meta.check_target,
            },
            {
              label: t("operations.taskReport.baseline.infoType"),
              value: d.meta.baseline_type,
            },
            {
              label: t("operations.taskReport.baseline.infoReportId"),
              value: d.meta.report_id,
            },
            {
              label: t("operations.taskReport.baseline.infoGeneratedAt"),
              value: d.meta.generated_at,
            },
          ],
          company: d.meta.company_name || undefined,
        }}
        banner={{
          tone: d.summary.has_critical_risk
            ? "danger"
            : d.summary.has_high_risk
              ? "warning"
              : "success",
          text:
            d.summary.conclusion_statement || d.summary.overall_conclusion,
        }}
        sections={[
          {
            title: t("operations.taskReport.baseline.secSummary"),
            content: <SummaryContent d={d} />,
          },
          {
            title: t("operations.taskReport.baseline.secTaskInfo"),
            content: <TaskInfoContent d={d} />,
          },
          {
            title: t("operations.taskReport.baseline.secStats"),
            content: <StatisticsContent d={d} />,
          },
          {
            title: t("operations.taskReport.baseline.secScore"),
            content: <ScoreContent d={d} />,
          },
          {
            title: t("operations.taskReport.baseline.secRisks"),
            content:
              d.risk_items.length > 0 ? <RiskItemsContent d={d} /> : null,
          },
          {
            title: t("operations.taskReport.baseline.secHosts"),
            content:
              d.host_details.length > 0 ? <HostDetailsContent d={d} /> : null,
          },
          {
            title: t("operations.taskReport.baseline.secCoverage"),
            content: <CoverageContent d={d} />,
          },
        ]}
        recommendation={{
          assessment: d.recommendation.overall_assessment,
          suggestions: d.recommendation.action_suggestions,
          disclaimer: d.recommendation.disclaimer || undefined,
        }}
        onBack={() => setSelectedTaskId(null)}
        onExportPdf={handleExportPdf}
        exporting={exporting}
      />
    );
  }

  // ── LIST STATE ────────────────────────────────────────────────────────────

  const tasks = tasksData?.items ?? [];

  const columns: Column<BaselineTask>[] = [
    {
      key: "name",
      title: t("operations.taskReport.baseline.taskName"),
      render: (r) => (
        <span className="font-medium text-ink">{r.name}</span>
      ),
    },
    {
      key: "matched_host_count",
      title: t("operations.taskReport.baseline.hostCount"),
      align: "right",
      render: (r) =>
        r.matched_host_count !== undefined ? r.matched_host_count : "-",
    },
    {
      key: "completed_at",
      title: t("operations.taskReport.baseline.completedAt"),
      render: (r) => r.completed_at ?? "-",
    },
    {
      key: "status",
      title: t("operations.taskReport.baseline.status"),
      render: (r) => (
        <StatusTag tone="success">{r.status}</StatusTag>
      ),
    },
    {
      key: "actions",
      title: t("operations.taskReport.baseline.actions"),
      render: (r) => (
        <Button variant="ghost" onClick={() => setSelectedTaskId(r.task_id)}>
          {t("operations.taskReport.baseline.viewReport")}
        </Button>
      ),
    },
  ];

  if (tasksLoading) {
    return (
      <Card className="p-10 text-center text-muted">
        {t("operations.taskReport.loading")}
      </Card>
    );
  }

  if (tasks.length === 0) {
    return (
      <EmptyState
        title={t("operations.taskReport.baseline.noTasks")}
        desc=""
      />
    );
  }

  return (
    <Card>
      <DataTable
        columns={columns}
        rows={tasks}
        rowKey={(r) => r.task_id}
      />
    </Card>
  );
}
