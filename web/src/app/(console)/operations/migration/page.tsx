"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { operationsApi, type MigrationStartInput } from "@/lib/api/operations";
import type { MigrationJob, MigrationStatus, MigrationTestResult } from "@/lib/api/types";
import { Card, CardHeader } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

// 可迁移数据表（镜像 Vue scopeOptions）
const buildScopeOptions = (t: TFunction): { value: string; label: string }[] => [
  { value: "users", label: t("operations.migration.scopeUsers") },
  { value: "business_lines", label: t("operations.migration.scopeBusinessLines") },
  { value: "hosts", label: t("operations.migration.scopeHosts") },
  { value: "policies", label: t("operations.migration.scopePolicies") },
  { value: "rules", label: t("operations.migration.scopeRules") },
  { value: "scan_tasks", label: t("operations.migration.scopeScanTasks") },
  { value: "scan_results", label: t("operations.migration.scopeScanResults") },
  { value: "notifications", label: t("operations.migration.scopeNotifications") },
];
const DEFAULT_SCOPE = ["users", "business_lines", "hosts", "policies", "rules", "notifications"];

const STATUS_TONE: Record<MigrationStatus, "info" | "success" | "danger" | "neutral"> = {
  pending: "info",
  running: "info",
  completed: "success",
  failed: "danger",
  cancelled: "neutral",
};
const buildStatusLabel = (t: TFunction): Record<MigrationStatus, string> => ({
  pending: t("operations.migration.statusPending"),
  running: t("operations.migration.statusRunning"),
  completed: t("operations.migration.statusCompleted"),
  failed: t("operations.migration.statusFailed"),
  cancelled: t("operations.migration.statusCancelled"),
});

type Step = 0 | 1 | 2;

interface ConnForm {
  source_url: string;
  source_user: string;
  password: string;
}
const emptyConn: ConnForm = { source_url: "", source_user: "", password: "" };

export default function MigrationPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const SCOPE_OPTIONS = buildScopeOptions(t);
  const STATUS_LABEL = buildStatusLabel(t);
  const steps = [t("operations.migration.step1"), t("operations.migration.step2"), t("operations.migration.step3")];
  const [step, setStep] = useState<Step>(0);
  const [conn, setConn] = useState<ConnForm>(emptyConn);
  const [testResult, setTestResult] = useState<MigrationTestResult | null>(null);
  const [scope, setScope] = useState<string[]>(DEFAULT_SCOPE);

  const [params, setParams] = useUrlState({ page: 1, page_size: 10 });
  const { data, isLoading } = useQuery({
    queryKey: ["ops-migration-jobs", params],
    queryFn: () => operationsApi.listMigrationJobs(params),
  });
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["ops-migration-jobs"] });

  const [cancelTarget, setCancelTarget] = useState<MigrationJob | null>(null);

  const testMutation = useMutation({
    mutationFn: () => operationsApi.testConnection(conn),
    onSuccess: (res) => {
      setTestResult(res);
      toast.success(t("operations.migration.testSuccess"));
    },
    onError: (e: Error) => {
      setTestResult(null);
      toast.error(e.message);
    },
  });

  const startMutation = useMutation({
    mutationFn: (): Promise<MigrationJob> => {
      const body: MigrationStartInput = { ...conn, scope };
      return operationsApi.startMigrationJob(body);
    },
    onSuccess: () => {
      toast.success(t("operations.migration.started"));
      invalidate();
      // 重置向导
      setStep(0);
      setTestResult(null);
      setConn((c) => ({ ...c, password: "" }));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const cancelMutation = useMutation({
    mutationFn: (id: number) => operationsApi.cancelMigrationJob(id),
    onSuccess: () => {
      toast.success(t("operations.migration.cancelled"));
      setCancelTarget(null);
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleScope = (value: string) =>
    setScope((s) => (s.includes(value) ? s.filter((v) => v !== value) : [...s, value]));

  const connValid = conn.source_url && conn.source_user && conn.password;

  const columns: Column<MigrationJob>[] = [
    {
      key: "source_url",
      title: t("operations.migration.colSourceUrl"),
      render: (r) => <span className="font-medium text-ink">{r.source_url || "—"}</span>,
    },
    {
      key: "status",
      title: t("operations.migration.colStatus"),
      render: (r) => <StatusTag tone={STATUS_TONE[r.status]}>{STATUS_LABEL[r.status]}</StatusTag>,
    },
    {
      key: "progress",
      title: t("operations.migration.colProgress"),
      width: "160px",
      render: (r) => (
        <div className="flex items-center gap-2">
          <div className="h-1.5 w-24 overflow-hidden rounded-full bg-surface-muted">
            <div className="h-full rounded-full bg-primary" style={{ width: `${r.progress || 0}%` }} />
          </div>
          <span className="text-xs text-muted tabular-nums">{r.progress || 0}%</span>
        </div>
      ),
    },
    { key: "current_table", title: t("operations.migration.colCurrentTable"), render: (r) => r.current_table || "—" },
    {
      key: "counts",
      title: t("operations.migration.colCounts"),
      render: (r) => (
        <span className="text-xs tabular-nums">
          <span className="text-success">✓ {r.created_count}</span>
          <span className="mx-1.5 text-warning">- {r.skipped_count}</span>
          <span className="text-danger">× {r.failed_count}</span>
        </span>
      ),
    },
    {
      key: "created_at",
      title: t("operations.migration.colCreatedAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.created_at}</span>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) =>
        r.status === "running" || r.status === "pending" ? (
          <button
            type="button"
            className="text-sm text-danger transition-colors hover:opacity-80"
            onClick={() => setCancelTarget(r)}
          >
            {t("operations.migration.cancel")}
          </button>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader title={t("operations.migration.wizardTitle")} />
        <div className="px-5 pb-5">
          {/* 步骤指示 */}
          <div className="mb-6 flex items-center gap-3">
            {steps.map((label, i) => (
              <div key={label} className="flex items-center gap-3">
                <div className="flex items-center gap-2">
                  <span
                    className={
                      "flex h-6 w-6 items-center justify-center rounded-full text-xs font-semibold " +
                      (i <= step ? "bg-primary text-white" : "bg-surface-muted text-muted")
                    }
                  >
                    {i + 1}
                  </span>
                  <span className={i === step ? "text-sm font-medium text-ink" : "text-sm text-muted"}>
                    {label}
                  </span>
                </div>
                {i < steps.length - 1 && <span className="h-px w-8 bg-border" />}
              </div>
            ))}
          </div>

          {/* Step 1: 连接 */}
          {step === 0 && (
            <div className="max-w-xl space-y-4">
              <p className="text-sm text-muted">
                {t("operations.migration.connectHint")}
              </p>
              <FormField label={t("operations.migration.fieldSourceUrl")} required>
                <Input
                  value={conn.source_url}
                  onChange={(e) => setConn((c) => ({ ...c, source_url: e.target.value }))}
                  placeholder="http://mvp1.example.com"
                />
              </FormField>
              <FormField label={t("operations.migration.fieldSourceUser")} required>
                <Input
                  value={conn.source_user}
                  onChange={(e) => setConn((c) => ({ ...c, source_user: e.target.value }))}
                  placeholder="admin"
                />
              </FormField>
              <FormField label={t("operations.migration.fieldPassword")} required>
                <Input
                  type="password"
                  value={conn.password}
                  onChange={(e) => setConn((c) => ({ ...c, password: e.target.value }))}
                  placeholder={t("operations.migration.passwordPlaceholder")}
                />
              </FormField>
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  onClick={() => testMutation.mutate()}
                  disabled={!connValid || testMutation.isPending}
                >
                  {testMutation.isPending ? t("operations.migration.testing") : t("operations.migration.testConnection")}
                </Button>
                {testResult && (
                  <Button onClick={() => setStep(1)}>{t("operations.migration.nextSelectScope")}</Button>
                )}
              </div>
              {testResult && (
                <div className="rounded-control border border-border bg-surface-muted/50 p-4">
                  <div className="mb-2 text-sm font-medium text-ink">
                    {t("operations.migration.connectedVersion", { version: testResult.version || t("operations.migration.versionUnknown") })}
                  </div>
                  <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm md:grid-cols-3">
                    {Object.entries(testResult.tables).map(([k, v]) => (
                      <div key={k} className="flex justify-between">
                        <span className="text-muted">{k}</span>
                        <span className="tabular-nums text-ink">{v < 0 ? t("operations.migration.queryFailed") : v}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 2: 范围 */}
          {step === 1 && (
            <div className="max-w-xl space-y-4">
              <p className="text-sm text-warning">
                {t("operations.migration.scopeWarning")}
              </p>
              <div className="grid grid-cols-2 gap-2">
                {SCOPE_OPTIONS.map((opt) => (
                  <label
                    key={opt.value}
                    className="flex cursor-pointer items-center gap-2 rounded-control border border-border px-3 py-2 text-sm text-ink"
                  >
                    <input
                      type="checkbox"
                      checked={scope.includes(opt.value)}
                      onChange={() => toggleScope(opt.value)}
                    />
                    {opt.label}
                  </label>
                ))}
              </div>
              <div className="flex items-center gap-2">
                <Button variant="ghost" onClick={() => setStep(0)}>
                  {t("operations.migration.prevStep")}
                </Button>
                <Button onClick={() => setStep(2)} disabled={scope.length === 0}>
                  {t("operations.migration.nextStep")}
                </Button>
              </div>
            </div>
          )}

          {/* Step 3: 执行 */}
          {step === 2 && (
            <div className="max-w-xl space-y-4">
              <div className="rounded-control border border-border bg-surface-muted/50 p-4 text-sm">
                <div className="mb-1 text-muted">{t("operations.migration.willMigrate")}</div>
                <div className="flex flex-wrap gap-1.5">
                  {scope.map((s) => (
                    <StatusTag key={s} tone="info">
                      {s}
                    </StatusTag>
                  ))}
                </div>
              </div>
              <p className="text-sm text-muted">
                {t("operations.migration.executeHint")}
              </p>
              <div className="flex items-center gap-2">
                <Button variant="ghost" onClick={() => setStep(1)}>
                  {t("operations.migration.prevStep")}
                </Button>
                <Button onClick={() => startMutation.mutate()} disabled={startMutation.isPending}>
                  {startMutation.isPending ? t("operations.migration.starting") : t("operations.migration.startMigration")}
                </Button>
              </div>
            </div>
          )}
        </div>
      </Card>

      <Card>
        <CardHeader title={t("operations.migration.jobsTitle")} />
        <DataTable
          columns={columns}
          rows={data?.items ?? []}
          rowKey={(r) => r.id}
          loading={isLoading}
          emptyText={t("operations.migration.empty")}
        />
        <Pagination
          page={params.page}
          pageSize={params.page_size}
          total={data?.total ?? 0}
          onChange={(page) => setParams((p) => ({ ...p, page }))}
        />
      </Card>

      <ConfirmDialog
        open={!!cancelTarget}
        title={t("operations.migration.cancelTitle")}
        desc={cancelTarget ? t("operations.migration.cancelConfirmDesc", { id: cancelTarget.id, url: cancelTarget.source_url }) : undefined}
        confirmText={t("operations.migration.cancelConfirm")}
        loading={cancelMutation.isPending}
        onConfirm={() => cancelTarget && cancelMutation.mutate(cancelTarget.id)}
        onCancel={() => setCancelTarget(null)}
      />
    </div>
  );
}
