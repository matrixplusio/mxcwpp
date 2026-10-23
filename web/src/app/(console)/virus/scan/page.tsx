"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ShieldAlert, Bug, AlertTriangle, Server } from "lucide-react";
import { virusApi } from "@/lib/api/virus";
import { hostsApi } from "@/lib/api/assets";
import type { Severity, VirusScanTask, VirusScanResult } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Tabs } from "@/components/ui/Tabs";
import { Drawer } from "@/components/ui/Drawer";
import { Modal } from "@/components/ui/Modal";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Input, Textarea } from "@/components/ui/Input";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

function isSeverity(v: string): v is Severity {
  return v === "critical" || v === "high" || v === "medium" || v === "low";
}

const buildScanTypeLabels = (t: TFunction): Record<string, string> => ({
  quick: t("virus.scanType.quick"),
  full: t("virus.scanType.full"),
  custom: t("virus.scanType.custom"),
});
const buildTaskStatusMeta = (t: TFunction): Record<string, { tone: Tone; label: string }> => ({
  pending: { tone: "neutral", label: t("virus.taskStatus.pending") },
  running: { tone: "info", label: t("virus.taskStatus.running") },
  completed: { tone: "success", label: t("virus.taskStatus.completed") },
  failed: { tone: "danger", label: t("virus.taskStatus.failed") },
  cancelled: { tone: "warning", label: t("virus.taskStatus.cancelled") },
});
const buildThreatTypeLabels = (t: TFunction): Record<string, string> => ({
  virus: t("virus.threatType.virus"),
  trojan: t("virus.threatType.trojan"),
  worm: t("virus.threatType.worm"),
  ransomware: t("virus.threatType.ransomware"),
  rootkit: t("virus.threatType.rootkit"),
  miner: t("virus.threatType.miner"),
  backdoor: t("virus.threatType.backdoor"),
  other: t("virus.threatType.other"),
});
const buildActionMeta = (t: TFunction): Record<string, { tone: Tone; label: string }> => ({
  detected: { tone: "danger", label: t("virus.disposition.detected") },
  quarantined: { tone: "warning", label: t("virus.disposition.quarantined") },
  deleted: { tone: "neutral", label: t("virus.disposition.deleted") },
  ignored: { tone: "neutral", label: t("virus.disposition.ignored") },
});

const buildTaskStatusOptions = (t: TFunction) => [
  { label: t("common.allStatus"), value: "" },
  { label: t("virus.taskStatus.pending"), value: "pending" },
  { label: t("virus.taskStatus.running"), value: "running" },
  { label: t("virus.taskStatus.completed"), value: "completed" },
  { label: t("virus.taskStatus.failed"), value: "failed" },
  { label: t("virus.taskStatus.cancelled"), value: "cancelled" },
];
const buildScanTypeOptions = (t: TFunction) => [
  { label: t("common.allType"), value: "" },
  { label: t("virus.scanType.quick"), value: "quick" },
  { label: t("virus.scanType.full"), value: "full" },
  { label: t("virus.scanType.custom"), value: "custom" },
];
const buildSeverityOptions = (t: TFunction) => [
  { label: t("common.allSeverity"), value: "" },
  { label: t("common.severity.critical"), value: "critical" },
  { label: t("common.severity.high"), value: "high" },
  { label: t("common.severity.medium"), value: "medium" },
  { label: t("common.severity.low"), value: "low" },
];
const buildThreatTypeOptions = (t: TFunction) => [
  { label: t("common.allType"), value: "" },
  { label: t("virus.threatType.virus"), value: "virus" },
  { label: t("virus.threatType.trojan"), value: "trojan" },
  { label: t("virus.threatType.worm"), value: "worm" },
  { label: t("virus.threatType.ransomware"), value: "ransomware" },
  { label: t("virus.threatType.rootkit"), value: "rootkit" },
  { label: t("virus.threatType.miner"), value: "miner" },
  { label: t("virus.threatType.backdoor"), value: "backdoor" },
  { label: t("virus.threatType.other"), value: "other" },
];
const buildActionOptions = (t: TFunction) => [
  { label: t("virus.scan.allDisposition"), value: "" },
  { label: t("virus.disposition.detected"), value: "detected" },
  { label: t("virus.disposition.quarantined"), value: "quarantined" },
  { label: t("virus.disposition.deleted"), value: "deleted" },
  { label: t("virus.disposition.ignored"), value: "ignored" },
];
const buildScanTypeFormOptions = (t: TFunction) => [
  { label: t("virus.scanType.quick"), value: "quick" },
  { label: t("virus.scanType.full"), value: "full" },
  { label: t("virus.scanType.custom"), value: "custom" },
];

function formatFileSize(bytes: number): string {
  if (!bytes) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let size = bytes;
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024;
    i++;
  }
  return `${size.toFixed(1)} ${units[i]}`;
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="min-w-0 break-all text-ink">{value}</span>
    </div>
  );
}

interface TaskParams {
  page: number;
  page_size: number;
  keyword: string;
  status: string;
  scan_type: string;
}
interface ResultParams {
  page: number;
  page_size: number;
  keyword: string;
  severity: string;
  threat_type: string;
  action: string;
}
interface CreateForm {
  name: string;
  scanType: string;
  scanPathsText: string;
  hostIdsText: string;
}

const emptyCreate: CreateForm = { name: "", scanType: "quick", scanPathsText: "", hostIdsText: "" };

export default function VirusScanPage() {
  const { t } = useTranslation();
  const scanTypeLabels = buildScanTypeLabels(t);
  const taskStatusMeta = buildTaskStatusMeta(t);
  const threatTypeLabels = buildThreatTypeLabels(t);
  const actionMeta = buildActionMeta(t);
  const taskStatusOptions = buildTaskStatusOptions(t);
  const scanTypeOptions = buildScanTypeOptions(t);
  const severityOptions = buildSeverityOptions(t);
  const threatTypeOptions = buildThreatTypeOptions(t);
  const actionOptions = buildActionOptions(t);
  const scanTypeFormOptions = buildScanTypeFormOptions(t);
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<"tasks" | "results">("tasks");

  const [taskParams, setTaskParams] = useState<TaskParams>({
    page: 1,
    page_size: 20,
    keyword: "",
    status: "",
    scan_type: "",
  });
  const [resultParams, setResultParams] = useState<ResultParams>({
    page: 1,
    page_size: 20,
    keyword: "",
    severity: "",
    threat_type: "",
    action: "",
  });

  const { data: stats, isError: statsError } = useQuery({ queryKey: ["virus-stats"], queryFn: () => virusApi.statistics() });

  const { data: taskData, isLoading: tasksLoading } = useQuery({
    queryKey: ["virus-tasks", taskParams],
    queryFn: () =>
      virusApi.listTasks({
        page: taskParams.page,
        page_size: taskParams.page_size,
        keyword: taskParams.keyword || undefined,
        status: taskParams.status || undefined,
        scan_type: taskParams.scan_type || undefined,
      }),
  });

  const { data: resultData, isLoading: resultsLoading } = useQuery({
    queryKey: ["virus-results", resultParams],
    queryFn: () =>
      virusApi.listResults({
        page: resultParams.page,
        page_size: resultParams.page_size,
        keyword: resultParams.keyword || undefined,
        severity: resultParams.severity || undefined,
        threat_type: resultParams.threat_type || undefined,
        action: resultParams.action || undefined,
      }),
  });

  const [taskDetail, setTaskDetail] = useState<VirusScanTask | null>(null);
  const [resultDetail, setResultDetail] = useState<VirusScanResult | null>(null);
  const [deletingTask, setDeletingTask] = useState<VirusScanTask | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState<CreateForm>(emptyCreate);

  const { data: hostData } = useQuery({
    queryKey: ["virus-scan-hosts"],
    queryFn: () => hostsApi.list({ page: 1, page_size: 1000, status: "online" }),
    enabled: createOpen,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["virus-tasks"] });
    queryClient.invalidateQueries({ queryKey: ["virus-results"] });
    queryClient.invalidateQueries({ queryKey: ["virus-stats"] });
  };

  const createMutation = useMutation({
    mutationFn: () => {
      const hostIds = form.hostIdsText
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      const scanPaths =
        form.scanType === "custom"
          ? form.scanPathsText
              .split("\n")
              .map((s) => s.trim())
              .filter(Boolean)
          : undefined;
      return virusApi.createTask({ name: form.name.trim(), scanType: form.scanType, scanPaths, hostIds });
    },
    onSuccess: () => {
      invalidate();
      setCreateOpen(false);
      setForm(emptyCreate);
      toast.success(t("virus.scan.toastCreated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const cancelMutation = useMutation({
    mutationFn: (id: number) => virusApi.cancelTask(id),
    onSuccess: () => {
      invalidate();
      toast.success(t("virus.scan.toastCancelled"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => virusApi.deleteTask(id),
    onSuccess: () => {
      invalidate();
      setDeletingTask(null);
      toast.success(t("virus.scan.toastDeleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const dispositionMutation = useMutation({
    mutationFn: ({ id, type }: { id: number; type: "quarantine" | "delete" | "ignore" }) => {
      if (type === "quarantine") return virusApi.quarantineResult(id);
      if (type === "delete") return virusApi.deleteFileResult(id);
      return virusApi.ignoreResult(id);
    },
    onSuccess: (_d, v) => {
      invalidate();
      setResultDetail(null);
      toast.success(v.type === "quarantine" ? t("virus.scan.toastQuarantined") : v.type === "delete" ? t("virus.scan.toastFileDeleted") : t("virus.scan.toastIgnored"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const handleCreate = () => {
    if (!form.name.trim()) {
      toast.error(t("virus.scan.errNameRequired"));
      return;
    }
    const hostCount = form.hostIdsText.split(/[\n,]/).filter((s) => s.trim()).length;
    if (hostCount === 0) {
      toast.error(t("virus.scan.errHostRequired"));
      return;
    }
    if (form.scanType === "custom" && !form.scanPathsText.trim()) {
      toast.error(t("virus.scan.errPathRequired"));
      return;
    }
    createMutation.mutate();
  };

  const appendAllHosts = () => {
    const ids = (hostData?.items ?? []).map((h) => h.host_id);
    setForm((f) => ({ ...f, hostIdsText: ids.join("\n") }));
  };

  const taskColumns: Column<VirusScanTask>[] = [
    { key: "name", title: t("virus.scan.colName"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    {
      key: "scanType",
      title: t("virus.scan.colScanType"),
      render: (r) => <StatusTag tone="neutral">{scanTypeLabels[r.scanType] ?? r.scanType}</StatusTag>,
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => {
        const m = taskStatusMeta[r.status] ?? { tone: "neutral" as Tone, label: r.status };
        return <StatusTag tone={m.tone}>{m.label}</StatusTag>;
      },
    },
    {
      key: "progress",
      title: t("virus.scan.colProgress"),
      render: (r) => (
        <span className="text-faint tabular-nums">
          {r.scannedHosts}/{r.totalHosts}
        </span>
      ),
    },
    {
      key: "threatCount",
      title: t("virus.scan.colThreatCount"),
      align: "center",
      render: (r) => (
        <span className={r.threatCount > 0 ? "font-semibold text-danger" : "text-muted"}>{r.threatCount}</span>
      ),
    },
    { key: "createdBy", title: t("virus.scan.colCreatedBy"), render: (r) => r.createdBy || "—" },
    { key: "createdAt", title: t("common.createdAt"), render: (r) => <span className="text-faint tabular-nums">{r.createdAt}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          {(r.status === "pending" || r.status === "running") && (
            <button
              type="button"
              className="text-sm text-warning transition-colors hover:opacity-80"
              onClick={() => cancelMutation.mutate(r.id)}
            >
              {t("common.cancel")}
            </button>
          )}
          {r.status !== "running" && (
            <button
              type="button"
              className="text-sm text-danger transition-colors hover:opacity-80"
              onClick={() => setDeletingTask(r)}
            >
              {t("common.delete")}
            </button>
          )}
        </div>
      ),
    },
  ];

  const resultColumns: Column<VirusScanResult>[] = [
    { key: "threatName", title: t("virus.scan.colThreatName"), render: (r) => <span className="font-medium text-ink">{r.threatName}</span> },
    {
      key: "severity",
      title: t("common.level"),
      render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : <StatusTag tone="neutral">{r.severity}</StatusTag>),
    },
    {
      key: "threatType",
      title: t("virus.scan.colThreatType"),
      render: (r) => <StatusTag tone="neutral">{threatTypeLabels[r.threatType] ?? r.threatType}</StatusTag>,
    },
    { key: "host", title: t("common.host"), render: (r) => <span className="text-faint">{r.hostname || r.hostId}</span> },
    {
      key: "filePath",
      title: t("virus.scan.colFilePath"),
      render: (r) => <span className="font-mono text-xs text-muted break-all">{r.filePath}</span>,
    },
    {
      key: "action",
      title: t("virus.scan.colDisposition"),
      render: (r) => {
        const m = actionMeta[r.action] ?? { tone: "neutral" as Tone, label: r.action };
        return <StatusTag tone={m.tone}>{m.label}</StatusTag>;
      },
    },
    {
      key: "detectedAt",
      title: t("virus.scan.colDetectedAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.detectedAt}</span>,
    },
  ];

  return (
    <>
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard compact label={t("virus.scan.statTasks")} value={stats?.tasks.total ?? 0} error={statsError} icon={ShieldAlert} tone="default" />
        <StatCard compact label={t("virus.scan.statThreats")} value={stats?.threats.total ?? 0} error={statsError} icon={Bug} tone="danger" />
        <StatCard compact label={t("virus.scan.statHandled")} value={stats?.threats.quarantined ?? 0} error={statsError} icon={AlertTriangle} tone="warning" />
        <StatCard compact label={t("virus.scan.statAffectedHosts")} value={stats?.affectedHosts ?? 0} error={statsError} icon={Server} tone="success" />
      </div>

      <div className="mb-4">
        <Tabs
          items={[
            { key: "tasks", label: t("virus.scan.tabTasks") },
            { key: "results", label: t("virus.scan.tabResults") },
          ]}
          active={tab}
          onChange={(k) => setTab(k as "tasks" | "results")}
        />
      </div>

      {tab === "tasks" ? (
        <div className="space-y-4">
          <FilterBar extra={<Button onClick={() => setCreateOpen(true)}>{t("virus.scan.startScan")}</Button>}>
            <SearchInput
              value={taskParams.keyword}
              onChange={(v) => setTaskParams((p) => ({ ...p, keyword: v, page: 1 }))}
              placeholder={t("virus.scan.searchTask")}
            />
            <Select
              value={taskParams.status}
              onChange={(v) => setTaskParams((p) => ({ ...p, status: v, page: 1 }))}
              options={taskStatusOptions}
            />
            <Select
              value={taskParams.scan_type}
              onChange={(v) => setTaskParams((p) => ({ ...p, scan_type: v, page: 1 }))}
              options={scanTypeOptions}
            />
          </FilterBar>
          <Card>
            <DataTable
              columns={taskColumns}
              rows={taskData?.items ?? []}
              rowKey={(r) => r.id}
              loading={tasksLoading}
              emptyText={t("virus.scan.emptyTasks")}
              onRowClick={setTaskDetail}
            />
            <Pagination
              page={taskParams.page}
              pageSize={taskParams.page_size}
              total={taskData?.total ?? 0}
              onChange={(page) => setTaskParams((p) => ({ ...p, page }))}
            />
          </Card>
        </div>
      ) : (
        <div className="space-y-4">
          <FilterBar>
            <SearchInput
              value={resultParams.keyword}
              onChange={(v) => setResultParams((p) => ({ ...p, keyword: v, page: 1 }))}
              placeholder={t("virus.scan.searchResult")}
            />
            <Select
              value={resultParams.severity}
              onChange={(v) => setResultParams((p) => ({ ...p, severity: v, page: 1 }))}
              options={severityOptions}
            />
            <Select
              value={resultParams.threat_type}
              onChange={(v) => setResultParams((p) => ({ ...p, threat_type: v, page: 1 }))}
              options={threatTypeOptions}
            />
            <Select
              value={resultParams.action}
              onChange={(v) => setResultParams((p) => ({ ...p, action: v, page: 1 }))}
              options={actionOptions}
            />
          </FilterBar>
          <Card>
            <DataTable
              columns={resultColumns}
              rows={resultData?.items ?? []}
              rowKey={(r) => r.id}
              loading={resultsLoading}
              emptyText={t("virus.scan.emptyResults")}
              onRowClick={setResultDetail}
            />
            <Pagination
              page={resultParams.page}
              pageSize={resultParams.page_size}
              total={resultData?.total ?? 0}
              onChange={(page) => setResultParams((p) => ({ ...p, page }))}
            />
          </Card>
        </div>
      )}

      {/* 任务详情 */}
      <Drawer open={!!taskDetail} onClose={() => setTaskDetail(null)} title={t("virus.scan.taskDetailTitle")} width={560}>
        {taskDetail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold text-ink">{taskDetail.name}</h2>
              <StatusTag tone={(taskStatusMeta[taskDetail.status] ?? { tone: "neutral" as Tone }).tone}>
                {(taskStatusMeta[taskDetail.status] ?? { label: taskDetail.status }).label}
              </StatusTag>
            </div>
            <div className="space-y-2">
              <Field label={t("virus.scan.colScanType")} value={scanTypeLabels[taskDetail.scanType] ?? taskDetail.scanType} />
              <Field label={t("virus.scan.fieldTargetHosts")} value={taskDetail.totalHosts} />
              <Field label={t("virus.scan.fieldScanned")} value={taskDetail.scannedHosts} />
              <Field
                label={t("virus.scan.fieldThreatFound")}
                value={
                  <span className={taskDetail.threatCount > 0 ? "font-semibold text-danger" : "text-ink"}>
                    {taskDetail.threatCount}
                  </span>
                }
              />
              <Field label={t("virus.scan.colCreatedBy")} value={taskDetail.createdBy || "—"} />
              <Field label={t("common.createdAt")} value={<span className="tabular-nums">{taskDetail.createdAt}</span>} />
              <Field label={t("virus.scan.fieldStartedAt")} value={<span className="tabular-nums">{taskDetail.startedAt || "—"}</span>} />
              <Field label={t("virus.scan.fieldFinishedAt")} value={<span className="tabular-nums">{taskDetail.finishedAt || "—"}</span>} />
            </div>
            {taskDetail.scanPaths?.length > 0 && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("virus.scan.fieldScanPaths")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                  {taskDetail.scanPaths.join("\n")}
                </pre>
              </div>
            )}
          </div>
        )}
      </Drawer>

      {/* 结果详情 */}
      <Drawer
        open={!!resultDetail}
        onClose={() => setResultDetail(null)}
        title={t("virus.scan.resultDetailTitle")}
        width={560}
        footer={
          resultDetail?.action === "detected" ? (
            <>
              <Button variant="ghost" onClick={() => dispositionMutation.mutate({ id: resultDetail.id, type: "ignore" })}>
                {t("virus.scan.ignore")}
              </Button>
              <Button
                variant="danger"
                onClick={() => dispositionMutation.mutate({ id: resultDetail.id, type: "delete" })}
              >
                {t("virus.scan.deleteFile")}
              </Button>
              <Button onClick={() => dispositionMutation.mutate({ id: resultDetail.id, type: "quarantine" })}>
                {t("virus.scan.quarantineFile")}
              </Button>
            </>
          ) : undefined
        }
      >
        {resultDetail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold text-ink">{resultDetail.threatName}</h2>
              <div className="flex items-center gap-2">
                {isSeverity(resultDetail.severity) ? (
                  <SeverityTag level={resultDetail.severity} />
                ) : (
                  <StatusTag tone="neutral">{resultDetail.severity}</StatusTag>
                )}
                <StatusTag tone={(actionMeta[resultDetail.action] ?? { tone: "neutral" as Tone }).tone}>
                  {(actionMeta[resultDetail.action] ?? { label: resultDetail.action }).label}
                </StatusTag>
              </div>
            </div>
            <div className="space-y-2">
              <Field label={t("virus.scan.colThreatType")} value={threatTypeLabels[resultDetail.threatType] ?? resultDetail.threatType} />
              <Field label={t("virus.scan.colFilePath")} value={<span className="font-mono text-xs">{resultDetail.filePath}</span>} />
              <Field label={t("virus.scan.fieldFileHash")} value={<span className="font-mono text-xs">{resultDetail.fileHash || "—"}</span>} />
              <Field label={t("virus.scan.fieldFileSize")} value={formatFileSize(resultDetail.fileSize)} />
              <Field label={t("common.host")} value={`${resultDetail.hostname || resultDetail.hostId}${resultDetail.ip ? ` (${resultDetail.ip})` : ""}`} />
              <Field label={t("virus.scan.colDetectedAt")} value={<span className="tabular-nums">{resultDetail.detectedAt}</span>} />
            </div>
          </div>
        )}
      </Drawer>

      {/* 发起扫描 */}
      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={t("virus.scan.startScan")}
        width={520}
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={handleCreate} disabled={createMutation.isPending}>
              {createMutation.isPending ? t("common.submitting") : t("virus.scan.createTask")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("virus.scan.colName")} required>
            <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <FormField label={t("virus.scan.colScanType")}>
            <Select
              value={form.scanType}
              onChange={(v) => setForm((f) => ({ ...f, scanType: v }))}
              options={scanTypeFormOptions}
              className="w-full"
            />
          </FormField>
          {form.scanType === "custom" && (
            <FormField label={t("virus.scan.fieldScanPaths")} required>
              <Textarea
                rows={3}
                value={form.scanPathsText}
                onChange={(e) => setForm((f) => ({ ...f, scanPathsText: e.target.value }))}
                placeholder={t("virus.scan.scanPathsPlaceholder")}
              />
            </FormField>
          )}
          <FormField label={t("virus.scan.fieldTargetHosts")} required>
            <Textarea
              rows={3}
              value={form.hostIdsText}
              onChange={(e) => setForm((f) => ({ ...f, hostIdsText: e.target.value }))}
              placeholder={t("virus.scan.hostIdsPlaceholder")}
            />
            <button
              type="button"
              className="mt-1.5 text-xs text-primary transition-colors hover:text-primary-hover"
              onClick={appendAllHosts}
            >
              {t("virus.scan.fillOnlineHosts", { count: hostData?.items.length ?? 0 })}
            </button>
          </FormField>
        </div>
      </Modal>

      <ConfirmDialog
        open={!!deletingTask}
        title={t("virus.scan.deleteTaskTitle")}
        desc={deletingTask ? t("virus.scan.deleteTaskDesc", { name: deletingTask.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deletingTask && deleteMutation.mutate(deletingTask.id)}
        onCancel={() => setDeletingTask(null)}
      />
    </>
  );
}
