"use client";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { operationsApi } from "@/lib/api/operations";
import type { Backup, BackupConfig } from "@/lib/api/types";
import { Card, CardHeader } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Input } from "@/components/ui/Input";
import { Switch } from "@/components/ui/Switch";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

const buildFrequencyOptions = (t: TFunction) => [
  { label: t("operations.backup.freqDaily"), value: "daily" },
  { label: t("operations.backup.freqWeekly"), value: "weekly" },
  { label: t("operations.backup.freqMonthly"), value: "monthly" },
];

const buildScopeOptions = (t: TFunction) => [
  { label: t("operations.backup.scopePolicies"), value: "policies" },
  { label: t("operations.backup.scopeUsers"), value: "users" },
  { label: t("operations.backup.scopeNotifications"), value: "notifications" },
  { label: t("operations.backup.scopeSettings"), value: "settings" },
];
const defaultScope = ["policies", "users", "notifications", "settings"];

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}

const emptyConfig: BackupConfig = { enabled: false, frequency: "daily", retention: 7 };

export default function BackupPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const frequencyOptions = buildFrequencyOptions(t);
  const scopeOptions = buildScopeOptions(t);
  const typeMeta: Record<string, { label: string; tone: "info" | "neutral" }> = {
    auto: { label: t("operations.backup.typeAuto"), tone: "info" },
    manual: { label: t("operations.backup.typeManual"), tone: "neutral" },
  };
  const statusMeta: Record<string, { label: string; tone: "success" | "info" | "danger" }> = {
    completed: { label: t("operations.backup.statusCompleted"), tone: "success" },
    pending: { label: t("operations.backup.statusPending"), tone: "info" },
    failed: { label: t("operations.backup.statusFailed"), tone: "danger" },
  };

  // ---- A. 自动备份配置 ----
  const { data: config } = useQuery({
    queryKey: ["ops-backup-config"],
    queryFn: () => operationsApi.getBackupConfig(),
  });
  const [configForm, setConfigForm] = useState<BackupConfig>(emptyConfig);
  useEffect(() => {
    if (config) setConfigForm(config);
  }, [config]);

  const saveConfigMutation = useMutation({
    mutationFn: () => operationsApi.updateBackupConfig(configForm),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ops-backup-config"] });
      toast.success(t("operations.backup.configSaved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // ---- B. 备份列表 ----
  const [params, setParams] = useUrlState({ page: 1, page_size: 20 });
  const { data, isLoading } = useQuery({
    queryKey: ["ops-backups", params],
    queryFn: () => operationsApi.listBackups(params),
  });

  // ---- 立即备份 ----
  const [createOpen, setCreateOpen] = useState(false);
  const [createScope, setCreateScope] = useState<string[]>(defaultScope);
  const [createRemark, setCreateRemark] = useState("");

  const createMutation = useMutation({
    // 后端 createBackup 接收 scope 字符串（逗号分隔）
    mutationFn: () => operationsApi.createBackup({ scope: createScope.join(","), remark: createRemark || undefined }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ops-backups"] });
      setCreateOpen(false);
      setCreateScope(defaultScope);
      setCreateRemark("");
      toast.success(t("operations.backup.created"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // ---- 恢复 / 删除 ----
  const [restoring, setRestoring] = useState<Backup | null>(null);
  const restoreMutation = useMutation({
    mutationFn: (id: number) => operationsApi.restoreBackup(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ops-backups"] });
      setRestoring(null);
      toast.success(t("operations.backup.restoreDone"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const [deleting, setDeleting] = useState<Backup | null>(null);
  const deleteMutation = useMutation({
    mutationFn: (id: number) => operationsApi.deleteBackup(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ops-backups"] });
      setDeleting(null);
      toast.success(t("operations.backup.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleScope = (value: string) =>
    setCreateScope((prev) => (prev.includes(value) ? prev.filter((v) => v !== value) : [...prev, value]));

  const columns: Column<Backup>[] = [
    {
      key: "type",
      title: t("operations.backup.colType"),
      render: (r) => {
        const meta = typeMeta[r.type] ?? { label: r.type, tone: "neutral" as const };
        return <StatusTag tone={meta.tone}>{meta.label}</StatusTag>;
      },
    },
    {
      key: "scope",
      title: t("operations.backup.colScope"),
      render: (r) => <span className="text-muted">{r.scope ? r.scope.split(",").join("、") : "—"}</span>,
    },
    { key: "remark", title: t("operations.backup.colRemark"), render: (r) => <span className="text-muted">{r.remark || "—"}</span> },
    {
      key: "file_size",
      title: t("operations.backup.colSize"),
      align: "right",
      render: (r) => <span className="tabular-nums text-muted">{formatBytes(r.file_size)}</span>,
    },
    {
      key: "status",
      title: t("operations.backup.colStatus"),
      render: (r) => {
        const meta = statusMeta[r.status] ?? { label: r.status, tone: "info" as const };
        return <StatusTag tone={meta.tone}>{meta.label}</StatusTag>;
      },
    },
    { key: "created_by", title: t("operations.backup.colCreatedBy"), render: (r) => <span className="text-faint">{r.created_by || "—"}</span> },
    {
      key: "created_at",
      title: t("operations.backup.colCreatedAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.created_at}</span>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-3">
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={(e) => {
              e.stopPropagation();
              setRestoring(r);
            }}
          >
            {t("operations.backup.restore")}
          </button>
          <button
            type="button"
            className="text-sm text-danger transition-colors hover:opacity-80"
            onClick={(e) => {
              e.stopPropagation();
              setDeleting(r);
            }}
          >
            {t("common.delete")}
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="space-y-4">
        {/* A. 自动备份配置 */}
        <Card>
          <CardHeader title={t("operations.backup.autoBackup")} />
          <div className="flex flex-wrap items-end gap-6 px-5 pb-5">
            <FormField label={t("operations.backup.fieldEnabled")}>
              <div className="flex h-10 items-center">
                <Switch
                  checked={configForm.enabled}
                  onChange={(checked) => setConfigForm((f) => ({ ...f, enabled: checked }))}
                />
              </div>
            </FormField>
            <FormField label={t("operations.backup.fieldFrequency")}>
              <Select
                value={configForm.frequency}
                onChange={(v) => setConfigForm((f) => ({ ...f, frequency: v }))}
                options={frequencyOptions}
                className="w-40"
              />
            </FormField>
            <FormField label={t("operations.backup.fieldRetention")}>
              <Input
                type="number"
                min={1}
                value={configForm.retention}
                onChange={(e) => setConfigForm((f) => ({ ...f, retention: Number(e.target.value) }))}
                className="w-40"
              />
            </FormField>
            <Button onClick={() => saveConfigMutation.mutate()} disabled={saveConfigMutation.isPending}>
              {saveConfigMutation.isPending ? t("common.saving") : t("common.save")}
            </Button>
          </div>
        </Card>

        {/* B. 备份列表 */}
        <FilterBar extra={<Button onClick={() => setCreateOpen(true)}>{t("operations.backup.createNow")}</Button>}>
          <span className="text-sm text-muted">{t("operations.backup.backupList")}</span>
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("operations.backup.empty")}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      {/* 立即备份 */}
      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title={t("operations.backup.createTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => createMutation.mutate()} disabled={createMutation.isPending || createScope.length === 0}>
              {createMutation.isPending ? t("operations.backup.backingUp") : t("operations.backup.startBackup")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("operations.backup.fieldScopeRequired")} required>
            <div className="flex flex-wrap gap-2">
              {scopeOptions.map((o) => {
                const active = createScope.includes(o.value);
                return (
                  <button
                    key={o.value}
                    type="button"
                    onClick={() => toggleScope(o.value)}
                    className={
                      active
                        ? "rounded-control border border-primary bg-primary/10 px-3 py-1.5 text-sm text-primary"
                        : "rounded-control border border-border px-3 py-1.5 text-sm text-muted transition-colors hover:text-ink"
                    }
                  >
                    {o.label}
                  </button>
                );
              })}
            </div>
          </FormField>
          <FormField label={t("operations.backup.fieldRemark")}>
            <Input value={createRemark} onChange={(e) => setCreateRemark(e.target.value)} placeholder={t("operations.backup.remarkPlaceholder")} />
          </FormField>
        </div>
      </Modal>

      {/* 恢复 */}
      <ConfirmDialog
        open={!!restoring}
        title={t("operations.backup.restoreTitle")}
        desc={t("operations.backup.restoreConfirmDesc")}
        confirmText={t("operations.backup.restoreConfirm")}
        loading={restoreMutation.isPending}
        onConfirm={() => restoring && restoreMutation.mutate(restoring.id)}
        onCancel={() => setRestoring(null)}
      />

      {/* 删除 */}
      <ConfirmDialog
        open={!!deleting}
        title={t("operations.backup.deleteTitle")}
        desc={deleting ? t("operations.backup.deleteConfirmDesc", { time: deleting.created_at }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
