"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { vulnApi } from "@/lib/api/vuln";
import type { VulnScanSchedule } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { FilterBar } from "@/components/ui/FilterBar";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { Switch } from "@/components/ui/Switch";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

const buildScanTypeLabel = (t: TFunction): Record<string, string> => ({
  sync_only: t("vuln.scanSchedules.scanTypeSyncOnly"),
  full_scan: t("vuln.scanSchedules.scanTypeFullScan"),
  incremental_scan: t("vuln.scanSchedules.scanTypeIncrementalScan"),
});
const buildScanTypeOptions = (t: TFunction) => [
  { label: t("vuln.scanSchedules.scanTypeSyncOnly"), value: "sync_only" },
  { label: t("vuln.scanSchedules.scanTypeFullScan"), value: "full_scan" },
  { label: t("vuln.scanSchedules.scanTypeIncrementalScan"), value: "incremental_scan" },
];

interface ScheduleForm {
  name: string;
  scanType: string;
  cronExpr: string;
  enabled: boolean;
}
const emptyForm: ScheduleForm = { name: "", scanType: "full_scan", cronExpr: "", enabled: true };

export default function ScanSchedulesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const SCAN_TYPE_LABEL = buildScanTypeLabel(t);
  const scanTypeOptions = buildScanTypeOptions(t);
  const { data, isLoading } = useQuery({
    queryKey: ["vuln-schedules"],
    queryFn: () => vulnApi.listScanSchedules(),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<VulnScanSchedule | null>(null);
  const [form, setForm] = useState<ScheduleForm>(emptyForm);
  const [deleting, setDeleting] = useState<VulnScanSchedule | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["vuln-schedules"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (s: VulnScanSchedule) => {
    setEditing(s);
    setForm({ name: s.name, scanType: s.scanType, cronExpr: s.cronExpr, enabled: s.enabled });
    setDrawerOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: () =>
      editing
        ? vulnApi.updateScanSchedule(editing.id, {
            name: form.name,
            scanType: form.scanType,
            cronExpr: form.cronExpr,
            enabled: form.enabled,
          })
        : vulnApi.createScanSchedule({ name: form.name, scanType: form.scanType, cronExpr: form.cronExpr }),
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("vuln.scanSchedules.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => vulnApi.deleteScanSchedule(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("vuln.scanSchedules.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleMutation = useMutation({
    mutationFn: (id: number) => vulnApi.toggleScanSchedule(id),
    onSuccess: () => {
      invalidate();
      toast.success(t("vuln.scanSchedules.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<VulnScanSchedule>[] = [
    { key: "name", title: t("common.name"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    {
      key: "scanType",
      title: t("vuln.scanSchedules.colScanType"),
      render: (r) => <StatusTag tone="neutral">{SCAN_TYPE_LABEL[r.scanType] ?? r.scanType}</StatusTag>,
    },
    {
      key: "cronExpr",
      title: t("vuln.scanSchedules.colCronExpr"),
      render: (r) => <span className="font-mono text-xs text-ink">{r.cronExpr}</span>,
    },
    {
      key: "enabled",
      title: t("vuln.scanSchedules.colEnabled"),
      render: (r) => (
        <Switch checked={r.enabled} disabled={toggleMutation.isPending} onChange={() => toggleMutation.mutate(r.id)} />
      ),
    },
    { key: "lastRunAt", title: t("vuln.scanSchedules.colLastRunAt"), render: (r) => <span className="text-faint tabular-nums">{r.lastRunAt || "—"}</span> },
    { key: "nextRunAt", title: t("vuln.scanSchedules.colNextRunAt"), render: (r) => <span className="text-faint tabular-nums">{r.nextRunAt || "—"}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={(e) => {
              e.stopPropagation();
              openEdit(r);
            }}
          >
            {t("common.edit")}
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
        <FilterBar extra={<Button onClick={openCreate}>{t("vuln.scanSchedules.create")}</Button>}>
          <span className="text-sm text-muted">{t("vuln.scanSchedules.subtitle")}</span>
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("vuln.scanSchedules.empty")}
          />
        </Card>
      </div>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={editing ? t("vuln.scanSchedules.editTitle") : t("vuln.scanSchedules.createTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setDrawerOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
              {saveMutation.isPending ? t("common.saving") : t("common.save")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("common.name")} required>
            <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <FormField label={t("vuln.scanSchedules.fieldScanType")}>
            <Select
              value={form.scanType}
              onChange={(v) => setForm((f) => ({ ...f, scanType: v }))}
              options={scanTypeOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("vuln.scanSchedules.fieldCronExpr")} required>
            <Input
              value={form.cronExpr}
              onChange={(e) => setForm((f) => ({ ...f, cronExpr: e.target.value }))}
              placeholder="0 2 * * *"
            />
          </FormField>
          <FormField label={t("vuln.scanSchedules.fieldEnabled")}>
            <Switch checked={form.enabled} onChange={(b) => setForm((f) => ({ ...f, enabled: b }))} />
          </FormField>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("vuln.scanSchedules.deleteTitle")}
        desc={deleting ? t("vuln.scanSchedules.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
