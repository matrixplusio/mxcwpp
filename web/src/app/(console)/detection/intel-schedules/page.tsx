"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { detectionApi } from "@/lib/api/detection";
import type { IntelSyncSchedule } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { FilterBar } from "@/components/ui/FilterBar";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { Switch } from "@/components/ui/Switch";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ScheduleForm {
  name: string;
  cronExpr: string;
  enabled: boolean;
}
const emptyForm: ScheduleForm = { name: "", cronExpr: "", enabled: true };

const statusTone = (s: string): "success" | "danger" | "warning" | "neutral" => {
  if (s === "success") return "success";
  if (s === "failed") return "danger";
  if (s === "running") return "warning";
  return "neutral";
};

export default function IntelSchedulesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["intel-schedules"],
    queryFn: () => detectionApi.listIntelSchedules(),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<IntelSyncSchedule | null>(null);
  const [form, setForm] = useState<ScheduleForm>(emptyForm);
  const [deleting, setDeleting] = useState<IntelSyncSchedule | null>(null);
  const [historyFor, setHistoryFor] = useState<IntelSyncSchedule | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["intel-schedules"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (s: IntelSyncSchedule) => {
    setEditing(s);
    setForm({ name: s.name, cronExpr: s.cronExpr, enabled: s.enabled });
    setDrawerOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: () =>
      editing
        ? detectionApi.updateIntelSchedule(editing.id, {
            name: form.name,
            cronExpr: form.cronExpr,
            enabled: form.enabled,
          })
        : detectionApi.createIntelSchedule({ name: form.name, cronExpr: form.cronExpr }),
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("detection.intelSchedules.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => detectionApi.deleteIntelSchedule(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("detection.intelSchedules.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleMutation = useMutation({
    mutationFn: (id: number) => detectionApi.toggleIntelSchedule(id),
    onSuccess: () => {
      invalidate();
      toast.success(t("detection.intelSchedules.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const runMutation = useMutation({
    mutationFn: (id: number) => detectionApi.runIntelSchedule(id),
    onSuccess: () => toast.success(t("detection.intelSchedules.triggered")),
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<IntelSyncSchedule>[] = [
    { key: "name", title: t("common.name"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    {
      key: "cronExpr",
      title: t("detection.intelSchedules.colCronExpr"),
      render: (r) => <span className="font-mono text-xs text-ink">{r.cronExpr}</span>,
    },
    {
      key: "enabled",
      title: t("detection.intelSchedules.colEnabled"),
      render: (r) => (
        <Switch checked={r.enabled} disabled={toggleMutation.isPending} onChange={() => toggleMutation.mutate(r.id)} />
      ),
    },
    { key: "lastRunAt", title: t("detection.intelSchedules.colLastRunAt"), render: (r) => <span className="text-faint tabular-nums">{r.lastRunAt || "—"}</span> },
    { key: "nextRunAt", title: t("detection.intelSchedules.colNextRunAt"), render: (r) => <span className="text-faint tabular-nums">{r.nextRunAt || "—"}</span> },
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
              runMutation.mutate(r.id);
            }}
          >
            {t("detection.intelSchedules.runNow")}
          </button>
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={(e) => {
              e.stopPropagation();
              setHistoryFor(r);
            }}
          >
            {t("detection.intelSchedules.history")}
          </button>
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
        <FilterBar extra={<Button onClick={openCreate}>{t("detection.intelSchedules.create")}</Button>}>
          <span className="text-sm text-muted">{t("detection.intelSchedules.subtitle")}</span>
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("detection.intelSchedules.empty")}
          />
        </Card>
      </div>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={editing ? t("detection.intelSchedules.editTitle") : t("detection.intelSchedules.createTitle")}
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
          <FormField label={t("detection.intelSchedules.fieldCronExpr")} required>
            <Input
              value={form.cronExpr}
              onChange={(e) => setForm((f) => ({ ...f, cronExpr: e.target.value }))}
              placeholder="0 0 3 * * *"
            />
          </FormField>
          <p className="text-xs text-faint">{t("detection.intelSchedules.cronHint")}</p>
          <FormField label={t("detection.intelSchedules.fieldEnabled")}>
            <Switch checked={form.enabled} onChange={(b) => setForm((f) => ({ ...f, enabled: b }))} />
          </FormField>
        </div>
      </Drawer>

      <ExecutionsDrawer schedule={historyFor} onClose={() => setHistoryFor(null)} statusTone={statusTone} />

      <ConfirmDialog
        open={!!deleting}
        title={t("detection.intelSchedules.deleteTitle")}
        desc={deleting ? t("detection.intelSchedules.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}

function ExecutionsDrawer({
  schedule,
  onClose,
  statusTone,
}: {
  schedule: IntelSyncSchedule | null;
  onClose: () => void;
  statusTone: (s: string) => "success" | "danger" | "warning" | "neutral";
}) {
  const { t } = useTranslation();
  const { data, isLoading } = useQuery({
    queryKey: ["intel-executions", schedule?.id],
    queryFn: () => detectionApi.listIntelExecutions(schedule!.id, { page: 1, pageSize: 50 }),
    enabled: !!schedule,
  });

  return (
    <Drawer open={!!schedule} onClose={onClose} title={t("detection.intelSchedules.historyTitle", { name: schedule?.name ?? "" })}>
      {isLoading ? (
        <p className="text-sm text-muted">{t("common.loading")}</p>
      ) : (data?.items.length ?? 0) === 0 ? (
        <p className="text-sm text-muted">{t("detection.intelSchedules.noHistory")}</p>
      ) : (
        <div className="space-y-2">
          {data!.items.map((ex) => (
            <div key={ex.id} className="rounded-md border border-line p-3 text-sm">
              <div className="flex items-center justify-between">
                <StatusTag tone={statusTone(ex.status)}>{ex.status}</StatusTag>
                <span className="text-faint tabular-nums">{ex.startedAt}</span>
              </div>
              <div className="mt-2 flex gap-4 text-xs text-muted">
                <span>{t("detection.intelSchedules.iocCount")}: {ex.iocCount}</span>
                <span>{t("detection.intelSchedules.duration")}: {ex.duration}s</span>
              </div>
              {ex.errorMsg && <p className="mt-2 break-all text-xs text-danger">{ex.errorMsg}</p>}
            </div>
          ))}
        </div>
      )}
    </Drawer>
  );
}
