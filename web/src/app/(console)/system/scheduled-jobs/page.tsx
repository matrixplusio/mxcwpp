"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { systemApi } from "@/lib/api/system";
import type { ScheduledJob } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Modal } from "@/components/ui/Modal";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Select } from "@/components/ui/Select";
import { Switch } from "@/components/ui/Switch";
import { Button } from "@/components/ui/Button";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

const pad = (n: number) => String(n).padStart(2, "0");

const hourOptions = Array.from({ length: 24 }, (_, h) => ({ value: String(h), label: `${pad(h)}:00` }));

// 一天内的执行时刻：间隔不足 24 小时时从开始时刻起按间隔排开。
function slotsOf(startHour: number, intervalHours: number): string {
  if (intervalHours >= 24) return `${pad(startHour)}:00`;
  const hours: number[] = [];
  for (let h = startHour % intervalHours; h < 24; h += intervalHours) hours.push(h);
  return hours.map((h) => `${pad(h)}:00`).join(" · ");
}

function formatNext(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const statusTone: Record<string, "success" | "danger" | "info" | "warning" | "neutral"> = {
  ok: "success",
  failed: "danger",
  running: "info",
  interrupted: "warning",
};

interface JobForm {
  intervalHours: number;
  startHour: number;
  enabled: boolean;
}

export default function ScheduledJobsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["sys-scheduled-jobs"],
    queryFn: () => systemApi.listScheduledJobs(),
    refetchInterval: 15000,
  });

  const [editing, setEditing] = useState<ScheduledJob | null>(null);
  const [form, setForm] = useState<JobForm>({ intervalHours: 24, startHour: 4, enabled: true });
  const [running, setRunning] = useState<ScheduledJob | null>(null);

  const intervalLabel = (h: number) =>
    h < 24 ? t("system.jobs.everyHours", { n: h }) : h === 24 ? t("system.jobs.daily") : t("system.jobs.everyDays", { n: h / 24 });

  const openEdit = (j: ScheduledJob) => {
    setEditing(j);
    setForm({ intervalHours: j.intervalHours, startHour: j.startHour, enabled: j.enabled });
  };

  const saveMutation = useMutation({
    mutationFn: () => systemApi.updateScheduledJob(editing!.jobKey, form),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sys-scheduled-jobs"] });
      setEditing(null);
      toast.success(t("system.jobs.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const runMutation = useMutation({
    mutationFn: (key: string) => systemApi.runScheduledJob(key),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sys-scheduled-jobs"] });
      setRunning(null);
      toast.success(t("system.jobs.started"));
    },
    onError: (e: Error) => {
      setRunning(null);
      toast.error(e.message);
    },
  });

  const columns: Column<ScheduledJob>[] = [
    {
      key: "name",
      title: t("system.jobs.colJob"),
      render: (r) => (
        <div>
          <div className="flex items-center gap-2">
            <span className="font-medium text-ink">{r.name}</span>
            {r.touchesHosts && <StatusTag tone="warning">{t("system.jobs.touchesHosts")}</StatusTag>}
          </div>
          <p className="mt-0.5 text-xs text-muted">{r.description}</p>
        </div>
      ),
    },
    {
      key: "schedule",
      nowrap: true,
      title: t("system.jobs.colSchedule"),
      render: (r) =>
        r.enabled ? (
          <div className="tabular-nums">
            <div className="text-ink">{intervalLabel(r.intervalHours)}</div>
            <div className="text-xs text-muted">{slotsOf(r.startHour, r.intervalHours)}</div>
          </div>
        ) : (
          <StatusTag tone="neutral">{t("system.jobs.disabled")}</StatusTag>
        ),
    },
    {
      key: "next",
      nowrap: true,
      title: t("system.jobs.colNext"),
      render: (r) => <span className="tabular-nums text-muted">{r.enabled ? formatNext(r.nextRunAt) : "—"}</span>,
    },
    {
      key: "last",
      nowrap: true,
      title: t("system.jobs.colLast"),
      render: (r) =>
        r.lastRunAt ? (
          <div>
            <div className="flex items-center gap-2">
              <span className="tabular-nums text-muted">{r.lastRunAt}</span>
              {r.lastStatus && (
                <StatusTag tone={statusTone[r.lastStatus] ?? "neutral"}>{t(`system.jobs.status.${r.lastStatus}`, r.lastStatus)}</StatusTag>
              )}
            </div>
            {r.lastStatus === "failed" && r.lastError && (
              <p className="mt-0.5 max-w-xs truncate text-xs text-danger" title={r.lastError}>
                {r.lastError}
              </p>
            )}
          </div>
        ) : (
          <span className="text-faint">{t("system.jobs.neverRun")}</span>
        ),
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-1">
          {!r.external && (
            <Button
              variant="ghost"
              className="h-8 px-3"
              disabled={r.lastStatus === "running"}
              onClick={() => setRunning(r)}
            >
              {t("system.jobs.runNow")}
            </Button>
          )}
          <Button variant="ghost" className="h-8 px-3" onClick={() => openEdit(r)}>
            {t("common.edit")}
          </Button>
        </div>
      ),
    },
  ];

  const intervalOptions = (data?.intervals ?? [24]).map((h) => ({ value: String(h), label: intervalLabel(h) }));

  return (
    <>
      <p className="mb-4 text-sm text-muted">{t("system.jobs.intro")}</p>
      <Card>
        <DataTable
          columns={columns}
          rows={data?.items ?? []}
          rowKey={(r) => r.jobKey}
          loading={isLoading}
          emptyText={t("system.jobs.empty")}
        />
      </Card>

      <Modal
        open={!!editing}
        onClose={() => setEditing(null)}
        title={t("system.jobs.editTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditing(null)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
              {saveMutation.isPending ? t("common.saving") : t("common.save")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("system.jobs.colJob")}>
            <p className="text-sm text-ink">{editing?.name}</p>
            <p className="mt-0.5 text-xs text-muted">{editing?.description}</p>
          </FormField>
          <FormField label={t("system.jobs.fieldInterval")}>
            {editing?.fixedInterval ? (
              <p className="text-sm text-ink">{intervalLabel(form.intervalHours)}</p>
            ) : (
              <Select
                value={String(form.intervalHours)}
                onChange={(v) => setForm((f) => ({ ...f, intervalHours: Number(v) }))}
                options={intervalOptions}
                className="w-full"
              />
            )}
          </FormField>
          <FormField label={t("system.jobs.fieldStartHour")}>
            <Select
              value={String(form.startHour)}
              onChange={(v) => setForm((f) => ({ ...f, startHour: Number(v) }))}
              options={hourOptions}
              className="w-full"
            />
            <p className="mt-1 text-xs text-muted">
              {t("system.jobs.slotsPreview", { slots: slotsOf(form.startHour, form.intervalHours) })}
            </p>
          </FormField>
          <FormField label={t("system.jobs.fieldEnabled")}>
            <Switch checked={form.enabled} onChange={(v) => setForm((f) => ({ ...f, enabled: v }))} />
          </FormField>
        </div>
      </Modal>

      <ConfirmDialog
        open={!!running}
        title={t("system.jobs.runNowTitle")}
        desc={
          running
            ? t(running.touchesHosts ? "system.jobs.runNowDescHosts" : "system.jobs.runNowDesc", { name: running.name })
            : undefined
        }
        loading={runMutation.isPending}
        onConfirm={() => running && runMutation.mutate(running.jobKey)}
        onCancel={() => setRunning(null)}
      />
    </>
  );
}
