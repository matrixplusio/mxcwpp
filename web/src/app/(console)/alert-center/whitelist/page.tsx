"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { whitelistApi, type WhitelistParams } from "@/lib/api/alerts";
import type { AlertWhitelist, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DateTimeCell } from "@/components/ui/DateTimeCell";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Input, Textarea } from "@/components/ui/Input";
import { SeverityTag, StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface WhitelistForm {
  name: string;
  rule_id: string;
  host_id: string;
  category: string;
  severity: string;
  exe: string;
  cmdline: string;
  source_ip_cidr: string;
  reason: string;
  /** 新建为有效期，编辑为续期天数（空 = 不续期） */
  days: string;
}

const knownSeverities: Severity[] = ["critical", "high", "medium", "low"];
const isSeverity = (v: string): v is Severity => knownSeverities.includes(v as Severity);

const emptyForm: WhitelistForm = {
  name: "",
  rule_id: "",
  host_id: "",
  category: "",
  severity: "",
  exe: "",
  cmdline: "",
  source_ip_cidr: "",
  reason: "",
  days: "30",
};

type EntryState = "active" | "expired" | "disabled";

function entryState(w: AlertWhitelist, now = Date.now()): EntryState {
  if (!w.enabled) return "disabled";
  if (w.expires_at && new Date(w.expires_at.replace(" ", "T")).getTime() <= now) return "expired";
  return "active";
}

const stateTone: Record<EntryState, "success" | "warning" | "neutral"> = {
  active: "success",
  expired: "warning",
  disabled: "neutral",
};

// 条目原样回写，只改启停或到期：后端 PUT 是整条覆盖。
const bodyOf = (w: AlertWhitelist): WhitelistParams => ({
  name: w.name,
  rule_id: w.rule_id || undefined,
  host_id: w.host_id || undefined,
  category: w.category || undefined,
  severity: w.severity || undefined,
  exe: w.exe || undefined,
  cmdline: w.cmdline || undefined,
  source_ip_cidr: w.source_ip_cidr || undefined,
  reason: w.reason || undefined,
});

export default function WhitelistPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, keyword: "", status: "" });

  const statusOptions = [
    { label: t("alerts.whitelist.filterAllStatus"), value: "" },
    { label: t("alerts.whitelist.statusActive"), value: "active" },
    { label: t("alerts.whitelist.filterExpiring"), value: "expiring" },
    { label: t("alerts.whitelist.statusExpired"), value: "expired" },
    { label: t("alerts.whitelist.statusDisabled"), value: "disabled" },
  ];

  const severityOptions = [
    { label: t("common.all"), value: "" },
    { label: t("common.severity.critical"), value: "critical" },
    { label: t("common.severity.high"), value: "high" },
    { label: t("common.severity.medium"), value: "medium" },
    { label: t("common.severity.low"), value: "low" },
  ];

  const { data, isLoading } = useQuery({
    queryKey: ["alert-whitelist", params],
    queryFn: () =>
      whitelistApi.list({
        page: params.page,
        page_size: params.page_size,
        keyword: params.keyword || undefined,
        status:
          params.status === "active" || params.status === "expired" || params.status === "disabled"
            ? params.status
            : undefined,
        expiring_days: params.status === "expiring" ? 30 : undefined,
      }),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<AlertWhitelist | null>(null);
  const [form, setForm] = useState<WhitelistForm>(emptyForm);
  const [deleting, setDeleting] = useState<AlertWhitelist | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["alert-whitelist"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (w: AlertWhitelist) => {
    setEditing(w);
    setForm({
      name: w.name,
      rule_id: w.rule_id,
      host_id: w.host_id,
      category: w.category,
      severity: w.severity,
      exe: w.exe,
      cmdline: w.cmdline,
      source_ip_cidr: w.source_ip_cidr,
      reason: w.reason,
      days: "",
    });
    setDrawerOpen(true);
  };

  const buildBody = (f: WhitelistForm): WhitelistParams => ({
    name: f.name,
    rule_id: f.rule_id || undefined,
    host_id: f.host_id || undefined,
    category: f.category || undefined,
    severity: f.severity || undefined,
    exe: f.exe || undefined,
    cmdline: f.cmdline || undefined,
    source_ip_cidr: f.source_ip_cidr || undefined,
    reason: f.reason || undefined,
    expires_in_days: Number(f.days) || undefined,
  });

  const saveMutation = useMutation({
    mutationFn: () => {
      const body = buildBody(form);
      return editing ? whitelistApi.update(editing.id, body) : whitelistApi.create(body);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("alerts.whitelist.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const patchMutation = useMutation({
    mutationFn: ({ w, patch }: { w: AlertWhitelist; patch: Partial<WhitelistParams> }) =>
      whitelistApi.update(w.id, { ...bodyOf(w), ...patch }),
    onSuccess: () => {
      invalidate();
      toast.success(t("alerts.whitelist.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const critical = form.severity === "critical" || form.severity === "";
  const hasEvidence = !!(form.exe.trim() || form.cmdline.trim() || form.source_ip_cidr.trim());

  const deleteMutation = useMutation({
    mutationFn: (id: number) => whitelistApi.delete(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("alerts.whitelist.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<AlertWhitelist>[] = [
    {
      // 创建人、到期时间分别并进名称列和状态列：八列在 1280 宽下放不下
      key: "name",
      title: t("common.name"),
      render: (r) => (
        <div className="min-w-[6rem] max-w-[8rem]">
          <div className="font-medium text-ink">{r.name}</div>
          {r.created_by && <div title={r.created_by} className="truncate text-xs text-faint">{t("alerts.whitelist.createdByLine", { name: r.created_by })}</div>}
        </div>
      ),
    },
    {
      // 七个匹配维度合成一列，只列出填了的：分列时表格过宽，操作按钮被挤出视野。
      key: "conditions",
      title: t("alerts.whitelist.colConditions"),
      render: (r) => {
        const items: [string, React.ReactNode][] = [];
        if (r.rule_id) items.push([t("alerts.whitelist.colRuleId"), r.rule_id]);
        if (r.host_id) items.push([t("alerts.whitelist.colHostId"), r.host_id]);
        if (r.category) items.push([t("common.category"), r.category]);
        if (isSeverity(r.severity)) items.push([t("common.level"), <SeverityTag key="sev" level={r.severity} />]);
        if (r.exe) items.push([t("alerts.whitelist.colExe"), r.exe]);
        if (r.cmdline) items.push([t("alerts.whitelist.colCmdline"), r.cmdline]);
        if (r.source_ip_cidr) items.push([t("alerts.whitelist.colSourceIpCidr"), r.source_ip_cidr]);
        return (
          <div className="space-y-0.5">
            {items.map(([label, value]) => (
              <div key={label} className="flex gap-2 text-xs">
                <span className="shrink-0 text-faint">{label}</span>
                <span title={typeof value === "string" ? value : undefined} className="block max-w-[8rem] truncate font-mono text-ink">{value}</span>
              </div>
            ))}
          </div>
        );
      },
    },
    {
      key: "reason",
      title: t("alerts.whitelist.colReason"),
      // 两行截断而非单行：单行 truncate 不能换行，会把整张表撑出横向滚动
      render: (r) => <span title={r.reason} className="line-clamp-2 max-w-[9rem] text-muted">{r.reason || "—"}</span>,
    },
    {
      key: "state",
      title: t("alerts.whitelist.colStatus"),
      render: (r) => {
        const st = entryState(r);
        const label = { active: "statusActive", expired: "statusExpired", disabled: "statusDisabled" }[st];
        return (
          <div className="space-y-1 whitespace-nowrap">
            <StatusTag tone={stateTone[st]}>{t(`alerts.whitelist.${label}`)}</StatusTag>
            <div className="text-xs text-faint tabular-nums">
              {r.expires_at ? t("alerts.whitelist.expiresLine", { date: r.expires_at.slice(0, 10) }) : t("alerts.whitelist.noExpiry")}
            </div>
          </div>
        );
      },
    },
    {
      key: "suppressed_hits",
      title: t("alerts.whitelist.colHits"),
      render: (r) => (
        <div>
          <div className="tabular-nums text-ink">{r.suppressed_hits ?? 0}</div>
          {r.last_suppressed_at && <DateTimeCell value={r.last_suppressed_at} className="text-xs text-faint" />}
        </div>
      ),
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2 whitespace-nowrap">
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink disabled:opacity-50"
            disabled={patchMutation.isPending}
            onClick={() => patchMutation.mutate({ w: r, patch: { expires_in_days: 30 } })}
            title={t("alerts.whitelist.renewTitle")}
          >
            {t("alerts.whitelist.renew")}
          </button>
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink disabled:opacity-50"
            disabled={patchMutation.isPending}
            onClick={() => patchMutation.mutate({ w: r, patch: { enabled: !r.enabled } })}
          >
            {r.enabled ? t("alerts.whitelist.disable") : t("alerts.whitelist.enable")}
          </button>
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={() => openEdit(r)}
          >
            {t("common.edit")}
          </button>
          <button
            type="button"
            className="text-sm text-danger transition-colors hover:opacity-80"
            onClick={() => setDeleting(r)}
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
        <FilterBar extra={<Button onClick={openCreate}>{t("alerts.whitelist.create")}</Button>}>
          <SearchInput
            value={params.keyword}
            onChange={(v) => setParams((p) => ({ ...p, keyword: v, page: 1 }))}
            placeholder={t("alerts.whitelist.searchPlaceholder")}
          />
          <Select
            value={params.status}
            onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))}
            options={statusOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("alerts.whitelist.empty")}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={editing ? t("alerts.whitelist.editTitle") : t("alerts.whitelist.createTitle")}
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
          <FormField label={t("alerts.whitelist.colRuleId")}>
            <Input value={form.rule_id} onChange={(e) => setForm((f) => ({ ...f, rule_id: e.target.value }))} />
          </FormField>
          <FormField label={t("alerts.whitelist.colHostId")}>
            <Input value={form.host_id} onChange={(e) => setForm((f) => ({ ...f, host_id: e.target.value }))} />
          </FormField>
          <FormField label={t("common.category")}>
            <Input value={form.category} onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))} />
          </FormField>
          <FormField label={t("common.level")}>
            <Select
              value={form.severity}
              onChange={(v) => setForm((f) => ({ ...f, severity: v }))}
              options={severityOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("alerts.whitelist.colExe")}>
            <Input
              value={form.exe}
              onChange={(e) => setForm((f) => ({ ...f, exe: e.target.value }))}
              placeholder={t("alerts.whitelist.exePlaceholder")}
            />
          </FormField>
          <FormField label={t("alerts.whitelist.colCmdline")}>
            <Input
              value={form.cmdline}
              onChange={(e) => setForm((f) => ({ ...f, cmdline: e.target.value }))}
              placeholder={t("alerts.whitelist.cmdlinePlaceholder")}
            />
          </FormField>
          <FormField label={t("alerts.whitelist.colSourceIpCidr")}>
            <Input
              value={form.source_ip_cidr}
              onChange={(e) => setForm((f) => ({ ...f, source_ip_cidr: e.target.value }))}
              placeholder={t("alerts.whitelist.sourceIpPlaceholder")}
            />
          </FormField>
          {critical && (
            <p className={`text-xs ${form.severity === "critical" && !hasEvidence ? "text-danger" : "text-faint"}`}>
              {t("alerts.whitelist.criticalHint")}
            </p>
          )}
          <FormField label={editing ? t("alerts.whitelist.renewDays") : t("alerts.whitelist.expiresInDays")}>
            <Input
              type="number"
              min={1}
              max={90}
              value={form.days}
              onChange={(e) => setForm((f) => ({ ...f, days: e.target.value }))}
            />
            <p className="mt-1 text-xs text-faint">
              {editing ? t("alerts.whitelist.renewHint") : t("alerts.whitelist.expiresHint")}
            </p>
          </FormField>
          <FormField label={t("alerts.whitelist.colReason")} required>
            <Textarea
              value={form.reason}
              onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value }))}
              placeholder={t("alerts.whitelist.reasonPlaceholder")}
            />
          </FormField>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("alerts.whitelist.deleteTitle")}
        desc={deleting ? t("alerts.whitelist.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
