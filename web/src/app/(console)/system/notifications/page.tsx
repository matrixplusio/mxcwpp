"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { systemApi } from "@/lib/api/system";
import type { Notification, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
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
import { Switch } from "@/components/ui/Switch";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";
import { cn } from "@/lib/utils/cn";
import { useUrlState } from "@/hooks/useUrlState";

interface ListParams {
  page: number;
  page_size: number;
  keyword: string;
  enabled: string; // "" = 全部, "true", "false"
}

interface NotificationForm {
  name: string;
  description: string;
  type: "lark" | "webhook";
  notify_category: string;
  enabled: boolean;
  severities: Severity[];
  scope: string;
  webhook_url: string;
  secret: string;
  user_notes: string;
}

const buildEnabledOptions = (t: TFunction) => [
  { label: t("common.all"), value: "" },
  { label: t("common.enabled"), value: "true" },
  { label: t("common.disabled"), value: "false" },
];

const buildTypeOptions = (t: TFunction) => [
  { label: t("system.notifications.typeLark"), value: "lark" },
  { label: t("system.notifications.typeWebhook"), value: "webhook" },
];

const buildTypeLabels = (t: TFunction): Record<string, string> => ({
  lark: t("system.notifications.typeLark"),
  webhook: t("system.notifications.typeWebhook"),
});

const buildCategoryLabels = (t: TFunction): Record<string, string> => ({
  baseline_alert: t("system.notifications.categoryBaselineAlert"),
  agent_offline: t("system.notifications.categoryAgentOffline"),
  virus_alert: t("system.notifications.categoryVirusAlert"),
  fim_alert: t("system.notifications.categoryFimAlert"),
  detection: t("system.notifications.categoryDetection"),
  kube_alert: t("system.notifications.categoryKubeAlert"),
  vuln_bulletin: t("system.notifications.categoryVulnBulletin"),
  infra_alert: t("system.notifications.categoryInfraAlert"),
  anomaly_alert: t("system.notifications.categoryAnomalyAlert"),
  behavior_alert: t("system.notifications.categoryBehaviorAlert"),
  ad_audit_alert: t("system.notifications.categoryAdAuditAlert"),
  incident: t("system.notifications.categoryIncident"),
});

const buildSeverityChips = (t: TFunction): { value: Severity; label: string }[] => [
  { value: "critical", label: t("common.severity.critical") },
  { value: "high", label: t("common.severity.high") },
  { value: "medium", label: t("common.severity.medium") },
  { value: "low", label: t("common.severity.low") },
];

const buildScopeOptions = (t: TFunction) => [
  { label: t("system.notifications.scopeGlobal"), value: "global" },
  { label: t("system.notifications.scopeHostTags"), value: "host_tags" },
  { label: t("system.notifications.scopeBusinessLine"), value: "business_line" },
  { label: t("system.notifications.scopeSpecified"), value: "specified" },
];

const knownSeverities: Severity[] = ["critical", "high", "medium", "low"];

const emptyForm: NotificationForm = {
  name: "",
  description: "",
  type: "webhook",
  notify_category: "baseline_alert",
  enabled: true,
  severities: [],
  scope: "global",
  webhook_url: "",
  secret: "",
  user_notes: "",
};

export default function NotificationsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, keyword: "", enabled: "" });

  const enabledOptions = buildEnabledOptions(t);
  const typeOptions = buildTypeOptions(t);
  const typeLabels = buildTypeLabels(t);
  const categoryLabels = buildCategoryLabels(t);
  const categoryOptions = Object.entries(categoryLabels).map(([value, label]) => ({ label, value }));
  const severityChips = buildSeverityChips(t);
  const scopeOptions = buildScopeOptions(t);

  const { data, isLoading } = useQuery({
    queryKey: ["sys-notifications", params],
    queryFn: () =>
      systemApi.listNotifications({
        page: params.page,
        page_size: params.page_size,
        keyword: params.keyword || undefined,
        enabled: params.enabled === "" ? undefined : params.enabled === "true",
      }),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<Notification | null>(null);
  const [form, setForm] = useState<NotificationForm>(emptyForm);
  const [deleting, setDeleting] = useState<Notification | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["sys-notifications"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (n: Notification) => {
    setEditing(n);
    setForm({
      name: n.name,
      description: n.description ?? "",
      type: n.type,
      notify_category: n.notify_category,
      enabled: n.enabled,
      severities: n.severities.filter((s): s is Severity => knownSeverities.includes(s as Severity)),
      scope: n.scope || "global",
      webhook_url: n.config?.webhook_url ?? "",
      secret: n.config?.secret ?? "",
      user_notes: n.config?.user_notes ?? "",
    });
    setDrawerOpen(true);
  };

  const buildBody = (f: NotificationForm): Partial<Notification> => ({
    name: f.name,
    description: f.description || undefined,
    type: f.type,
    notify_category: f.notify_category,
    enabled: f.enabled,
    severities: f.severities,
    scope: f.scope,
    config: {
      webhook_url: f.webhook_url,
      secret: f.secret || undefined,
      user_notes: f.user_notes || undefined,
    },
  });

  const saveMutation = useMutation({
    mutationFn: () => {
      const body = buildBody(form);
      return editing ? systemApi.updateNotification(editing.id, body) : systemApi.createNotification(body);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("system.notifications.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleMutation = useMutation({
    mutationFn: (n: Notification) => systemApi.updateNotification(n.id, { enabled: !n.enabled }),
    onSuccess: () => {
      invalidate();
      toast.success(t("system.notifications.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => systemApi.deleteNotification(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("system.notifications.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const testMutation = useMutation({
    mutationFn: (n: Notification) => systemApi.testNotification(n),
    onSuccess: () => toast.success(t("system.notifications.testSent")),
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleSeverity = (sev: Severity) => {
    setForm((f) => ({
      ...f,
      severities: f.severities.includes(sev) ? f.severities.filter((s) => s !== sev) : [...f.severities, sev],
    }));
  };

  const columns: Column<Notification>[] = [
    { key: "name", title: t("system.notifications.colName"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    {
      key: "notify_category",
      title: t("system.notifications.colCategory"),
      render: (r) => <StatusTag tone="info">{categoryLabels[r.notify_category] ?? r.notify_category}</StatusTag>,
    },
    {
      key: "type",
      title: t("system.notifications.colType"),
      render: (r) => <StatusTag tone="neutral">{typeLabels[r.type] ?? r.type}</StatusTag>,
    },
    {
      key: "enabled",
      title: t("system.notifications.colEnabled"),
      render: (r) => (
        <span onClick={(e) => e.stopPropagation()}>
          <Switch checked={r.enabled} onChange={() => toggleMutation.mutate(r)} disabled={toggleMutation.isPending} />
        </span>
      ),
    },
    {
      key: "severities",
      title: t("common.level"),
      render: (r) => {
        const sevs = r.severities.filter((s): s is Severity => knownSeverities.includes(s as Severity));
        if (sevs.length === 0) return <span className="text-faint">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {sevs.map((s) => (
              <SeverityTag key={s} level={s} />
            ))}
          </div>
        );
      },
    },
    {
      key: "created_at",
      title: t("common.createdAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.created_at}</span>,
    },
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
              testMutation.mutate(r);
            }}
          >
            {t("system.notifications.actionTest")}
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
        <FilterBar extra={<Button onClick={openCreate}>{t("system.notifications.create")}</Button>}>
          <SearchInput
            value={params.keyword}
            onChange={(v) => setParams((p) => ({ ...p, keyword: v, page: 1 }))}
            placeholder={t("system.notifications.searchPlaceholder")}
          />
          <Select
            value={params.enabled}
            onChange={(v) => setParams((p) => ({ ...p, enabled: v, page: 1 }))}
            options={enabledOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("system.notifications.empty")}
            onRowClick={openEdit}
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
        title={editing ? t("system.notifications.editTitle") : t("system.notifications.createTitle")}
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
          <FormField label={t("common.description")}>
            <Textarea
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </FormField>
          <FormField label={t("system.notifications.fieldType")}>
            <Select
              value={form.type}
              onChange={(v) => setForm((f) => ({ ...f, type: v as NotificationForm["type"] }))}
              options={typeOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("system.notifications.fieldCategory")}>
            <Select
              value={form.notify_category}
              onChange={(v) => setForm((f) => ({ ...f, notify_category: v }))}
              options={categoryOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("common.enabled")}>
            <Switch checked={form.enabled} onChange={(b) => setForm((f) => ({ ...f, enabled: b }))} />
          </FormField>
          <FormField label={t("common.level")}>
            <div className="flex flex-wrap gap-2">
              {severityChips.map((chip) => {
                const selected = form.severities.includes(chip.value);
                return (
                  <button
                    key={chip.value}
                    type="button"
                    onClick={() => toggleSeverity(chip.value)}
                    className={cn(
                      "rounded-full px-3 py-1 text-xs font-medium transition-colors",
                      selected ? "bg-primary text-white" : "bg-muted/10 text-muted hover:bg-muted/20",
                    )}
                  >
                    {chip.label}
                  </button>
                );
              })}
            </div>
          </FormField>
          <FormField label={t("system.notifications.fieldScope")}>
            <Select
              value={form.scope}
              onChange={(v) => setForm((f) => ({ ...f, scope: v }))}
              options={scopeOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("system.notifications.fieldWebhookUrl")} required>
            <Input
              value={form.webhook_url}
              onChange={(e) => setForm((f) => ({ ...f, webhook_url: e.target.value }))}
            />
          </FormField>
          <FormField label={t("system.notifications.fieldSecret")}>
            <Input value={form.secret} onChange={(e) => setForm((f) => ({ ...f, secret: e.target.value }))} />
          </FormField>
          <FormField label={t("system.notifications.fieldNotes")}>
            <Textarea
              value={form.user_notes}
              onChange={(e) => setForm((f) => ({ ...f, user_notes: e.target.value }))}
            />
          </FormField>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("system.notifications.deleteTitle")}
        desc={deleting ? t("system.notifications.deleteConfirmDesc", { name: deleting.name }) : undefined}
        danger
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
