"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ShieldCheck, CheckCircle, PauseCircle, AlertTriangle } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { detectionApi } from "@/lib/api/detection";
import type { DetectionRule, Severity } from "@/lib/api/types";
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
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { RuleLifecycle, StageBadge } from "./_components/RuleLifecycle";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  keyword: string;
  severity: string;
  category: string;
  enabled: string;
}

interface RuleForm {
  name: string;
  severity: Severity;
  category: string;
  mitreId: string;
  expression: string;
  enabled: boolean;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const severityLabel = (t: TFunction, s: Severity) => t(`common.severity.${s}`);
function isSeverity(v: string): v is Severity {
  return (SEVERITIES as string[]).includes(v);
}

const buildSeverityOptions = (t: TFunction) => [
  { label: t("common.allSeverity"), value: "" },
  ...SEVERITIES.map((s) => ({ label: severityLabel(t, s), value: s })),
];
const buildEnabledOptions = (t: TFunction) => [
  { label: t("common.allStatus"), value: "" },
  { label: t("common.enabled"), value: "true" },
  { label: t("common.disabled"), value: "false" },
];
const buildSeverityFormOptions = (t: TFunction) => SEVERITIES.map((s) => ({ label: severityLabel(t, s), value: s }));

const emptyForm: RuleForm = { name: "", severity: "medium", category: "", mitreId: "", expression: "", enabled: true };

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="break-all text-ink">{value}</span>
    </div>
  );
}

export default function DetectionRulesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const severityOptions = buildSeverityOptions(t);
  const enabledOptions = buildEnabledOptions(t);
  const severityFormOptions = buildSeverityFormOptions(t);
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    keyword: "",
    severity: "",
    category: "",
    enabled: "",
  });

  const { data: stats, isError: statsError } = useQuery({
    queryKey: ["det-rules-stats"],
    queryFn: () => detectionApi.ruleStats(),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["det-rules", params],
    queryFn: () =>
      detectionApi.listRules({
        page: params.page,
        page_size: params.page_size,
        keyword: params.keyword || undefined,
        severity: params.severity || undefined,
        category: params.category || undefined,
        enabled: params.enabled || undefined,
      }),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<DetectionRule | null>(null);
  const [form, setForm] = useState<RuleForm>(emptyForm);
  const [detail, setDetail] = useState<DetectionRule | null>(null);
  const [deleting, setDeleting] = useState<DetectionRule | null>(null);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["det-rules"] });
    queryClient.invalidateQueries({ queryKey: ["det-rules-stats"] });
  };

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (r: DetectionRule) => {
    setEditing(r);
    setForm({
      name: r.name,
      severity: r.severity,
      category: r.category,
      mitreId: r.mitreId,
      expression: r.expression,
      enabled: r.enabled,
    });
    setDrawerOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: () => {
      const body: Partial<DetectionRule> = {
        name: form.name,
        severity: form.severity,
        category: form.category,
        mitreId: form.mitreId,
        expression: form.expression,
        enabled: form.enabled,
      };
      return editing ? detectionApi.updateRule(editing.id, body) : detectionApi.createRule(body);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("common.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleMutation = useMutation({
    mutationFn: (id: number) => detectionApi.toggleRule(id),
    onSuccess: () => {
      invalidate();
      toast.success(t("common.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => detectionApi.deleteRule(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("common.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<DetectionRule>[] = [
    { key: "name", title: t("detection.rules.colName"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    { key: "severity", title: t("common.level"), render: (r) => <SeverityTag level={r.severity} /> },
    {
      key: "stage",
      title: t("detection.rules.colStage"),
      render: (r) => <StageBadge stage={r.stage} />,
    },
    { key: "category", title: t("detection.rules.colCategory"), render: (r) => <StatusTag tone="neutral">{r.category || "—"}</StatusTag> },
    {
      key: "mitreId",
      title: t("detection.rules.colMitreId"),
      render: (r) => <span className="font-mono text-xs text-faint">{r.mitreId || "—"}</span>,
    },
    {
      key: "dataTypes",
      title: t("detection.rules.colDataTypes"),
      render: (r) => <span className="text-faint">{r.dataTypes?.length ? r.dataTypes.join(", ") : "—"}</span>,
    },
    {
      key: "enabled",
      title: t("detection.rules.colEnabled"),
      render: (r) => (
        <div onClick={(e) => e.stopPropagation()}>
          <Switch checked={r.enabled} onChange={() => toggleMutation.mutate(r.id)} disabled={toggleMutation.isPending} />
        </div>
      ),
    },
    {
      key: "builtin",
      title: t("detection.rules.colSource"),
      render: (r) => <StatusTag tone="neutral">{r.builtin ? t("detection.rules.sourceBuiltin") : t("detection.rules.sourceCustom")}</StatusTag>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          <button type="button" className="text-sm text-muted transition-colors hover:text-ink" onClick={() => openEdit(r)}>
            {t("common.edit")}
          </button>
          {!r.builtin && (
            <button
              type="button"
              className="text-sm text-danger transition-colors hover:opacity-80"
              onClick={() => setDeleting(r)}
            >
              {t("common.delete")}
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard compact label={t("detection.rules.statTotal")} value={stats?.total ?? 0} error={statsError} icon={ShieldCheck} tone="default" />
        <StatCard compact label={t("detection.rules.statEnabled")} value={stats?.enabled ?? 0} error={statsError} icon={CheckCircle} tone="success" />
        <StatCard compact label={t("detection.rules.statDisabled")} value={stats?.disabled ?? 0} error={statsError} icon={PauseCircle} tone="warning" />
        <StatCard compact label={t("detection.rules.statCritical")} value={stats?.severity?.critical ?? 0} error={statsError} icon={AlertTriangle} tone="danger" />
      </div>

      <div className="space-y-4">
        <FilterBar extra={<Button onClick={openCreate}>{t("detection.rules.create")}</Button>}>
          <SearchInput
            value={params.keyword}
            onChange={(v) => setParams((p) => ({ ...p, keyword: v, page: 1 }))}
            placeholder={t("detection.rules.searchPlaceholder")}
          />
          <Select
            value={params.severity}
            onChange={(v) => setParams((p) => ({ ...p, severity: v, page: 1 }))}
            options={severityOptions}
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
            emptyText={t("detection.rules.empty")}
            onRowClick={setDetail}
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
        title={editing ? t("detection.rules.editTitle") : t("detection.rules.createTitle")}
        width={560}
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
          <FormField label={t("detection.rules.fieldName")} required>
            <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <FormField label={t("detection.rules.fieldSeverity")}>
            <Select
              value={form.severity}
              onChange={(v) => setForm((f) => ({ ...f, severity: isSeverity(v) ? v : f.severity }))}
              options={severityFormOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("detection.rules.fieldCategory")}>
            <Input value={form.category} onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))} />
          </FormField>
          <FormField label={t("detection.rules.fieldMitreId")}>
            <Input value={form.mitreId} onChange={(e) => setForm((f) => ({ ...f, mitreId: e.target.value }))} />
          </FormField>
          <FormField label={t("detection.rules.fieldExpression")} required>
            <Textarea
              className="min-h-32 font-mono"
              value={form.expression}
              onChange={(e) => setForm((f) => ({ ...f, expression: e.target.value }))}
            />
          </FormField>
          <FormField label={t("detection.rules.fieldEnabled")}>
            <Switch checked={form.enabled} onChange={(v) => setForm((f) => ({ ...f, enabled: v }))} />
          </FormField>
        </div>
      </Drawer>

      <Drawer open={!!detail} onClose={() => setDetail(null)} title={t("detection.rules.detailTitle")} width={560}>
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold text-ink">{detail.name}</h2>
              <div className="flex items-center gap-2">
                <SeverityTag level={detail.severity} />
                <StatusTag tone="neutral">{detail.builtin ? t("detection.rules.sourceBuiltin") : t("detection.rules.sourceCustom")}</StatusTag>
                <StatusTag tone={detail.enabled ? "success" : "neutral"}>{detail.enabled ? t("common.enabled") : t("common.disabled")}</StatusTag>
              </div>
            </div>
            <div className="space-y-2">
              <Field label={t("detection.rules.fieldCategory")} value={detail.category || "—"} />
              <Field label={t("detection.rules.fieldMitreId")} value={<span className="font-mono">{detail.mitreId || "—"}</span>} />
              <Field label={t("detection.rules.fieldDataTypes")} value={detail.dataTypes?.length ? detail.dataTypes.join(", ") : "—"} />
            </div>
            {/* 生命周期与检测质量：决定这条规则会不会打扰到人，
                以及凭什么认为它够格。 */}
            <RuleLifecycle rule={detail} />
            {detail.description && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("detection.rules.description")}</div>
                <p className="text-sm leading-relaxed text-muted">{detail.description}</p>
              </div>
            )}
            <div>
              <div className="mb-1.5 text-sm font-medium text-ink">{t("detection.rules.expression")}</div>
              <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                {detail.expression}
              </pre>
            </div>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("detection.rules.deleteTitle")}
        desc={deleting ? t("detection.rules.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
