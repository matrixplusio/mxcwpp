"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ListChecks, ToggleRight, ToggleLeft, Lock } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { kubeApi } from "@/lib/api/kube";
import type { KubeBaselineRule, KubeCheckConfig, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Input, Textarea } from "@/components/ui/Input";
import { Switch } from "@/components/ui/Switch";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  category: string;
  severity: string;
}

function isSeverity(v: string): v is Severity {
  return v === "critical" || v === "high" || v === "medium" || v === "low";
}

const buildSeverityFilterOptions = (t: TFunction) => [
  { label: t("kube.common.allSeverity"), value: "" },
  { label: t("common.severity.critical"), value: "critical" },
  { label: t("common.severity.high"), value: "high" },
  { label: t("common.severity.medium"), value: "medium" },
  { label: t("common.severity.low"), value: "low" },
];
const buildSeverityFormOptions = (t: TFunction) => [
  { label: t("common.severity.critical"), value: "critical" },
  { label: t("common.severity.high"), value: "high" },
  { label: t("common.severity.medium"), value: "medium" },
  { label: t("common.severity.low"), value: "low" },
];
const buildMatchPolicyOptions = (t: TFunction) => [
  { label: t("kube.baselineRules.matchAnyFail"), value: "any_match_fail" },
  { label: t("kube.baselineRules.matchNoneFail"), value: "no_match_fail" },
];

interface RuleForm {
  checkName: string;
  category: string;
  severity: Severity;
  resourceType: string;
  apiGroup: string;
  expression: string;
  matchPolicy: KubeCheckConfig["matchPolicy"];
  enabled: boolean;
}
const emptyForm: RuleForm = {
  checkName: "",
  category: "",
  severity: "medium",
  resourceType: "",
  apiGroup: "",
  expression: "",
  matchPolicy: "any_match_fail",
  enabled: true,
};

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-24 shrink-0 text-muted">{label}</span>
      <span className="min-w-0 break-words text-ink">{value}</span>
    </div>
  );
}

export default function KubeBaselineRulesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, category: "", severity: "" });

  const severityFilterOptions = buildSeverityFilterOptions(t);
  const severityFormOptions = buildSeverityFormOptions(t);
  const matchPolicyOptions = buildMatchPolicyOptions(t);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["kube-baseline-rules", params],
    queryFn: () =>
      kubeApi.listBaselineRules({
        page: params.page,
        page_size: params.page_size,
        category: params.category || undefined,
        severity: params.severity || undefined,
      }),
  });
  // 取不到就明说取不到：`?? 0` 会把"后端没答上来"渲染成 0，
  // 看板上读起来像"环境干净"。
  const statState = { error: isError, loading: isLoading };
  const stats = data?.stats;

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<KubeBaselineRule | null>(null);
  const [form, setForm] = useState<RuleForm>(emptyForm);
  const [detail, setDetail] = useState<KubeBaselineRule | null>(null);
  const [deleting, setDeleting] = useState<KubeBaselineRule | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["kube-baseline-rules"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (r: KubeBaselineRule) => {
    setEditing(r);
    setForm({
      checkName: r.checkName,
      category: r.category,
      severity: r.severity,
      resourceType: r.checkConfig?.resourceType ?? "",
      apiGroup: r.checkConfig?.apiGroup ?? "",
      expression: r.checkConfig?.expression ?? "",
      matchPolicy: r.checkConfig?.matchPolicy ?? "any_match_fail",
      enabled: r.enabled,
    });
    setDrawerOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: () => {
      const body: Partial<KubeBaselineRule> = {
        checkName: form.checkName,
        category: form.category,
        severity: form.severity,
        enabled: form.enabled,
        checkConfig: {
          resourceType: form.resourceType,
          apiGroup: form.apiGroup,
          namespace: editing?.checkConfig?.namespace ?? "",
          expression: form.expression,
          matchPolicy: form.matchPolicy,
        },
      };
      return editing ? kubeApi.updateBaselineRule(editing.id, body) : kubeApi.createBaselineRule(body);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("kube.baselineRules.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleMutation = useMutation({
    mutationFn: (r: KubeBaselineRule) => kubeApi.toggleBaselineRule(r.id),
    onSuccess: () => {
      invalidate();
      toast.success(t("kube.baselineRules.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => kubeApi.deleteBaselineRule(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("kube.baselineRules.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<KubeBaselineRule>[] = [
    { key: "checkId", title: t("kube.common.colCheckId"), render: (r) => <span className="font-mono text-xs text-muted">{r.checkId}</span> },
    {
      key: "checkName",
      title: t("kube.baselineRules.colCheckName"),
      render: (r) => <span className="block max-w-xs truncate font-medium text-ink">{r.checkName}</span>,
    },
    { key: "category", title: t("kube.common.colCategory"), render: (r) => <StatusTag tone="neutral">{r.category}</StatusTag> },
    {
      key: "severity",
      title: t("common.level"),
      render: (r) =>
        isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : <StatusTag tone="neutral">{r.severity}</StatusTag>,
    },
    {
      key: "resourceType",
      title: t("kube.baselineRules.colResourceType"),
      render: (r) =>
        r.checkConfig?.resourceType ? (
          <span className="text-muted">{r.checkConfig.resourceType}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      key: "enabled",
      title: t("kube.baselineRules.colEnabled"),
      render: (r) => (
        <div onClick={(e) => e.stopPropagation()}>
          <Switch checked={r.enabled} onChange={() => toggleMutation.mutate(r)} disabled={toggleMutation.isPending} />
        </div>
      ),
    },
    {
      key: "builtin",
      title: t("kube.baselineRules.colSource"),
      render: (r) =>
        r.builtin ? <StatusTag tone="neutral">{t("kube.baselineRules.sourceBuiltin")}</StatusTag> : <StatusTag tone="info">{t("kube.baselineRules.sourceCustom")}</StatusTag>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-3" onClick={(e) => e.stopPropagation()}>
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={() => openEdit(r)}
          >
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
        <StatCard compact label={t("kube.baselineRules.statTotalRules")} value={stats?.totalRules ?? 0} {...statState} icon={ListChecks} tone="default" />
        <StatCard compact label={t("kube.baselineRules.statEnabled")} value={stats?.enabled ?? 0} {...statState} icon={ToggleRight} tone="success" />
        <StatCard compact label={t("kube.baselineRules.statDisabled")} value={stats?.disabled ?? 0} {...statState} icon={ToggleLeft} tone="warning" />
        <StatCard compact label={t("kube.baselineRules.statBuiltin")} value={stats?.builtin ?? 0} {...statState} icon={Lock} tone="default" />
      </div>

      <div className="space-y-4">
        <FilterBar extra={<Button onClick={openCreate}>{t("kube.baselineRules.create")}</Button>}>
          <Input
            value={params.category}
            onChange={(e) => setParams((p) => ({ ...p, category: e.target.value, page: 1 }))}
            placeholder={t("kube.baselineRules.categoryFilterPlaceholder")}
            className="w-44"
          />
          <Select
            value={params.severity}
            onChange={(v) => setParams((p) => ({ ...p, severity: v, page: 1 }))}
            options={severityFilterOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.checkId ?? r.id}
            loading={isLoading}
            emptyText={t("kube.baselineRules.empty")}
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
        title={editing ? t("kube.baselineRules.editTitle") : t("kube.baselineRules.createTitle")}
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
          <FormField label={t("kube.baselineRules.fieldCheckName")} required>
            <Input value={form.checkName} onChange={(e) => setForm((f) => ({ ...f, checkName: e.target.value }))} />
          </FormField>
          <FormField label={t("kube.baselineRules.fieldCategory")}>
            <Input value={form.category} onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))} />
          </FormField>
          <FormField label={t("kube.baselineRules.fieldSeverity")}>
            <Select
              value={form.severity}
              onChange={(v) => setForm((f) => ({ ...f, severity: v as Severity }))}
              options={severityFormOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("kube.baselineRules.fieldResourceType")}>
            <Input
              value={form.resourceType}
              onChange={(e) => setForm((f) => ({ ...f, resourceType: e.target.value }))}
              placeholder={t("kube.baselineRules.fieldResourceTypePlaceholder")}
            />
          </FormField>
          <FormField label={t("kube.baselineRules.fieldApiGroup")}>
            <Input
              value={form.apiGroup}
              onChange={(e) => setForm((f) => ({ ...f, apiGroup: e.target.value }))}
              placeholder={t("kube.baselineRules.fieldApiGroupPlaceholder")}
            />
          </FormField>
          <FormField label={t("kube.baselineRules.fieldExpression")}>
            <Textarea
              className="font-mono"
              value={form.expression}
              onChange={(e) => setForm((f) => ({ ...f, expression: e.target.value }))}
            />
          </FormField>
          <FormField label={t("kube.baselineRules.fieldMatchPolicy")}>
            <Select
              value={form.matchPolicy}
              onChange={(v) => setForm((f) => ({ ...f, matchPolicy: v as KubeCheckConfig["matchPolicy"] }))}
              options={matchPolicyOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("kube.baselineRules.fieldEnabled")}>
            <Switch checked={form.enabled} onChange={(v) => setForm((f) => ({ ...f, enabled: v }))} />
          </FormField>
        </div>
      </Drawer>

      <Drawer open={!!detail} onClose={() => setDetail(null)} title={t("kube.baselineRules.detailTitle")} width={560}>
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold text-ink">{detail.checkName}</h2>
              <div className="flex items-center gap-2">
                {isSeverity(detail.severity) ? (
                  <SeverityTag level={detail.severity} />
                ) : (
                  <StatusTag tone="neutral">{detail.severity}</StatusTag>
                )}
                {detail.builtin ? <StatusTag tone="neutral">{t("kube.baselineRules.sourceBuiltin")}</StatusTag> : <StatusTag tone="info">{t("kube.baselineRules.sourceCustom")}</StatusTag>}
              </div>
            </div>
            <div className="space-y-2">
              <Field label={t("kube.common.fieldCheckId")} value={<span className="font-mono text-xs">{detail.checkId}</span>} />
              <Field label={t("kube.baselineRules.fieldCategory")} value={detail.category} />
              <Field label={t("kube.baselineRules.fieldResourceType")} value={detail.checkConfig?.resourceType || "—"} />
              <Field label={t("kube.baselineRules.fieldApiGroupLabel")} value={detail.checkConfig?.apiGroup || "—"} />
              <Field label={t("kube.baselineRules.fieldMatchPolicyLabel")} value={detail.checkConfig?.matchPolicy || "—"} />
            </div>
            {detail.checkConfig?.expression && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("kube.baselineRules.expressionLabel")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink">
                  {detail.checkConfig.expression}
                </pre>
              </div>
            )}
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("kube.baselineRules.deleteTitle")}
        desc={deleting ? t("kube.baselineRules.deleteConfirmDesc", { name: deleting.checkName }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
