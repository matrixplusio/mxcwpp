"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { fimApi } from "@/lib/api/fim";
import type { FimPolicy, FimWatchPath } from "@/lib/api/types";
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
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  name: string;
  enabled: string;
}

const buildEnabledOptions = (t: TFunction) => [
  { label: t("fim.policies.allStatus"), value: "" },
  { label: t("fim.policies.statusEnabled"), value: "true" },
  { label: t("fim.policies.statusDisabled"), value: "false" },
];

const buildTargetTypeFormOptions = (t: TFunction) => [
  { label: t("fim.policies.targetAll"), value: "all" },
  { label: t("fim.policies.targetHost"), value: "host_ids" },
  { label: t("fim.policies.targetBusinessLine"), value: "business_line" },
];

const levelOptions = [
  { label: "NORMAL", value: "NORMAL" },
  { label: "CONTENT", value: "CONTENT" },
  { label: "PERMS", value: "PERMS" },
];

const buildTargetTypeMeta = (t: TFunction): Record<string, string> => ({
  all: t("fim.policies.targetAll"),
  host_ids: t("fim.policies.targetHost"),
  business_line: t("fim.policies.targetBusinessLine"),
});

interface PolicyForm {
  name: string;
  description: string;
  check_interval_hours: number;
  target_type: string;
  enabled: boolean;
  watch_paths: FimWatchPath[];
}

const emptyForm: PolicyForm = {
  name: "",
  description: "",
  check_interval_hours: 24,
  target_type: "all",
  enabled: true,
  watch_paths: [{ path: "", level: "NORMAL", comment: "" }],
};

export default function FimPoliciesPage() {
  const { t } = useTranslation();
  const enabledOptions = buildEnabledOptions(t);
  const targetTypeFormOptions = buildTargetTypeFormOptions(t);
  const targetTypeMeta = buildTargetTypeMeta(t);
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, name: "", enabled: "" });

  const { data, isLoading } = useQuery({
    queryKey: ["fim-policies", params],
    queryFn: () => fimApi.listPolicies(params),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<FimPolicy | null>(null);
  const [form, setForm] = useState<PolicyForm>(emptyForm);
  const [deleting, setDeleting] = useState<FimPolicy | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["fim-policies"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (p: FimPolicy) => {
    setEditing(p);
    setForm({
      name: p.name,
      description: p.description,
      check_interval_hours: p.check_interval_hours,
      target_type: p.target_type,
      enabled: p.enabled,
      watch_paths:
        p.watch_paths && p.watch_paths.length > 0
          ? p.watch_paths.map((w) => ({ path: w.path, level: w.level, comment: w.comment }))
          : [{ path: "", level: "NORMAL", comment: "" }],
    });
    setDrawerOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: () => {
      const body: Partial<FimPolicy> = {
        name: form.name,
        description: form.description,
        check_interval_hours: form.check_interval_hours,
        target_type: form.target_type,
        enabled: form.enabled,
        watch_paths: form.watch_paths.filter((w) => w.path.trim() !== ""),
      };
      return editing ? fimApi.updatePolicy(editing.policy_id, body) : fimApi.createPolicy(body);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("fim.policies.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleMutation = useMutation({
    mutationFn: (p: FimPolicy) => fimApi.updatePolicy(p.policy_id, { enabled: !p.enabled }),
    onSuccess: () => {
      invalidate();
      toast.success(t("fim.policies.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (policyId: string) => fimApi.deletePolicy(policyId),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("fim.policies.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const updatePath = (idx: number, patch: Partial<FimWatchPath>) =>
    setForm((f) => ({
      ...f,
      watch_paths: f.watch_paths.map((w, i) => (i === idx ? { ...w, ...patch } : w)),
    }));
  const addPath = () =>
    setForm((f) => ({ ...f, watch_paths: [...f.watch_paths, { path: "", level: "NORMAL", comment: "" }] }));
  const removePath = (idx: number) =>
    setForm((f) => ({ ...f, watch_paths: f.watch_paths.filter((_, i) => i !== idx) }));

  const columns: Column<FimPolicy>[] = [
    {
      key: "name",
      title: t("fim.policies.colName"),
      render: (r) => (
        <div>
          <div className="font-medium text-ink">{r.name}</div>
          {r.description && <div className="max-w-xs truncate text-xs text-faint">{r.description}</div>}
        </div>
      ),
    },
    {
      key: "watch_paths",
      title: t("fim.policies.colWatchPaths"),
      render: (r) => <span className="text-muted">{t("fim.policies.watchPathsCount", { count: r.watch_paths?.length ?? 0 })}</span>,
    },
    {
      key: "check_interval_hours",
      title: t("fim.policies.colCheckInterval"),
      render: (r) => <span className="tabular-nums text-muted">{t("fim.policies.checkIntervalValue", { hours: r.check_interval_hours })}</span>,
    },
    {
      key: "target_type",
      title: t("fim.policies.colTargetType"),
      render: (r) => <StatusTag tone="neutral">{targetTypeMeta[r.target_type] ?? r.target_type}</StatusTag>,
    },
    {
      key: "enabled",
      title: t("fim.policies.colEnabled"),
      render: (r) => (
        <span onClick={(e) => e.stopPropagation()}>
          <Switch checked={r.enabled} onChange={() => toggleMutation.mutate(r)} disabled={toggleMutation.isPending} />
        </span>
      ),
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
        <div className="flex justify-end gap-3">
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
        <FilterBar extra={<Button onClick={openCreate}>{t("fim.policies.create")}</Button>}>
          <SearchInput
            value={params.name}
            onChange={(v) => setParams((p) => ({ ...p, name: v, page: 1 }))}
            placeholder={t("fim.policies.searchPlaceholder")}
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
            rowKey={(r) => r.policy_id}
            loading={isLoading}
            emptyText={t("fim.policies.empty")}
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
        title={editing ? t("fim.policies.editTitle") : t("fim.policies.createTitle")}
        width={640}
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
          <FormField label={t("fim.policies.fieldName")} required>
            <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <FormField label={t("fim.policies.fieldDescription")}>
            <Textarea
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </FormField>
          <FormField label={t("fim.policies.fieldCheckInterval")}>
            <Input
              type="number"
              min={1}
              value={form.check_interval_hours}
              onChange={(e) => setForm((f) => ({ ...f, check_interval_hours: Number(e.target.value) }))}
            />
          </FormField>
          <FormField label={t("fim.policies.fieldTargetType")}>
            <Select
              value={form.target_type}
              onChange={(v) => setForm((f) => ({ ...f, target_type: v }))}
              options={targetTypeFormOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("fim.policies.fieldEnabled")}>
            <Switch checked={form.enabled} onChange={(v) => setForm((f) => ({ ...f, enabled: v }))} />
          </FormField>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[13px] font-semibold text-muted">{t("fim.policies.watchPathsTitle")}</span>
              <Button variant="ghost" onClick={addPath}>
                {t("fim.policies.addPath")}
              </Button>
            </div>
            <div className="space-y-3">
              {form.watch_paths.map((w, idx) => (
                <div key={idx} className="rounded-card border border-border p-3">
                  <div className="flex items-center gap-2">
                    <Input
                      value={w.path}
                      onChange={(e) => updatePath(idx, { path: e.target.value })}
                      placeholder={t("fim.policies.pathPlaceholder")}
                      className="flex-1"
                    />
                    <Select
                      value={w.level}
                      onChange={(v) => updatePath(idx, { level: v })}
                      options={levelOptions}
                    />
                    <button
                      type="button"
                      className="text-sm text-danger transition-colors hover:opacity-80"
                      onClick={() => removePath(idx)}
                    >
                      {t("common.delete")}
                    </button>
                  </div>
                  <Input
                    value={w.comment}
                    onChange={(e) => updatePath(idx, { comment: e.target.value })}
                    placeholder={t("fim.policies.commentPlaceholder")}
                    className="mt-2"
                  />
                </div>
              ))}
            </div>
          </div>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("fim.policies.deleteTitle")}
        desc={deleting ? t("fim.policies.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.policy_id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
