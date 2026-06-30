"use client";
import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { baselineApi } from "@/lib/api/baseline";
import type { BaselinePolicy } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Input, Textarea } from "@/components/ui/Input";
import { Switch } from "@/components/ui/Switch";
import { toast } from "@/components/ui/toast";

interface ListFilters {
  os_family: string;
  enabled: string; // "" | "true" | "false"
}

const buildOsFamilyOptions = (t: TFunction) => [
  { label: t("baseline.policies.allOs"), value: "" },
  { label: "Linux", value: "linux" },
  { label: "Windows", value: "windows" },
];
const buildEnabledOptions = (t: TFunction) => [
  { label: t("common.allStatus"), value: "" },
  { label: t("common.enabled"), value: "true" },
  { label: t("common.disabled"), value: "false" },
];

interface PolicyForm {
  name: string;
  version: string;
  description: string;
  os_version: string;
  enabled: boolean;
}
const emptyForm: PolicyForm = { name: "", version: "", description: "", os_version: "", enabled: true };

function BaselinePoliciesContent() {
  const { t } = useTranslation();
  const router = useRouter();
  const searchParams = useSearchParams();
  const groupId = searchParams.get("group_id") || "";
  const queryClient = useQueryClient();
  const osFamilyOptions = buildOsFamilyOptions(t);
  const enabledOptions = buildEnabledOptions(t);
  const [filters, setFilters] = useState<ListFilters>({ os_family: "", enabled: "" });

  // 组钻取上下文：展示组名 + 返回链接，并把新建策略归入该组
  const { data: group } = useQuery({
    queryKey: ["bl-group", groupId],
    queryFn: () => baselineApi.getGroup(groupId),
    enabled: !!groupId,
  });

  const { data, isLoading, isError } = useQuery({
    queryKey: ["bl-policies", filters, groupId],
    queryFn: () =>
      baselineApi.listPolicies({
        os_family: filters.os_family || undefined,
        enabled: filters.enabled === "" ? undefined : filters.enabled === "true",
        group_id: groupId || undefined,
      }),
  });
  const rows = data?.items ?? [];

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<BaselinePolicy | null>(null);
  const [form, setForm] = useState<PolicyForm>(emptyForm);
  const [deleting, setDeleting] = useState<BaselinePolicy | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["bl-policies"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (p: BaselinePolicy) => {
    setEditing(p);
    setForm({
      name: p.name,
      version: p.version,
      description: p.description,
      os_version: p.os_version,
      enabled: p.enabled,
    });
    setDrawerOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: () => {
      const body: Partial<BaselinePolicy> = {
        name: form.name,
        version: form.version,
        description: form.description,
        os_version: form.os_version,
        enabled: form.enabled,
      };
      if (!editing && groupId) body.group_id = groupId;
      return editing ? baselineApi.updatePolicy(editing.id, body) : baselineApi.createPolicy(body);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("baseline.policies.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleMutation = useMutation({
    mutationFn: (p: BaselinePolicy) => baselineApi.updatePolicy(p.id, { enabled: !p.enabled }),
    onSuccess: () => {
      invalidate();
      toast.success(t("baseline.policies.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => baselineApi.deletePolicy(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("baseline.policies.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<BaselinePolicy>[] = [
    {
      key: "name",
      title: t("baseline.policies.colName"),
      render: (r) => (
        <div>
          <button
            type="button"
            className="font-medium text-ink transition-colors hover:text-primary"
            onClick={(e) => {
              e.stopPropagation();
              router.push(`/baseline/rules?policy_id=${r.id}`);
            }}
          >
            {r.name}
          </button>
          {r.version && <div className="text-xs text-faint tabular-nums">v{r.version}</div>}
        </div>
      ),
    },
    {
      key: "os_family",
      title: t("baseline.policies.colOs"),
      render: (r) => <span className="text-muted">{r.os_family?.length ? r.os_family.join(", ") : "—"}</span>,
    },
    {
      key: "rule_count",
      title: t("baseline.policies.colRuleCount"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.rule_count ?? 0}</span>,
    },
    {
      key: "enabled",
      title: t("common.status"),
      render: (r) => (
        <Switch checked={r.enabled} onChange={() => toggleMutation.mutate(r)} disabled={toggleMutation.isPending} />
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
        {groupId && (
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={() => router.push("/baseline/groups")}
          >
            ← {t("baseline.policies.backToGroups")}
            {group?.name ? `：${group.name}` : ""}
          </button>
        )}
        <FilterBar extra={<Button onClick={openCreate}>{t("baseline.policies.create")}</Button>}>
          <Select
            value={filters.os_family}
            onChange={(v) => setFilters((f) => ({ ...f, os_family: v }))}
            options={osFamilyOptions}
          />
          <Select
            value={filters.enabled}
            onChange={(v) => setFilters((f) => ({ ...f, enabled: v }))}
            options={enabledOptions}
          />
        </FilterBar>
        <Card>
          {isError ? (
            <div className="p-6 text-sm text-danger">{t("baseline.loadError")}</div>
          ) : (
            <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} loading={isLoading} emptyText={t("baseline.policies.empty")} />
          )}
        </Card>
      </div>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={editing ? t("baseline.policies.editTitle") : t("baseline.policies.createTitle")}
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
          <FormField label={t("baseline.policies.fieldName")} required>
            <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <FormField label={t("baseline.policies.fieldVersion")}>
            <Input
              value={form.version}
              onChange={(e) => setForm((f) => ({ ...f, version: e.target.value }))}
              placeholder={t("baseline.policies.versionPlaceholder")}
            />
          </FormField>
          <FormField label={t("baseline.policies.fieldDescription")}>
            <Textarea
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </FormField>
          <FormField label={t("baseline.policies.fieldOsVersion")}>
            <Input value={form.os_version} onChange={(e) => setForm((f) => ({ ...f, os_version: e.target.value }))} />
          </FormField>
          <FormField label={t("baseline.policies.fieldEnabled")}>
            <Switch checked={form.enabled} onChange={(v) => setForm((f) => ({ ...f, enabled: v }))} />
          </FormField>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("baseline.policies.deleteTitle")}
        desc={deleting ? t("baseline.policies.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}

export default function BaselinePoliciesPage() {
  return (
    <Suspense fallback={null}>
      <BaselinePoliciesContent />
    </Suspense>
  );
}
