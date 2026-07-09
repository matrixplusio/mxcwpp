"use client";
import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { baselineApi } from "@/lib/api/baseline";
import type { PolicyGroup } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Input, Textarea } from "@/components/ui/Input";
import { Switch } from "@/components/ui/Switch";
import { toast } from "@/components/ui/toast";

const PAGE_SIZE = 20;

function formatPassRate(rate?: number): string {
  if (rate == null) return "—";
  const pct = rate <= 1 ? rate * 100 : rate;
  return `${pct.toFixed(1)}%`;
}

interface GroupForm {
  name: string;
  description: string;
  enabled: boolean;
}
const emptyForm: GroupForm = { name: "", description: "", enabled: true };

export default function BaselineGroupsPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["bl-groups"],
    queryFn: () => baselineApi.listGroups(),
  });

  const allRows = data?.items ?? [];
  const total = data?.total ?? allRows.length;
  const rows = useMemo(() => allRows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), [allRows, page]);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<PolicyGroup | null>(null);
  const [form, setForm] = useState<GroupForm>(emptyForm);
  const [deleting, setDeleting] = useState<PolicyGroup | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["bl-groups"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (g: PolicyGroup) => {
    setEditing(g);
    setForm({ name: g.name, description: g.description, enabled: g.enabled });
    setDrawerOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: () => {
      const body: Partial<PolicyGroup> = {
        name: form.name,
        description: form.description,
        enabled: form.enabled,
      };
      return editing ? baselineApi.updateGroup(editing.id, body) : baselineApi.createGroup(body);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("baseline.groups.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const toggleMutation = useMutation({
    mutationFn: (g: PolicyGroup) => baselineApi.updateGroup(g.id, { enabled: !g.enabled }),
    onSuccess: () => {
      invalidate();
      toast.success(t("baseline.groups.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => baselineApi.deleteGroup(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("baseline.groups.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<PolicyGroup>[] = [
    {
      key: "name",
      title: t("baseline.groups.colName"),
      render: (r) => (
        <div className="flex items-center gap-2">
          {r.color && (
            <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: r.color }} />
          )}
          <button
            type="button"
            className="font-medium text-ink transition-colors hover:text-primary"
            onClick={(e) => {
              e.stopPropagation();
              router.push(`/baseline/policies?group_id=${r.id}`);
            }}
          >
            {r.name}
          </button>
        </div>
      ),
    },
    {
      key: "description",
      title: t("baseline.groups.colDescription"),
      render: (r) => <span className="text-muted">{r.description || "—"}</span>,
    },
    {
      key: "policy_count",
      title: t("baseline.groups.colPolicyCount"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.policy_count ?? 0}</span>,
    },
    {
      key: "rule_count",
      title: t("baseline.groups.colRuleCount"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.rule_count ?? 0}</span>,
    },
    {
      key: "pass_rate",
      title: t("baseline.groups.colPassRate"),
      align: "right",
      render: (r) => <span className="tabular-nums text-muted">{formatPassRate(r.pass_rate)}</span>,
    },
    {
      key: "host_count",
      title: t("baseline.groups.colHostCount"),
      align: "right",
      render: (r) => <span className="tabular-nums">{r.host_count ?? 0}</span>,
    },
    {
      key: "enabled",
      title: t("common.status"),
      render: (r) => (
        <Switch checked={r.enabled} onChange={() => toggleMutation.mutate(r)} disabled={toggleMutation.isPending} />
      ),
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
        <FilterBar extra={<Button onClick={openCreate}>{t("baseline.groups.create")}</Button>}>
          <span className="text-sm text-faint">{t("baseline.groups.totalCount", { count: total })}</span>
        </FilterBar>
        <Card>
          {isError ? (
            <div className="p-6 text-sm text-danger">{t("baseline.loadError")}</div>
          ) : (
            <>
              <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} loading={isLoading} emptyText={t("baseline.groups.empty")} />
              <Pagination page={page} pageSize={PAGE_SIZE} total={total} onChange={setPage} />
            </>
          )}
        </Card>
      </div>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={editing ? t("baseline.groups.editTitle") : t("baseline.groups.createTitle")}
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
          <FormField label={t("baseline.groups.fieldName")} required>
            <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <FormField label={t("baseline.groups.fieldDescription")}>
            <Textarea
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </FormField>
          <FormField label={t("baseline.groups.fieldEnabled")}>
            <Switch checked={form.enabled} onChange={(v) => setForm((f) => ({ ...f, enabled: v }))} />
          </FormField>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("baseline.groups.deleteTitle")}
        desc={deleting ? t("baseline.groups.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
