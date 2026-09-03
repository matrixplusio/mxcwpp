"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { businessLinesApi } from "@/lib/api/assets";
import type { BusinessLine } from "@/lib/api/types";
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
  keyword: string;
  enabled: string; // "" = 全部, "true", "false"
}

interface BusinessLineForm {
  name: string;
  code: string;
  description: string;
  owner: string;
  contact: string;
  enabled: boolean;
}

const emptyForm: BusinessLineForm = {
  name: "",
  code: "",
  description: "",
  owner: "",
  contact: "",
  enabled: true,
};

export default function BusinessLinesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, keyword: "", enabled: "" });

  const enabledOptions = [
    { label: t("common.all"), value: "" },
    { label: t("common.enabled"), value: "true" },
    { label: t("common.disabled"), value: "false" },
  ];

  const { data, isLoading } = useQuery({
    queryKey: ["business-lines", params],
    queryFn: () =>
      businessLinesApi.list({
        page: params.page,
        page_size: params.page_size,
        keyword: params.keyword || undefined,
        enabled: params.enabled === "" ? undefined : params.enabled,
      }),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<BusinessLine | null>(null);
  const [form, setForm] = useState<BusinessLineForm>(emptyForm);
  const [deleting, setDeleting] = useState<BusinessLine | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["business-lines"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (b: BusinessLine) => {
    setEditing(b);
    setForm({
      name: b.name,
      code: b.code,
      description: b.description ?? "",
      owner: b.owner ?? "",
      contact: b.contact ?? "",
      enabled: b.enabled,
    });
    setDrawerOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: () => {
      if (editing) {
        return businessLinesApi.update(editing.id, {
          name: form.name,
          description: form.description || undefined,
          owner: form.owner || undefined,
          contact: form.contact || undefined,
          enabled: form.enabled,
        });
      }
      return businessLinesApi.create({
        name: form.name,
        code: form.code,
        description: form.description || undefined,
        owner: form.owner || undefined,
        contact: form.contact || undefined,
        enabled: form.enabled,
      });
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("assets.businessLines.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => businessLinesApi.delete(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("assets.businessLines.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<BusinessLine>[] = [
    { key: "name", title: t("common.name"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    { key: "code", title: t("common.code"), render: (r) => <span className="font-mono text-sm">{r.code}</span> },
    {
      key: "description",
      title: t("common.description"),
      render: (r) =>
        r.description ? (
          <span className="block max-w-xs truncate text-muted">{r.description}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    { key: "owner", title: t("assets.businessLines.colOwner"), render: (r) => r.owner || <span className="text-faint">—</span> },
    {
      key: "host_count",
      title: t("assets.businessLines.colHostCount"),
      render: (r) => <span className="tabular-nums">{r.host_count ?? 0}</span>,
    },
    {
      key: "enabled",
      title: t("common.status"),
      render: (r) => (
        <StatusTag tone={r.enabled ? "success" : "neutral"}>{r.enabled ? t("common.enabled") : t("common.disabled")}</StatusTag>
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
        <div className="flex justify-end gap-2">
          <Button
            variant="ghost"
            className="h-8"
            onClick={(e) => {
              e.stopPropagation();
              openEdit(r);
            }}
          >
            {t("common.edit")}
          </Button>
          <Button
            variant="ghost"
            className="h-8 text-danger"
            onClick={(e) => {
              e.stopPropagation();
              setDeleting(r);
            }}
          >
            {t("common.delete")}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <FilterBar extra={<Button onClick={openCreate}>{t("assets.businessLines.create")}</Button>}>
          <SearchInput
            value={params.keyword}
            onChange={(v) => setParams((p) => ({ ...p, keyword: v, page: 1 }))}
            placeholder={t("assets.businessLines.searchPlaceholder")}
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
            emptyText={t("assets.businessLines.empty")}
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
        title={editing ? t("assets.businessLines.editTitle") : t("assets.businessLines.createTitle")}
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
          <FormField label={t("common.code")} required>
            <Input
              value={form.code}
              onChange={(e) => setForm((f) => ({ ...f, code: e.target.value }))}
              disabled={!!editing}
            />
          </FormField>
          <FormField label={t("common.description")}>
            <Textarea
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </FormField>
          <FormField label={t("assets.businessLines.colOwner")}>
            <Input value={form.owner} onChange={(e) => setForm((f) => ({ ...f, owner: e.target.value }))} />
          </FormField>
          <FormField label={t("assets.businessLines.fieldContact")}>
            <Input value={form.contact} onChange={(e) => setForm((f) => ({ ...f, contact: e.target.value }))} />
          </FormField>
          <FormField label={t("common.enabled")}>
            <Switch checked={form.enabled} onChange={(b) => setForm((f) => ({ ...f, enabled: b }))} />
          </FormField>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("assets.businessLines.deleteTitle")}
        desc={deleting ? t("assets.businessLines.deleteConfirmDesc", { name: deleting.name }) : undefined}
        danger
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
