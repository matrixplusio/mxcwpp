"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { systemApi } from "@/lib/api/system";
import type { User } from "@/lib/api/types";
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
import { Input } from "@/components/ui/Input";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";
import { useUrlState } from "@/hooks/useUrlState";

interface ListParams {
  page: number;
  page_size: number;
  username: string;
  role: string;
  status: string;
}

interface UserForm {
  username: string;
  email: string;
  role: string;
  status: "active" | "inactive";
  password: string;
}

const buildStatusOptions = (t: TFunction) => [
  { label: t("system.users.allStatus"), value: "" },
  { label: t("system.users.statusActive"), value: "active" },
  { label: t("system.users.statusInactive"), value: "inactive" },
];
const buildStatusFormOptions = (t: TFunction) => [
  { label: t("system.users.statusActive"), value: "active" },
  { label: t("system.users.statusInactive"), value: "inactive" },
];

const emptyForm: UserForm = { username: "", email: "", role: "user", status: "active", password: "" };

export default function UsersPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const statusOptions = buildStatusOptions(t);
  const statusFormOptions = buildStatusFormOptions(t);

  // 角色动态来自 RBAC（含内置 6 角色 + 自定义），不再写死 admin/user。
  const { data: roles } = useQuery({ queryKey: ["sys-roles"], queryFn: () => systemApi.listRoles() });
  const roleList = roles ?? [];
  const roleNameMap = Object.fromEntries(roleList.map((r) => [r.code, r.name]));
  const roleOptions = [{ label: t("system.users.allRoles"), value: "" }, ...roleList.map((r) => ({ label: r.name, value: r.code }))];
  const roleFormOptions = roleList.map((r) => ({ label: r.name, value: r.code }));
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, username: "", role: "", status: "" });

  const { data, isLoading } = useQuery({
    queryKey: ["sys-users", params],
    queryFn: () => systemApi.listUsers(params),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [form, setForm] = useState<UserForm>(emptyForm);
  const [deleting, setDeleting] = useState<User | null>(null);

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (u: User) => {
    setEditing(u);
    setForm({ username: u.username, email: u.email, role: u.role, status: u.status, password: "" });
    setDrawerOpen(true);
  };

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["sys-users"] });

  const saveMutation = useMutation({
    mutationFn: () => {
      const base: Partial<User> & { password?: string } = {
        username: form.username,
        email: form.email,
        role: form.role,
        status: form.status,
      };
      if (form.password) base.password = form.password;
      return editing ? systemApi.updateUser(editing.id, base) : systemApi.createUser(base);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("system.users.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => systemApi.deleteUser(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("system.users.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<User>[] = [
    { key: "username", title: t("system.users.colUsername"), render: (r) => <span className="font-medium text-ink">{r.username}</span> },
    { key: "email", title: t("system.users.colEmail"), render: (r) => r.email || "—" },
    {
      key: "role",
      title: t("system.users.colRole"),
      render: (r) => (
        <StatusTag tone={r.role === "admin" ? "info" : "neutral"}>{roleNameMap[r.role] ?? r.role}</StatusTag>
      ),
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => (
        <StatusTag tone={r.status === "active" ? "success" : "neutral"}>{r.status === "active" ? t("system.users.statusActive") : t("system.users.statusInactive")}</StatusTag>
      ),
    },
    { key: "last_login", title: t("system.users.colLastLogin"), render: (r) => <span className="text-faint">{r.last_login || "—"}</span> },
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
        <FilterBar extra={<Button onClick={openCreate}>{t("system.users.create")}</Button>}>
          <SearchInput
            value={params.username}
            onChange={(v) => setParams((p) => ({ ...p, username: v, page: 1 }))}
            placeholder={t("system.users.searchPlaceholder")}
          />
          <Select value={params.role} onChange={(v) => setParams((p) => ({ ...p, role: v, page: 1 }))} options={roleOptions} />
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
            emptyText={t("system.users.empty")}
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
        title={editing ? t("system.users.editTitle") : t("system.users.createTitle")}
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
          <FormField label={t("system.users.colUsername")} required>
            <Input value={form.username} onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} />
          </FormField>
          <FormField label={t("system.users.colEmail")}>
            <Input type="email" value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} />
          </FormField>
          <FormField label={t("system.users.colRole")}>
            <Select
              value={form.role}
              onChange={(v) => setForm((f) => ({ ...f, role: v }))}
              options={roleFormOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("common.status")}>
            <Select
              value={form.status}
              onChange={(v) => setForm((f) => ({ ...f, status: v as UserForm["status"] }))}
              options={statusFormOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("system.users.fieldPassword")}>
            <Input
              type="password"
              value={form.password}
              onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
              placeholder={editing ? t("system.users.passwordPlaceholder") : undefined}
            />
          </FormField>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("system.users.deleteTitle")}
        desc={deleting ? t("system.users.deleteConfirmDesc", { name: deleting.username }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
