"use client";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { systemApi } from "@/lib/api/system";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatusTag } from "@/components/ui/Tag";
import { cn } from "@/lib/utils/cn";
import { toast } from "@/components/ui/toast";

export default function RbacPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const { data: roles, isLoading: rolesLoading } = useQuery({ queryKey: ["sys-roles"], queryFn: () => systemApi.listRoles() });
  const { data: modules, isLoading: permsLoading } = useQuery({ queryKey: ["sys-permissions"], queryFn: () => systemApi.listPermissions() });

  const [selectedRole, setSelectedRole] = useState<string>("");
  useEffect(() => {
    if (!selectedRole && roles && roles.length > 0) setSelectedRole(roles[0].code);
  }, [roles, selectedRole]);

  const current = roles?.find((r) => r.code === selectedRole);
  const isAdmin = selectedRole === "admin";

  const { data: rolePerms, isLoading: rolePermsLoading } = useQuery({
    queryKey: ["sys-role-perms", selectedRole],
    queryFn: () => systemApi.getRolePermissions(selectedRole),
    enabled: !!selectedRole,
  });

  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [dirty, setDirty] = useState(false);
  useEffect(() => {
    setChecked(new Set(rolePerms?.permissions ?? []));
    setDirty(false);
  }, [rolePerms, selectedRole]);

  const toggle = (code: string) => {
    if (isAdmin) return;
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(code)) next.delete(code);
      else next.add(code);
      return next;
    });
    setDirty(true);
  };

  const saveMutation = useMutation({
    mutationFn: () => systemApi.updateRolePermissions(selectedRole, [...checked]),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sys-role-perms", selectedRole] });
      queryClient.invalidateQueries({ queryKey: ["sys-roles"] });
      setDirty(false);
      toast.success("权限已更新");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ code: "", name: "" });
  const createMutation = useMutation({
    mutationFn: () => systemApi.createRole({ code: form.code, name: form.name, permissions: [] }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["sys-roles"] });
      setCreateOpen(false);
      setForm({ code: "", name: "" });
      setSelectedRole(res.code);
      toast.success("角色已创建");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const [deleting, setDeleting] = useState<{ code: string; name: string } | null>(null);
  const deleteMutation = useMutation({
    mutationFn: (code: string) => systemApi.deleteRole(code),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sys-roles"] });
      setDeleting(null);
      setSelectedRole("");
      toast.success("角色已删除");
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const actionLabel: Record<string, string> = { view: "查看", manage: "管理", respond: "处置" };

  return (
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-[260px_1fr]">
      <Card>
        <CardHeader title="角色" extra={<Button className="h-8 px-3" onClick={() => setCreateOpen(true)}>+ 新建</Button>} />
        <div className="px-3 pb-4">
          {rolesLoading && <p className="px-2 py-4 text-sm text-muted">{t("common.loading")}</p>}
          <div className="space-y-1">
            {roles?.map((role) => {
              const active = role.code === selectedRole;
              return (
                <button
                  key={role.code}
                  type="button"
                  onClick={() => setSelectedRole(role.code)}
                  className={cn(
                    "flex w-full items-center justify-between gap-2 rounded-control px-3 py-2 text-left transition-colors",
                    active ? "bg-primary/10 text-primary font-medium" : "hover:bg-bg",
                  )}
                >
                  <span className="flex min-w-0 flex-col">
                    <span className="flex items-center gap-1.5 text-sm">
                      <span className="truncate">{role.name}</span>
                      {role.read_only && <StatusTag tone="warning">只读</StatusTag>}
                    </span>
                    <span className="truncate text-xs text-faint">
                      {role.code}
                      {role.builtin ? " · 内置" : ""}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader
          title={current ? `${current.name} 的权限` : "权限"}
          extra={
            <div className="flex items-center gap-2">
              {current && !current.builtin && (
                <Button variant="ghost" className="h-8 px-3 text-danger" onClick={() => setDeleting({ code: current.code, name: current.name })}>
                  删除角色
                </Button>
              )}
              <Button disabled={saveMutation.isPending || !dirty || isAdmin} onClick={() => saveMutation.mutate()}>
                {saveMutation.isPending ? t("common.saving") : t("common.save")}
              </Button>
            </div>
          }
        />
        <div className="px-5 pb-5">
          {isAdmin && <p className="mb-3 rounded-control bg-bg px-3 py-2 text-xs text-muted">平台超管拥有全部权限，不可编辑。</p>}
          {(permsLoading || rolePermsLoading) && <p className="py-4 text-sm text-muted">{t("common.loading")}</p>}
          {!permsLoading && !rolePermsLoading && selectedRole && (
            <div className="overflow-hidden rounded-control border border-border">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-bg text-left text-xs text-faint">
                    <th className="px-3 py-2 font-medium">模块</th>
                    <th className="px-3 py-2 font-medium">查看 view</th>
                    <th className="px-3 py-2 font-medium">管理 manage</th>
                    <th className="px-3 py-2 font-medium">处置 respond</th>
                  </tr>
                </thead>
                <tbody>
                  {modules?.map((m) => {
                    const byAction = new Map(m.actions.map((a) => [a.code.split(":")[1], a.code]));
                    return (
                      <tr key={m.code} className="border-b border-border last:border-0">
                        <td className="px-3 py-2">
                          <span className="text-ink">{m.name}</span>
                          <span className="ml-1.5 text-xs text-faint">{m.code}</span>
                        </td>
                        {(["view", "manage", "respond"] as const).map((act) => {
                          const code = byAction.get(act);
                          return (
                            <td key={act} className="px-3 py-2">
                              {code ? (
                                <label className="inline-flex cursor-pointer items-center gap-1.5" title={actionLabel[act]}>
                                  <input
                                    type="checkbox"
                                    disabled={isAdmin}
                                    className="h-4 w-4 accent-primary disabled:opacity-50"
                                    checked={checked.has(code)}
                                    onChange={() => toggle(code)}
                                  />
                                </label>
                              ) : (
                                <span className="text-faint">—</span>
                              )}
                            </td>
                          );
                        })}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>

      <Drawer open={createOpen} onClose={() => setCreateOpen(false)} title="新建自定义角色">
        <div className="space-y-4">
          <FormField label="角色码（小写字母开头，2-20 位字母/数字/下划线）">
            <Input value={form.code} placeholder="如 soc_lead" onChange={(e) => setForm((f) => ({ ...f, code: e.target.value }))} />
          </FormField>
          <FormField label="显示名">
            <Input value={form.name} placeholder="如 SOC 组长" onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <p className="text-xs text-muted">创建后在右侧矩阵勾选该角色的权限。</p>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setCreateOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button disabled={createMutation.isPending || !form.code || !form.name} onClick={() => createMutation.mutate()}>
              {createMutation.isPending ? t("common.saving") : t("common.create")}
            </Button>
          </div>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title="删除角色"
        desc={`确认删除角色「${deleting?.name}」？仍有用户使用时无法删除。`}
        danger
        loading={deleteMutation.isPending}
        onCancel={() => setDeleting(null)}
        onConfirm={() => {
          if (deleting) deleteMutation.mutate(deleting.code);
        }}
      />
    </div>
  );
}
