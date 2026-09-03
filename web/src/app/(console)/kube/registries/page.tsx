"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { kubeApi } from "@/lib/api/kube";
import type { KubeImageRegistry } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { FilterBar } from "@/components/ui/FilterBar";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FormField } from "@/components/ui/FormField";
import { Input } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface RegistryForm {
  name: string;
  type: string;
  url: string;
  username: string;
  password: string;
  insecure: boolean;
}
const emptyForm: RegistryForm = { name: "", type: "basic", url: "", username: "", password: "", insecure: false };

export default function KubeRegistriesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["kube-registries"] });

  const { data, isLoading } = useQuery({
    queryKey: ["kube-registries"],
    queryFn: () => kubeApi.listRegistries(),
  });

  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<KubeImageRegistry | null>(null);
  const [form, setForm] = useState<RegistryForm>(emptyForm);
  const [deleting, setDeleting] = useState<KubeImageRegistry | null>(null);

  const typeOptions = [
    { label: t("kube.registries.typeBasic"), value: "basic" },
    { label: "GCR (gcr.io)", value: "gcr" },
    { label: "GAR (Artifact Registry)", value: "gar" },
    { label: "ACR (Azure)", value: "acr" },
  ];
  const isGcp = form.type === "gcr" || form.type === "gar";

  const openCreate = () => { setEditing(null); setForm(emptyForm); setModalOpen(true); };
  const openEdit = (r: KubeImageRegistry) => {
    setEditing(r);
    setForm({ name: r.name, type: r.type || "basic", url: r.url, username: r.username || "", password: "", insecure: r.insecure });
    setModalOpen(true);
  };

  const saveMutation = useMutation({
    mutationFn: () => {
      const body = { name: form.name, type: form.type, url: form.url, username: form.username, password: form.password || undefined, insecure: form.insecure };
      return editing ? kubeApi.updateRegistry(editing.id, body) : kubeApi.createRegistry(body);
    },
    onSuccess: () => { invalidate(); setModalOpen(false); toast.success(t("common.saved")); },
    onError: (e: Error) => toast.error(e.message),
  });
  const deleteMutation = useMutation({
    mutationFn: (id: number) => kubeApi.deleteRegistry(id),
    onSuccess: () => { invalidate(); setDeleting(null); toast.success(t("common.deleted")); },
    onError: (e: Error) => toast.error(e.message),
  });
  const scanMutation = useMutation({
    mutationFn: (id: number) => kubeApi.scanRegistry(id),
    onSuccess: () => toast.success(t("kube.registries.scanSubmitted")),
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<KubeImageRegistry>[] = [
    { key: "name", title: t("kube.registries.colName"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    { key: "type", title: t("kube.registries.colType"), render: (r) => <StatusTag tone="neutral">{(r.type || "basic").toUpperCase()}</StatusTag> },
    { key: "url", title: "URL", render: (r) => <span className="font-mono text-sm text-muted">{r.url}</span> },
    { key: "imageCount", title: t("kube.registries.colImageCount"), align: "right", render: (r) => <span className="tabular-nums">{r.imageCount ?? 0}</span> },
    { key: "lastSyncAt", title: t("kube.registries.colLastSync"), render: (r) => <span className="text-faint tabular-nums">{r.lastSyncAt || "—"}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          <Button variant="ghost" className="h-8 px-3" onClick={() => scanMutation.mutate(r.id)} disabled={scanMutation.isPending}>
            {t("kube.registries.scan")}
          </Button>
          <Button variant="ghost" className="h-8 px-3" onClick={() => openEdit(r)}>{t("common.edit")}</Button>
          <Button variant="ghost" className="h-8 px-3 text-danger" onClick={() => setDeleting(r)}>{t("common.delete")}</Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <FilterBar extra={<Button onClick={openCreate}>{t("kube.registries.add")}</Button>}>
          <span className="text-sm text-muted">{t("kube.registries.hint")}</span>
        </FilterBar>
        <Card>
          <DataTable columns={columns} rows={data ?? []} rowKey={(r) => r.id} loading={isLoading} emptyText={t("kube.registries.empty")} />
        </Card>
      </div>

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editing ? t("kube.registries.editTitle") : t("kube.registries.add")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setModalOpen(false)}>{t("common.cancel")}</Button>
            <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending || !form.name.trim() || !form.url.trim()}>
              {saveMutation.isPending ? t("common.submitting") : t("common.save")}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("kube.registries.fieldName")} required>
            <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          </FormField>
          <FormField label={t("kube.registries.fieldType")} required>
            <Select value={form.type} onChange={(v) => setForm((f) => ({ ...f, type: v }))} options={typeOptions} />
          </FormField>
          <FormField label="URL" required>
            <Input value={form.url} onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))} placeholder={isGcp ? "gcr.io / asia-docker.pkg.dev" : "https://harbor.example.com"} />
          </FormField>
          {isGcp ? (
            <FormField label={t("kube.registries.fieldSaJson")}>
              <textarea
                value={form.password}
                onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                rows={5}
                placeholder={editing ? t("kube.registries.credKeep") : t("kube.registries.saJsonPlaceholder")}
                className="w-full rounded-control border border-border bg-surface px-3 py-2 font-mono text-xs text-ink outline-none focus:border-primary"
              />
            </FormField>
          ) : (
            <>
              <FormField label={t("kube.registries.fieldUsername")}>
                <Input value={form.username} onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} />
              </FormField>
              <FormField label={t("kube.registries.fieldPassword")}>
                <Input type="password" value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} placeholder={editing ? t("kube.registries.credKeep") : ""} />
              </FormField>
            </>
          )}
          <label className="flex items-center gap-2 text-sm text-muted">
            <input type="checkbox" checked={form.insecure} onChange={(e) => setForm((f) => ({ ...f, insecure: e.target.checked }))} />
            {t("kube.registries.insecure")}
          </label>
        </div>
      </Modal>

      <ConfirmDialog
        open={!!deleting}
        onCancel={() => setDeleting(null)}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        title={t("kube.registries.deleteTitle")}
        desc={deleting ? t("kube.registries.deleteConfirm", { name: deleting.name }) : ""}
        danger
      />
    </>
  );
}
