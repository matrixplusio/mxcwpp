"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Network, Hash, Globe, Link2, Database } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { detectionApi } from "@/lib/api/detection";
import type { LocalIOC } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
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
import { StatusTag } from "@/components/ui/Tag";
import { CopyButton } from "@/components/ui/CopyButton";
import { toast } from "@/components/ui/toast";

const IOC_TYPES = ["ip", "domain", "hash", "url"];
const sourceLabel = (s: string) => (s === "tp_extract" ? "研判提取" : s === "manual" ? "人工录入" : s);

export default function LocalIntelPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, type: "", keyword: "" });
  const [addOpen, setAddOpen] = useState(false);
  const [form, setForm] = useState({ ioc_type: "ip", value: "", severity: "high", description: "" });
  const [deleting, setDeleting] = useState<LocalIOC | null>(null);

  const typeOptions = [{ label: t("detection.localIntel.allType"), value: "" }, ...IOC_TYPES.map((v) => ({ label: v, value: v }))];

  const { data: stats } = useQuery({ queryKey: ["local-iocs-stats"], queryFn: () => detectionApi.localIocStats() });
  const { data, isLoading } = useQuery({
    queryKey: ["local-iocs", params],
    queryFn: () => detectionApi.listLocalIocs({ type: params.type || undefined, keyword: params.keyword || undefined, page: params.page, page_size: params.page_size }),
  });
  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["local-iocs"] });
    queryClient.invalidateQueries({ queryKey: ["local-iocs-stats"] });
  };

  const addMutation = useMutation({
    mutationFn: () => detectionApi.createLocalIoc(form),
    onSuccess: () => {
      invalidate();
      setAddOpen(false);
      setForm({ ioc_type: "ip", value: "", severity: "high", description: "" });
      toast.success(t("detection.localIntel.added"));
    },
    onError: (e: Error) => toast.error(e.message),
  });
  const delMutation = useMutation({
    mutationFn: (id: number) => detectionApi.deleteLocalIoc(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("detection.localIntel.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<LocalIOC>[] = [
    { key: "ioc_type", title: t("detection.localIntel.colType"), render: (r) => <StatusTag tone="neutral">{r.ioc_type}</StatusTag> },
    {
      key: "value",
      title: t("detection.localIntel.colValue"),
      render: (r) => (
        <span className="flex items-center gap-1.5">
          <span className="break-all font-mono text-xs text-ink">{r.value}</span>
          <CopyButton text={r.value} />
        </span>
      ),
    },
    { key: "source", title: t("detection.localIntel.colSource"), render: (r) => <span className="text-muted">{sourceLabel(r.source)}</span> },
    { key: "severity", title: t("common.level"), render: (r) => <span className="text-ink">{r.severity}</span> },
    { key: "description", title: t("detection.localIntel.colDesc"), render: (r) => <span className="text-muted">{r.description || "—"}</span> },
    { key: "ref_id", title: t("detection.localIntel.colRef"), render: (r) => <span className="font-mono text-xs text-faint">{r.ref_id || "—"}</span> },
    { key: "created_at", title: t("detection.localIntel.colTime"), render: (r) => <span className="text-faint tabular-nums">{r.created_at}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <button type="button" className="text-sm text-danger transition-colors hover:opacity-80" onClick={() => setDeleting(r)}>
          {t("common.delete")}
        </button>
      ),
    },
  ];

  return (
    <>
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatCard compact label={t("detection.threatIntel.statIp")} value={stats?.ip ?? 0} icon={Network} tone="default" />
        <StatCard compact label={t("detection.threatIntel.statHash")} value={stats?.hash ?? 0} icon={Hash} tone="default" />
        <StatCard compact label={t("detection.threatIntel.statDomain")} value={stats?.domain ?? 0} icon={Globe} tone="default" />
        <StatCard compact label={t("detection.threatIntel.statUrl")} value={stats?.url ?? 0} icon={Link2} tone="default" />
        <StatCard compact label={t("detection.threatIntel.statTotal")} value={stats?.total ?? 0} icon={Database} tone="success" />
      </div>

      <div className="space-y-4">
        <p className="text-sm text-muted">{t("detection.localIntel.intro")}</p>
        <FilterBar extra={<Button onClick={() => setAddOpen(true)}>{t("detection.localIntel.add")}</Button>}>
          <SearchInput
            value={params.keyword}
            onChange={(v) => setParams((p) => ({ ...p, keyword: v, page: 1 }))}
            placeholder={t("detection.localIntel.searchPlaceholder")}
          />
          <Select value={params.type} onChange={(v) => setParams((p) => ({ ...p, type: v, page: 1 }))} options={typeOptions} />
        </FilterBar>
        <Card>
          <DataTable columns={columns} rows={data?.items ?? []} rowKey={(r) => r.id} loading={isLoading} emptyText={t("detection.localIntel.empty")} />
          <Pagination page={params.page} pageSize={params.page_size} total={data?.total ?? 0} onChange={(page) => setParams((p) => ({ ...p, page }))} />
        </Card>
      </div>

      <Drawer
        open={addOpen}
        onClose={() => setAddOpen(false)}
        title={t("detection.localIntel.addTitle")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setAddOpen(false)}>{t("common.cancel")}</Button>
            <Button onClick={() => addMutation.mutate()} disabled={!form.value.trim() || addMutation.isPending}>{t("common.save")}</Button>
          </>
        }
      >
        <div className="space-y-4">
          <FormField label={t("detection.localIntel.colType")}>
            <Select value={form.ioc_type} onChange={(v) => setForm((f) => ({ ...f, ioc_type: v }))} options={IOC_TYPES.map((v) => ({ label: v, value: v }))} className="w-full" />
          </FormField>
          <FormField label={t("detection.localIntel.colValue")} required>
            <Input value={form.value} onChange={(e) => setForm((f) => ({ ...f, value: e.target.value }))} placeholder="1.2.3.4 / evil.com / sha256" />
          </FormField>
          <FormField label={t("detection.localIntel.colDesc")}>
            <Textarea value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />
          </FormField>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("detection.localIntel.deleteTitle")}
        desc={deleting ? t("detection.localIntel.deleteDesc", { value: deleting.value }) : undefined}
        loading={delMutation.isPending}
        onConfirm={() => deleting && delMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
