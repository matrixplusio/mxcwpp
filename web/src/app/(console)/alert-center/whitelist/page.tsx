"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { whitelistApi, type WhitelistParams } from "@/lib/api/alerts";
import type { AlertWhitelist, Severity } from "@/lib/api/types";
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
import { SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  keyword: string;
}

interface WhitelistForm {
  name: string;
  rule_id: string;
  host_id: string;
  category: string;
  severity: string;
  exe: string;
  cmdline: string;
  source_ip_cidr: string;
  reason: string;
}

const knownSeverities: Severity[] = ["critical", "high", "medium", "low"];
const isSeverity = (v: string): v is Severity => knownSeverities.includes(v as Severity);

const emptyForm: WhitelistForm = {
  name: "",
  rule_id: "",
  host_id: "",
  category: "",
  severity: "",
  exe: "",
  cmdline: "",
  source_ip_cidr: "",
  reason: "",
};

export default function WhitelistPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, keyword: "" });

  const severityOptions = [
    { label: t("common.all"), value: "" },
    { label: t("common.severity.critical"), value: "critical" },
    { label: t("common.severity.high"), value: "high" },
    { label: t("common.severity.medium"), value: "medium" },
    { label: t("common.severity.low"), value: "low" },
  ];

  const { data, isLoading } = useQuery({
    queryKey: ["alert-whitelist", params],
    queryFn: () =>
      whitelistApi.list({
        page: params.page,
        page_size: params.page_size,
        keyword: params.keyword || undefined,
      }),
  });

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<AlertWhitelist | null>(null);
  const [form, setForm] = useState<WhitelistForm>(emptyForm);
  const [deleting, setDeleting] = useState<AlertWhitelist | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["alert-whitelist"] });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setDrawerOpen(true);
  };
  const openEdit = (w: AlertWhitelist) => {
    setEditing(w);
    setForm({
      name: w.name,
      rule_id: w.rule_id,
      host_id: w.host_id,
      category: w.category,
      severity: w.severity,
      exe: w.exe,
      cmdline: w.cmdline,
      source_ip_cidr: w.source_ip_cidr,
      reason: w.reason,
    });
    setDrawerOpen(true);
  };

  const buildBody = (f: WhitelistForm): WhitelistParams => ({
    name: f.name,
    rule_id: f.rule_id || undefined,
    host_id: f.host_id || undefined,
    category: f.category || undefined,
    severity: f.severity || undefined,
    exe: f.exe || undefined,
    cmdline: f.cmdline || undefined,
    source_ip_cidr: f.source_ip_cidr || undefined,
    reason: f.reason || undefined,
  });

  const saveMutation = useMutation({
    mutationFn: () => {
      const body = buildBody(form);
      return editing ? whitelistApi.update(editing.id, body) : whitelistApi.create(body);
    },
    onSuccess: () => {
      invalidate();
      setDrawerOpen(false);
      toast.success(t("alerts.whitelist.saved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => whitelistApi.delete(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      toast.success(t("alerts.whitelist.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<AlertWhitelist>[] = [
    { key: "name", title: t("common.name"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    { key: "rule_id", title: t("alerts.whitelist.colRuleId"), render: (r) => <span className="font-mono text-xs">{r.rule_id || "—"}</span> },
    { key: "host_id", title: t("alerts.whitelist.colHostId"), render: (r) => <span className="font-mono text-xs">{r.host_id || "—"}</span> },
    { key: "category", title: t("common.category"), render: (r) => r.category || "—" },
    {
      key: "severity",
      title: t("common.level"),
      render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : "—"),
    },
    {
      key: "exe",
      title: t("alerts.whitelist.colExe"),
      render: (r) => <span className="font-mono text-xs">{r.exe || "—"}</span>,
    },
    {
      key: "cmdline",
      title: t("alerts.whitelist.colCmdline"),
      render: (r) => <span className="block max-w-48 truncate font-mono text-xs">{r.cmdline || "—"}</span>,
    },
    {
      key: "source_ip_cidr",
      title: t("alerts.whitelist.colSourceIpCidr"),
      render: (r) => <span className="font-mono text-xs">{r.source_ip_cidr || "—"}</span>,
    },
    {
      key: "reason",
      title: t("alerts.whitelist.colReason"),
      render: (r) => <span className="block max-w-48 truncate text-muted">{r.reason || "—"}</span>,
    },
    { key: "created_by", title: t("alerts.whitelist.colCreatedBy"), render: (r) => <span className="text-faint">{r.created_by || "—"}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={() => openEdit(r)}
          >
            {t("common.edit")}
          </button>
          <button
            type="button"
            className="text-sm text-danger transition-colors hover:opacity-80"
            onClick={() => setDeleting(r)}
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
        <FilterBar extra={<Button onClick={openCreate}>{t("alerts.whitelist.create")}</Button>}>
          <SearchInput
            value={params.keyword}
            onChange={(v) => setParams((p) => ({ ...p, keyword: v, page: 1 }))}
            placeholder={t("alerts.whitelist.searchPlaceholder")}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("alerts.whitelist.empty")}
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
        title={editing ? t("alerts.whitelist.editTitle") : t("alerts.whitelist.createTitle")}
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
          <FormField label={t("alerts.whitelist.colRuleId")}>
            <Input value={form.rule_id} onChange={(e) => setForm((f) => ({ ...f, rule_id: e.target.value }))} />
          </FormField>
          <FormField label={t("alerts.whitelist.colHostId")}>
            <Input value={form.host_id} onChange={(e) => setForm((f) => ({ ...f, host_id: e.target.value }))} />
          </FormField>
          <FormField label={t("common.category")}>
            <Input value={form.category} onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))} />
          </FormField>
          <FormField label={t("common.level")}>
            <Select
              value={form.severity}
              onChange={(v) => setForm((f) => ({ ...f, severity: v }))}
              options={severityOptions}
              className="w-full"
            />
          </FormField>
          <FormField label={t("alerts.whitelist.colExe")}>
            <Input
              value={form.exe}
              onChange={(e) => setForm((f) => ({ ...f, exe: e.target.value }))}
              placeholder={t("alerts.whitelist.exePlaceholder")}
            />
          </FormField>
          <FormField label={t("alerts.whitelist.colCmdline")}>
            <Input
              value={form.cmdline}
              onChange={(e) => setForm((f) => ({ ...f, cmdline: e.target.value }))}
              placeholder={t("alerts.whitelist.cmdlinePlaceholder")}
            />
          </FormField>
          <FormField label={t("alerts.whitelist.colSourceIpCidr")}>
            <Input
              value={form.source_ip_cidr}
              onChange={(e) => setForm((f) => ({ ...f, source_ip_cidr: e.target.value }))}
              placeholder={t("alerts.whitelist.sourceIpPlaceholder")}
            />
          </FormField>
          <FormField label={t("alerts.whitelist.colReason")}>
            <Textarea value={form.reason} onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value }))} />
          </FormField>
        </div>
      </Drawer>

      <ConfirmDialog
        open={!!deleting}
        title={t("alerts.whitelist.deleteTitle")}
        desc={deleting ? t("alerts.whitelist.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
