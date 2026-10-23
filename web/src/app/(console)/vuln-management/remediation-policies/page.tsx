"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { vulnApi } from "@/lib/api/vuln";
import type { RemediationPolicy, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { FilterBar } from "@/components/ui/FilterBar";
import { FormField } from "@/components/ui/FormField";
import { Input, Textarea } from "@/components/ui/Input";
import { Select } from "@/components/ui/Select";
import { Switch } from "@/components/ui/Switch";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

const SEVS = ["critical", "high", "medium", "low"];
const isSeverity = (s: string): s is Severity => SEVS.includes(s);
const buildRolloutText = (t: TFunction): Record<string, string> => ({
  immediate: t("vuln.remediationPolicies.rolloutImmediate"),
  canary: t("vuln.remediationPolicies.rolloutCanary"),
  manual: t("vuln.remediationPolicies.rolloutManual"),
});

interface Form {
  name: string; description: string; targetType: string;
  severityMin: string; rolloutType: string; canaryRatio: number; enabled: boolean;
}
const emptyForm: Form = { name: "", description: "", targetType: "all", severityMin: "high", rolloutType: "immediate", canaryRatio: 10, enabled: true };

export default function RemediationPoliciesPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const rolloutText = buildRolloutText(t);
  const { data, isLoading } = useQuery({ queryKey: ["vuln-policies"], queryFn: () => vulnApi.listRemediationPolicies() });
  const [editing, setEditing] = useState<RemediationPolicy | null>(null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<Form>(emptyForm);
  const [delTarget, setDelTarget] = useState<RemediationPolicy | null>(null);
  const [execTarget, setExecTarget] = useState<RemediationPolicy | null>(null);

  const openCreate = () => { setEditing(null); setForm(emptyForm); setOpen(true); };
  const openEdit = (p: RemediationPolicy) => {
    setEditing(p);
    setForm({ name: p.name, description: p.description, targetType: p.targetType, severityMin: p.severityMin, rolloutType: p.rolloutType, canaryRatio: p.canaryRatio, enabled: p.enabled });
    setOpen(true);
  };

  const save = useMutation({
    mutationFn: () => editing ? vulnApi.updateRemediationPolicy(editing.id, form) : vulnApi.createRemediationPolicy(form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["vuln-policies"] }); setOpen(false); toast.success(t("vuln.remediationPolicies.saved")); },
    onError: (e: Error) => toast.error(e.message),
  });
  const toggle = useMutation({
    mutationFn: (p: RemediationPolicy) => vulnApi.updateRemediationPolicy(p.id, { enabled: !p.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["vuln-policies"] }),
    onError: (e: Error) => toast.error(e.message),
  });
  const remove = useMutation({
    mutationFn: (id: number) => vulnApi.deleteRemediationPolicy(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["vuln-policies"] }); setDelTarget(null); toast.success(t("vuln.remediationPolicies.deleted")); },
    onError: (e: Error) => toast.error(e.message),
  });
  const execute = useMutation({
    mutationFn: (id: number) => vulnApi.executeRemediationPolicy(id),
    onSuccess: () => { setExecTarget(null); toast.success(t("vuln.remediationPolicies.executed")); },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<RemediationPolicy>[] = [
    { key: "name", title: t("vuln.remediationPolicies.colName"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    { key: "targetType", title: t("vuln.remediationPolicies.colTargetType"), render: (r) => <StatusTag tone="neutral">{r.targetType}</StatusTag> },
    { key: "severityMin", title: t("vuln.remediationPolicies.colSeverityMin"), render: (r) => isSeverity(r.severityMin) ? <SeverityTag level={r.severityMin} /> : <span className="text-muted">{r.severityMin}</span> },
    { key: "rolloutType", title: t("vuln.remediationPolicies.colRolloutType"), render: (r) => <span className="text-muted">{rolloutText[r.rolloutType] ?? r.rolloutType}</span> },
    { key: "canaryRatio", title: t("vuln.remediationPolicies.colCanaryRatio"), render: (r) => <span className="text-muted tabular-nums">{r.rolloutType === "canary" ? `${r.canaryRatio}%` : "—"}</span> },
    { key: "enabled", title: t("vuln.remediationPolicies.colEnabled"), render: (r) => <span onClick={(e) => e.stopPropagation()}><Switch checked={r.enabled} onChange={() => toggle.mutate(r)} /></span> },
    {
      key: "actions", title: t("common.actions"), align: "right",
      render: (r) => (
        <span className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <Button variant="ghost" className="h-8 px-3" onClick={() => openEdit(r)}>{t("common.edit")}</Button>
          <Button variant="ghost" className="h-8 px-3" onClick={() => setExecTarget(r)}>{t("vuln.remediationPolicies.actionExecute")}</Button>
          <Button variant="ghost" className="h-8 px-3 text-danger" onClick={() => setDelTarget(r)}>{t("common.delete")}</Button>
        </span>
      ),
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <FilterBar extra={<Button onClick={openCreate}>{t("vuln.remediationPolicies.create")}</Button>}>
          <span className="text-sm text-muted">{t("vuln.remediationPolicies.subtitle")}</span>
        </FilterBar>
        <Card>
          <DataTable columns={columns} rows={data ?? []} rowKey={(r) => r.id} loading={isLoading} emptyText={t("vuln.remediationPolicies.empty")} />
        </Card>
      </div>

      <Drawer open={open} onClose={() => setOpen(false)} title={editing ? t("vuln.remediationPolicies.editTitle") : t("vuln.remediationPolicies.createTitle")}
        footer={<>
          <Button variant="ghost" onClick={() => setOpen(false)}>{t("common.cancel")}</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending || !form.name}>{save.isPending ? t("common.saving") : t("common.save")}</Button>
        </>}>
        <div className="space-y-4">
          <FormField label={t("vuln.remediationPolicies.fieldName")} required><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></FormField>
          <FormField label={t("common.description")}><Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></FormField>
          <FormField label={t("vuln.remediationPolicies.fieldTargetType")}><Select className="w-full" value={form.targetType} onChange={(v) => setForm({ ...form, targetType: v })} options={[{ label: t("vuln.remediationPolicies.targetAll"), value: "all" }, { label: t("vuln.remediationPolicies.targetBusinessLine"), value: "business_line" }, { label: t("vuln.remediationPolicies.targetHost"), value: "host" }]} /></FormField>
          <FormField label={t("vuln.remediationPolicies.fieldSeverityMin")}><Select className="w-full" value={form.severityMin} onChange={(v) => setForm({ ...form, severityMin: v })} options={[{ label: t("common.severity.critical"), value: "critical" }, { label: t("common.severity.high"), value: "high" }, { label: t("common.severity.medium"), value: "medium" }, { label: t("common.severity.low"), value: "low" }]} /></FormField>
          <FormField label={t("vuln.remediationPolicies.fieldRolloutType")}><Select className="w-full" value={form.rolloutType} onChange={(v) => setForm({ ...form, rolloutType: v })} options={[{ label: t("vuln.remediationPolicies.rolloutImmediate"), value: "immediate" }, { label: t("vuln.remediationPolicies.rolloutCanary"), value: "canary" }, { label: t("vuln.remediationPolicies.rolloutManual"), value: "manual" }]} /></FormField>
          {form.rolloutType === "canary" && (
            <FormField label={t("vuln.remediationPolicies.fieldCanaryRatio")}><Input type="number" value={form.canaryRatio} onChange={(e) => setForm({ ...form, canaryRatio: Number(e.target.value) })} /></FormField>
          )}
          <FormField label={t("vuln.remediationPolicies.fieldEnabled")}><Switch checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} /></FormField>
        </div>
      </Drawer>

      <ConfirmDialog open={!!delTarget} title={t("vuln.remediationPolicies.deleteTitle")} desc={t("vuln.remediationPolicies.deleteConfirmDesc", { name: delTarget?.name })} loading={remove.isPending}
        onConfirm={() => delTarget && remove.mutate(delTarget.id)} onCancel={() => setDelTarget(null)} />
      <ConfirmDialog open={!!execTarget} title={t("vuln.remediationPolicies.executeTitle")} desc={t("vuln.remediationPolicies.executeConfirmDesc", { name: execTarget?.name })} danger={false} confirmText={t("vuln.remediationPolicies.actionExecute")} loading={execute.isPending}
        onConfirm={() => execTarget && execute.mutate(execTarget.id)} onCancel={() => setExecTarget(null)} />
    </>
  );
}
