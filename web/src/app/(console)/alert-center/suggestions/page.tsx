"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { suggestionApi } from "@/lib/api/alerts";
import type { AlertWhitelistSuggestion, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

const knownSeverities: Severity[] = ["critical", "high", "medium", "low"];
const isSeverity = (v: string): v is Severity => knownSeverities.includes(v as Severity);

export default function SuggestionsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, status: "pending" });

  const statusOptions = [
    { label: t("alerts.suggestion.statusPending"), value: "pending" },
    { label: t("alerts.suggestion.statusAdopted"), value: "adopted" },
    { label: t("alerts.suggestion.statusDismissed"), value: "dismissed" },
    { label: t("alerts.suggestion.statusRevoked"), value: "revoked" },
    { label: t("common.all"), value: "all" },
  ];

  const { data, isLoading } = useQuery({
    queryKey: ["alert-whitelist-suggestions", params],
    queryFn: () =>
      suggestionApi.list({
        page: params.page,
        page_size: params.page_size,
        status: params.status || undefined,
      }),
  });

  const [adopting, setAdopting] = useState<AlertWhitelistSuggestion | null>(null);
  const [dismissing, setDismissing] = useState<AlertWhitelistSuggestion | null>(null);
  const [revoking, setRevoking] = useState<AlertWhitelistSuggestion | null>(null);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["alert-whitelist-suggestions"] });

  const adoptMutation = useMutation({
    mutationFn: (id: number) => suggestionApi.adopt(id),
    onSuccess: () => {
      invalidate();
      setAdopting(null);
      toast.success(t("alerts.suggestion.adopted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const dismissMutation = useMutation({
    mutationFn: (id: number) => suggestionApi.dismiss(id),
    onSuccess: () => {
      invalidate();
      setDismissing(null);
      toast.success(t("alerts.suggestion.dismissed"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const revokeMutation = useMutation({
    mutationFn: (id: number) => suggestionApi.revoke(id),
    onSuccess: () => {
      invalidate();
      setRevoking(null);
      toast.success(t("alerts.suggestion.revoked"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<AlertWhitelistSuggestion>[] = [
    {
      key: "rule_name",
      title: t("alerts.suggestion.colRule"),
      render: (r) => (
        <div>
          <div className="font-medium text-ink">{r.rule_name || r.rule_id}</div>
          <div className="font-mono text-xs text-faint">{r.rule_id}</div>
        </div>
      ),
    },
    { key: "exe", title: t("alerts.suggestion.colExe"), render: (r) => <span className="font-mono text-xs">{r.exe || "—"}</span> },
    {
      key: "host_id",
      title: t("alerts.suggestion.colScope"),
      render: (r) => (r.host_id ? <span className="font-mono text-xs">{r.host_id}</span> : <span className="text-muted">{t("alerts.suggestion.scopeFleet")}</span>),
    },
    {
      key: "severity",
      title: t("common.level"),
      render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : "—"),
    },
    { key: "hit_count", title: t("alerts.suggestion.colHits"), render: (r) => <span className="font-mono">{r.hit_count}</span> },
    {
      key: "confidence",
      title: t("alerts.suggestion.colConfidence"),
      render: (r) => (
        <span className={r.confidence >= 75 ? "font-semibold text-danger" : "text-ink"}>{r.confidence}</span>
      ),
    },
    {
      key: "resolve_reason_sample",
      title: t("alerts.suggestion.colReason"),
      render: (r) => <span className="block max-w-48 truncate text-muted">{r.resolve_reason_sample || "—"}</span>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) =>
        r.status === "pending" ? (
          <div className="flex justify-end gap-2">
            <button
              type="button"
              className="text-sm text-primary transition-colors hover:opacity-80"
              onClick={() => setAdopting(r)}
            >
              {t("alerts.suggestion.adopt")}
            </button>
            <button
              type="button"
              className="text-sm text-muted transition-colors hover:text-ink"
              onClick={() => setDismissing(r)}
            >
              {t("alerts.suggestion.dismiss")}
            </button>
          </div>
        ) : r.status === "adopted" ? (
          <div className="flex items-center justify-end gap-2">
            <span className="text-faint">{t("alerts.suggestion.statusAdopted")}</span>
            <button
              type="button"
              className="text-sm text-danger transition-colors hover:opacity-80"
              onClick={() => setRevoking(r)}
            >
              {t("alerts.suggestion.revoke")}
            </button>
          </div>
        ) : (
          <span className="text-faint">{r.status === "revoked" ? t("alerts.suggestion.statusRevoked") : t("alerts.suggestion.statusDismissed")}</span>
        ),
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <p className="text-sm text-muted">{t("alerts.suggestion.intro")}</p>
        <FilterBar>
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
            emptyText={t("alerts.suggestion.empty")}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      <ConfirmDialog
        open={!!adopting}
        title={t("alerts.suggestion.adoptTitle")}
        desc={adopting ? t("alerts.suggestion.adoptConfirmDesc", { exe: adopting.exe, rule: adopting.rule_name || adopting.rule_id }) : undefined}
        loading={adoptMutation.isPending}
        onConfirm={() => adopting && adoptMutation.mutate(adopting.id)}
        onCancel={() => setAdopting(null)}
      />
      <ConfirmDialog
        open={!!dismissing}
        title={t("alerts.suggestion.dismissTitle")}
        desc={dismissing ? t("alerts.suggestion.dismissConfirmDesc", { exe: dismissing.exe }) : undefined}
        loading={dismissMutation.isPending}
        onConfirm={() => dismissing && dismissMutation.mutate(dismissing.id)}
        onCancel={() => setDismissing(null)}
      />
      <ConfirmDialog
        open={!!revoking}
        title={t("alerts.suggestion.revokeTitle")}
        desc={revoking ? t("alerts.suggestion.revokeConfirmDesc", { exe: revoking.exe }) : undefined}
        loading={revokeMutation.isPending}
        onConfirm={() => revoking && revokeMutation.mutate(revoking.id)}
        onCancel={() => setRevoking(null)}
      />
    </>
  );
}
