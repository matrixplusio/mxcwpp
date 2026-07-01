"use client";
import { Suspense, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { baselineApi } from "@/lib/api/baseline";
import type { BaselineRule } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { FilterBar } from "@/components/ui/FilterBar";
import { Input } from "@/components/ui/Input";
import { Switch } from "@/components/ui/Switch";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

const sevTone = (s: string): "danger" | "warning" | "neutral" => {
  if (s === "critical" || s === "high") return "danger";
  if (s === "medium") return "warning";
  return "neutral";
};

function BaselineRulesContent() {
  const { t } = useTranslation();
  const router = useRouter();
  const searchParams = useSearchParams();
  const policyId = searchParams.get("policy_id") || "";
  const queryClient = useQueryClient();
  const [keyword, setKeyword] = useState("");

  const { data: policy } = useQuery({
    queryKey: ["bl-policy", policyId],
    queryFn: () => baselineApi.getPolicy(policyId),
    enabled: !!policyId,
  });

  const { data, isLoading, isError } = useQuery({
    queryKey: ["bl-rules", policyId],
    queryFn: () => baselineApi.listRules(policyId),
    enabled: !!policyId,
  });

  const allRows = data?.items ?? [];
  const rows = useMemo(() => {
    const kw = keyword.trim().toLowerCase();
    if (!kw) return allRows;
    return allRows.filter(
      (r) => r.title.toLowerCase().includes(kw) || r.category.toLowerCase().includes(kw) || r.rule_id.toLowerCase().includes(kw),
    );
  }, [allRows, keyword]);

  const toggleMutation = useMutation({
    mutationFn: (r: BaselineRule) => baselineApi.updateRule(r.rule_id, { enabled: !r.enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bl-rules", policyId] });
      toast.success(t("baseline.rules.updated"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<BaselineRule>[] = [
    {
      key: "title",
      title: t("baseline.rules.colTitle"),
      render: (r) => (
        <div>
          <div className="font-medium text-ink">{r.title}</div>
          <div className="text-xs text-faint">{r.rule_id}</div>
        </div>
      ),
    },
    { key: "category", title: t("baseline.rules.colCategory"), render: (r) => <span className="text-muted">{r.category || "—"}</span> },
    {
      key: "severity",
      title: t("baseline.rules.colSeverity"),
      render: (r) => <StatusTag tone={sevTone(r.severity)}>{r.severity || "—"}</StatusTag>,
    },
    {
      key: "builtin",
      title: t("baseline.rules.colSource"),
      render: (r) => (
        <span className="text-muted">{r.builtin ? t("baseline.rules.builtin") : t("baseline.rules.custom")}</span>
      ),
    },
    {
      key: "enabled",
      title: t("common.status"),
      render: (r) => (
        <Switch checked={r.enabled} onChange={() => toggleMutation.mutate(r)} disabled={toggleMutation.isPending} />
      ),
    },
  ];

  if (!policyId) {
    return <div className="p-6 text-sm text-danger">{t("baseline.rules.noPolicy")}</div>;
  }

  return (
    <div className="space-y-4">
      <button
        type="button"
        className="text-sm text-muted transition-colors hover:text-ink"
        onClick={() => router.push("/baseline/policies")}
      >
        ← {t("baseline.rules.backToPolicies")}
        {policy?.name ? `：${policy.name}` : ""}
      </button>
      <FilterBar>
        <Input
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          placeholder={t("baseline.rules.searchPlaceholder")}
          className="w-64"
        />
        <span className="text-sm text-faint">{t("baseline.rules.totalCount", { count: allRows.length })}</span>
      </FilterBar>
      <Card>
        {isError ? (
          <div className="p-6 text-sm text-danger">{t("baseline.loadError")}</div>
        ) : (
          <DataTable columns={columns} rows={rows} rowKey={(r) => r.rule_id} loading={isLoading} emptyText={t("baseline.rules.empty")} />
        )}
      </Card>
    </div>
  );
}

export default function BaselineRulesPage() {
  return (
    <Suspense fallback={null}>
      <BaselineRulesContent />
    </Suspense>
  );
}
