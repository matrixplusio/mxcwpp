"use client";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { auditApi } from "@/lib/api/audit";
import type { AuditLog } from "@/lib/api/types";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { StatusTag } from "@/components/ui/Tag";

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

const buildResourceTypeOptions = (t: TFunction) => [
  { label: t("audit.allResource"), value: "" },
  { label: t("audit.resource.hosts"), value: "hosts" },
  { label: t("audit.resource.policies"), value: "policies" },
  { label: t("audit.resource.rules"), value: "rules" },
  { label: t("audit.resource.tasks"), value: "tasks" },
  { label: t("audit.resource.users"), value: "users" },
  { label: t("audit.resource.alerts"), value: "alerts" },
  { label: t("audit.resource.notifications"), value: "notifications" },
  { label: t("audit.resource.system-config"), value: "system-config" },
  { label: t("audit.resource.fim-policies"), value: "fim-policies" },
];
const buildActorOptions = (t: TFunction) => [
  { label: t("audit.allActor"), value: "" },
  { label: t("audit.actor.user"), value: "user" },
  { label: t("audit.actor.system"), value: "system" },
  { label: t("audit.actor.agent"), value: "agent" },
];
const buildOutcomeOptions = (t: TFunction) => [
  { label: t("audit.allOutcome"), value: "" },
  { label: t("audit.outcome.success"), value: "success" },
  { label: t("audit.outcome.failure"), value: "failure" },
];

// 语义动作着色：删除类红，处置类橙，创建/更新蓝，越权拒绝红。
function actionTone(action: string): Tone {
  if (action === "access.denied") return "danger";
  if (action.endsWith(".delete")) return "danger";
  if (/\.(isolate|release|quarantine|resolve|ignore|dispose)$/.test(action)) return "warning";
  if (action.endsWith(".create") || action.endsWith(".update") || action.includes("update_perms")) return "info";
  return "neutral";
}
function actorTone(actor: string): Tone {
  if (actor === "system") return "info";
  if (actor === "agent") return "warning";
  return "neutral";
}
// 兜底：旧审计行无 actor_type/outcome 字段，缺失时归一为合理默认，避免渲染 i18n key。
function normalizeActor(actor?: string): "user" | "system" | "agent" {
  return actor === "system" || actor === "agent" ? actor : "user";
}
function normalizeOutcome(outcome: string | undefined, code: number): "success" | "failure" {
  if (outcome === "success" || outcome === "failure") return outcome;
  return code >= 400 ? "failure" : "success";
}
function statusTone(code: number): Tone {
  if (code === 0) return "neutral";
  if (code < 300) return "success";
  if (code < 400) return "info";
  if (code < 500) return "warning";
  return "danger";
}

export default function AuditLogPage() {
  const { t } = useTranslation();
  const resourceTypeOptions = buildResourceTypeOptions(t);
  const actorOptions = buildActorOptions(t);
  const outcomeOptions = buildOutcomeOptions(t);
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    username: "",
    resource_type: "",
    action: "",
    actor_type: "",
    outcome: "",
  });

  const { data, isLoading } = useQuery({
    queryKey: ["audit-logs", params],
    queryFn: () =>
      auditApi.list({
        page: params.page,
        page_size: params.page_size,
        username: params.username || undefined,
        resource_type: params.resource_type || undefined,
        action: params.action || undefined,
        actor_type: params.actor_type || undefined,
        outcome: params.outcome || undefined,
      }),
  });

  const columns: Column<AuditLog>[] = [
    {
      key: "created_at",
      title: t("audit.colTime"),
      render: (r) => <span className="text-faint tabular-nums">{r.created_at}</span>,
    },
    {
      key: "actor_type",
      title: t("audit.colActor"),
      render: (r) => {
        const actor = normalizeActor(r.actor_type);
        return <StatusTag tone={actorTone(actor)}>{t(`audit.actor.${actor}`)}</StatusTag>;
      },
    },
    { key: "username", title: t("audit.colUser"), render: (r) => <span className="font-medium text-ink">{r.username}</span> },
    {
      key: "action",
      title: t("audit.colAction"),
      render: (r) => <StatusTag tone={actionTone(r.action)}>{r.action}</StatusTag>,
    },
    {
      key: "outcome",
      title: t("audit.colOutcome"),
      render: (r) => {
        const outcome = normalizeOutcome(r.outcome, r.status_code);
        return <StatusTag tone={outcome === "failure" ? "danger" : "success"}>{t(`audit.outcome.${outcome}`)}</StatusTag>;
      },
    },
    {
      key: "resource",
      title: t("audit.colResource"),
      render: (r) => (
        <div className="leading-tight">
          <div className="font-medium text-ink">{r.resource_type || "-"}</div>
          {r.resource_id && <div className="text-xs text-faint">{r.resource_id}</div>}
        </div>
      ),
    },
    {
      key: "target_name",
      title: t("audit.colTarget"),
      render: (r) => <span className="text-muted">{r.target_name || "-"}</span>,
    },
    { key: "ip", title: "IP", render: (r) => <span className="text-muted">{r.ip || "-"}</span> },
    {
      key: "status_code",
      title: t("audit.colStatusCode"),
      render: (r) => <StatusTag tone={statusTone(r.status_code)}>{r.status_code || "-"}</StatusTag>,
    },
  ];

  return (
    <>
      <PageHeader title={t("audit.title")} desc={t("audit.desc")} />
      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={params.username}
            onChange={(v) => setParams((p) => ({ ...p, username: v, page: 1 }))}
            placeholder={t("audit.search")}
          />
          <Select
            value={params.actor_type}
            onChange={(v) => setParams((p) => ({ ...p, actor_type: v, page: 1 }))}
            options={actorOptions}
          />
          <Select
            value={params.outcome}
            onChange={(v) => setParams((p) => ({ ...p, outcome: v, page: 1 }))}
            options={outcomeOptions}
          />
          <Select
            value={params.resource_type}
            onChange={(v) => setParams((p) => ({ ...p, resource_type: v, page: 1 }))}
            options={resourceTypeOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("audit.empty")}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>
    </>
  );
}
