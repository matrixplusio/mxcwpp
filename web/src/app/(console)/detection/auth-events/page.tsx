"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { detectionApi } from "@/lib/api/detection";
import type { AuthEvent } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Input } from "@/components/ui/Input";
import { Drawer } from "@/components/ui/Drawer";
import { StatusTag } from "@/components/ui/Tag";
import { CopyButton } from "@/components/ui/CopyButton";

const EVENT_TYPES = [
  "auth_login_success",
  "auth_login_failed",
  "auth_preauth_close",
  "auth_sudo",
  "auth_sudo_denied",
  "auth_su_success",
  "auth_su_failed",
  "auth_account_change",
  "auth_session_open",
  "auth_session_close",
  "auth_collector_stats",
  // 不筛类型时接口不返回心跳（量大），只能在这里单独选。
  "auth_collector_heartbeat",
];

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

const typeTone: Record<string, Tone> = {
  auth_login_success: "success",
  auth_login_failed: "danger",
  auth_preauth_close: "neutral",
  auth_sudo: "info",
  auth_sudo_denied: "warning",
  auth_su_success: "info",
  auth_su_failed: "warning",
  auth_account_change: "warning",
  auth_collector_stats: "neutral",
  auth_collector_heartbeat: "neutral",
};

function dash(v: string | undefined) {
  return v && v.length > 0 ? v : "—";
}

function Field({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-24 shrink-0 text-muted">{label}</span>
      <span className={`min-w-0 break-all text-ink${mono ? " font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}

export default function AuthEventsPage() {
  const { t } = useTranslation();
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    keyword: "",
    host_id: "",
    username: "",
    source_ip: "",
    event_type: "",
  });

  const typeLabel = (v: string) => t(`detection.authEvents.type.${v}`, v);
  const eventTypeOptions = [
    { label: t("common.allType"), value: "" },
    ...EVENT_TYPES.map((v) => ({ label: typeLabel(v), value: v })),
  ];

  const { data, isLoading } = useQuery({
    queryKey: ["auth-events", params],
    queryFn: () =>
      detectionApi.listAuthEvents({
        page: params.page,
        page_size: params.page_size,
        keyword: params.keyword || undefined,
        host_id: params.host_id || undefined,
        username: params.username || undefined,
        source_ip: params.source_ip || undefined,
        event_type: params.event_type || undefined,
      }),
  });

  const [detail, setDetail] = useState<AuthEvent | null>(null);

  // 一行里最值得看的那句话：登录看方式，sudo 看命令，账号变更看动作。
  const summary = (r: AuthEvent) => {
    if (r.command) return r.command;
    if (r.event_type === "auth_account_change") return [r.reason, r.detail].filter(Boolean).join(" · ");
    if (r.event_type === "auth_collector_stats") return t("detection.authEvents.dropped", { n: r.count });
    if (r.event_type === "auth_collector_heartbeat") return [r.reason, r.detail].filter(Boolean).join(" · ");
    return [r.auth_method, r.reason !== r.auth_method ? r.reason : ""].filter(Boolean).join(" · ");
  };

  const columns: Column<AuthEvent>[] = [
    {
      key: "timestamp",
      nowrap: true,
      title: t("detection.authEvents.colTime"),
      render: (r) => <span className="text-faint tabular-nums">{r.timestamp}</span>,
    },
    {
      key: "hostname",
      title: t("detection.authEvents.colHost"),
      render: (r) => (
        <button
          type="button"
          className="font-medium text-ink transition-colors hover:text-primary"
          onClick={(e) => {
            e.stopPropagation();
            setParams((p) => ({ ...p, host_id: r.host_id, page: 1 }));
          }}
        >
          {r.hostname || r.host_id}
        </button>
      ),
    },
    {
      key: "event_type",
      nowrap: true,
      title: t("detection.authEvents.colType"),
      render: (r) => (
        <div className="flex items-center gap-1.5">
          <StatusTag tone={typeTone[r.event_type] ?? "neutral"}>{typeLabel(r.event_type)}</StatusTag>
          {r.count > 1 && <span className="tabular-nums text-xs text-muted">×{r.count}</span>}
        </div>
      ),
    },
    {
      key: "username",
      title: t("detection.authEvents.colUser"),
      render: (r) => (
        <span className="text-ink">
          {dash(r.username)}
          {r.target_user && <span className="text-muted"> → {r.target_user}</span>}
          {r.invalid_user === 1 && <span className="ml-1.5 text-xs text-muted">{t("detection.authEvents.invalidUser")}</span>}
        </span>
      ),
    },
    {
      key: "source_ip",
      nowrap: true,
      title: t("detection.authEvents.colSource"),
      render: (r) =>
        r.source_ip ? (
          <button
            type="button"
            className="font-mono text-xs text-ink transition-colors hover:text-primary"
            onClick={(e) => {
              e.stopPropagation();
              setParams((p) => ({ ...p, source_ip: r.source_ip, page: 1 }));
            }}
          >
            {r.source_ip}
          </button>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      key: "summary",
      title: t("detection.authEvents.colSummary"),
      render: (r) => <span className="block max-w-[360px] truncate font-mono text-xs text-ink">{dash(summary(r))}</span>,
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={params.keyword}
            onChange={(v) => setParams((p) => ({ ...p, keyword: v, page: 1 }))}
            placeholder={t("detection.authEvents.searchPlaceholder")}
          />
          <Input
            value={params.host_id}
            onChange={(e) => setParams((p) => ({ ...p, host_id: e.target.value, page: 1 }))}
            placeholder={t("detection.authEvents.filterHostId")}
            className="w-56"
          />
          <Input
            value={params.username}
            onChange={(e) => setParams((p) => ({ ...p, username: e.target.value, page: 1 }))}
            placeholder={t("detection.authEvents.filterUser")}
            className="w-36"
          />
          <Input
            value={params.source_ip}
            onChange={(e) => setParams((p) => ({ ...p, source_ip: e.target.value, page: 1 }))}
            placeholder={t("detection.authEvents.filterSource")}
            className="w-44"
          />
          <Select
            value={params.event_type}
            onChange={(v) => setParams((p) => ({ ...p, event_type: v, page: 1 }))}
            options={eventTypeOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => `${r.host_id}-${r.timestamp}-${r.event_type}-${r.pid}-${r.source_port}`}
            loading={isLoading}
            emptyText={t("detection.authEvents.empty")}
            onRowClick={setDetail}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      <Drawer open={!!detail} onClose={() => setDetail(null)} title={t("detection.authEvents.detailTitle")} width={560}>
        {detail && (
          <div className="space-y-2">
            <Field label={t("detection.authEvents.colTime")} value={<span className="tabular-nums">{detail.timestamp}</span>} />
            {detail.received_at && (
              <Field
                label={t("detection.authEvents.fieldReceivedAt")}
                value={<span className="tabular-nums">{detail.received_at}</span>}
              />
            )}
            <Field label={t("detection.authEvents.colHost")} value={detail.hostname || detail.host_id} />
            <Field
              label={t("detection.authEvents.fieldHostId")}
              value={<span className="inline-flex items-center gap-1.5">{detail.host_id}<CopyButton text={detail.host_id} /></span>}
              mono
            />
            <Field label={t("detection.authEvents.colType")} value={`${typeLabel(detail.event_type)}${detail.count > 1 ? ` ×${detail.count}` : ""}`} />
            <Field label={t("detection.authEvents.fieldService")} value={dash(detail.service)} />
            <Field label={t("detection.authEvents.colUser")} value={dash(detail.username)} />
            {detail.target_user && <Field label={t("detection.authEvents.fieldTargetUser")} value={detail.target_user} />}
            {detail.source_ip && (
              <Field label={t("detection.authEvents.colSource")} value={`${detail.source_ip}${detail.source_port ? `:${detail.source_port}` : ""}`} mono />
            )}
            {detail.auth_method && <Field label={t("detection.authEvents.fieldMethod")} value={detail.auth_method} />}
            {detail.key_fingerprint && <Field label={t("detection.authEvents.fieldKey")} value={detail.key_fingerprint} mono />}
            {detail.reason && <Field label={t("detection.authEvents.fieldReason")} value={detail.reason} />}
            {detail.tty && <Field label="TTY" value={detail.tty} mono />}
            {detail.cwd && <Field label={t("detection.authEvents.fieldCwd")} value={detail.cwd} mono />}
            {detail.command && <Field label={t("detection.authEvents.fieldCommand")} value={detail.command} mono />}
            {detail.detail && <Field label={t("detection.authEvents.fieldDetail")} value={detail.detail} />}
            <Field
              label={t("detection.authEvents.fieldTrust")}
              value={detail.trust === "file" ? t("detection.authEvents.trustFile") : t("detection.authEvents.trustJournal")}
            />
            {detail.raw && <Field label={t("detection.authEvents.fieldRaw")} value={detail.raw} mono />}
          </div>
        )}
      </Drawer>
    </>
  );
}
