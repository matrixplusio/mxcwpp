"use client";
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
  ArrowLeft,
  Cpu,
  MemoryStick,
  HardDrive,
  Gauge,
  Activity,
  Boxes,
  ShieldAlert,
  Bug,
  Copy,
} from "lucide-react";
import { hostsApi } from "@/lib/api/assets";
import { alertsApi } from "@/lib/api/alerts";
import { vulnApi } from "@/lib/api/vuln";
import { baselineApi } from "@/lib/api/baseline";
import { virusApi } from "@/lib/api/virus";
import { monitorApi } from "@/lib/api/monitoring";
import { assetsApi } from "@/lib/api/assets";
import type {
  Host,
  HostPlugin,
  Alert,
  Vulnerability,
  BaselineFixItem,
  VirusScanResult,
  HostDiskPartition,
  MonitorRange,
  Paged,
  Process,
  Port,
  AssetUser,
  Software,
  Container,
  Service,
  Cron,
  Severity,
} from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { ChartCard } from "@/components/ui/ChartCard";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Tabs } from "@/components/ui/Tabs";
import { Drawer } from "@/components/ui/Drawer";
import { EmptyState } from "@/components/ui/EmptyState";
import { SeverityTag, StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";
import { copyText } from "@/lib/utils/clipboard";
import { chartColors, baseGrid, axisStyle, softTooltip, legendStyle } from "@/lib/echartsTheme";

const dash = (v: string | number | undefined | null) =>
  v === undefined || v === null || v === "" ? "—" : v;

const mono = "font-mono text-xs text-muted";

// Severity strings on vuln/virus are loose; normalize to the SeverityTag enum.
function normalizeSeverity(s: string | undefined): Severity {
  const v = (s || "").toLowerCase();
  if (v === "critical" || v === "high" || v === "medium" || v === "low") return v;
  return "low";
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs uppercase tracking-wide text-faint">{label}</span>
      <span className="break-words whitespace-pre-wrap text-sm text-ink">{value}</span>
    </div>
  );
}

// Click-to-copy value: shows the value (optionally a truncated display) with a
// hover copy icon and the full text in a native tooltip.
function CopyValue({
  value,
  display,
  label,
  className,
}: {
  value: string | undefined | null;
  display?: React.ReactNode;
  label: string;
  className?: string;
}) {
  const { t } = useTranslation();
  if (!value) return <span className="text-sm text-ink">—</span>;
  return (
    <button
      type="button"
      onClick={() => copyText(value, label)}
      title={`${value}\n${t("common.clickToCopy")}`}
      className={`group inline-flex max-w-full items-center gap-1.5 text-left text-sm text-ink hover:text-primary ${className ?? ""}`}
    >
      <span className="min-w-0 break-all">{display ?? value}</span>
      <Copy size={13} className="shrink-0 text-faint opacity-0 transition-opacity group-hover:opacity-100" />
    </button>
  );
}

// host_id is a 64-char sha256; show a short prefix and keep the full value for copy/tooltip.
function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 12)}…` : id;
}

/* ============================ Overview tab ============================ */

function OverviewTab({ host }: { host: Host }) {
  const { t } = useTranslation();
  const statusTone = host.status === "online" ? "success" : "neutral";
  const statusLabel = host.status === "online" ? t("common.online") : t("common.offline");
  const os = `${host.os_family} ${host.os_version}`.trim();

  return (
    <div className="space-y-5">
      <Card className="p-5">
        <h3 className="mb-4 text-sm font-semibold text-ink">{t("assets.hostDetail.sectionBasic")}</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label={t("assets.hosts.colHostname")} value={<CopyValue value={host.hostname} label={t("assets.hosts.colHostname")} />} />
          <Field
            label={t("assets.hosts.fieldHostId")}
            value={<CopyValue value={host.host_id} display={shortId(host.host_id)} label={t("assets.hosts.fieldHostId")} className="font-mono text-xs" />}
          />
          <Field
            label={t("common.status")}
            value={<StatusTag tone={statusTone}>{statusLabel}</StatusTag>}
          />
          <Field label={t("assets.hosts.colOs")} value={os ? <CopyValue value={os} label={t("assets.hosts.colOs")} /> : "—"} />
          <Field label={t("assets.hosts.fieldKernel")} value={<CopyValue value={host.kernel_version} label={t("assets.hosts.fieldKernel")} />} />
          <Field label={t("assets.hosts.fieldArch")} value={<CopyValue value={host.arch} label={t("assets.hosts.fieldArch")} />} />
          <Field
            label="IPv4"
            value={host.ipv4?.length ? <CopyValue value={host.ipv4.join(", ")} label="IPv4" /> : "—"}
          />
          <Field
            label="IPv6"
            value={host.ipv6?.length ? <CopyValue value={host.ipv6.join(", ")} label="IPv6" /> : "—"}
          />
          <Field
            label={t("assets.hosts.colBusinessLine")}
            value={host.business_line ? <CopyValue value={host.business_line} label={t("assets.hosts.colBusinessLine")} /> : "—"}
          />
          <Field
            label={t("assets.hostDetail.fieldRuntime")}
            value={host.runtime_type ? t(`assets.hosts.runtime${cap(host.runtime_type)}`) : "—"}
          />
          <Field
            label={t("assets.hosts.fieldCpuUsage")}
            value={host.cpu_usage ? <CopyValue value={`${host.cpu_usage}%`} label={t("assets.hosts.fieldCpuUsage")} /> : "—"}
          />
          <Field
            label={t("assets.hosts.fieldMemUsage")}
            value={host.memory_usage ? <CopyValue value={`${host.memory_usage}%`} label={t("assets.hosts.fieldMemUsage")} /> : "—"}
          />
          <Field
            label={t("assets.hosts.colAgentVersion")}
            value={<CopyValue value={host.agent_version} label={t("assets.hosts.colAgentVersion")} className="font-mono text-xs" />}
          />
          <Field
            label={t("assets.hosts.colLastHeartbeat")}
            value={<CopyValue value={host.last_heartbeat} label={t("assets.hosts.colLastHeartbeat")} className="tabular-nums" />}
          />
          <Field
            label={t("assets.hostDetail.fieldBootTime")}
            value={<CopyValue value={host.system_boot_time} label={t("assets.hostDetail.fieldBootTime")} className="tabular-nums" />}
          />
          <Field
            label={t("assets.hostDetail.fieldAgentStart")}
            value={<CopyValue value={host.agent_start_time} label={t("assets.hostDetail.fieldAgentStart")} className="tabular-nums" />}
          />
          <Field
            label={t("assets.hostDetail.fieldCreatedAt")}
            value={<CopyValue value={host.created_at} label={t("assets.hostDetail.fieldCreatedAt")} className="tabular-nums" />}
          />
          {host.is_container && (
            <Field label={t("assets.hostDetail.fieldContainerId")} value={<CopyValue value={host.container_id} label={t("assets.hostDetail.fieldContainerId")} className="font-mono text-xs" />} />
          )}
        </div>
      </Card>

      <ComponentVersions host={host} />

      <Card className="p-5">
        <h3 className="mb-4 text-sm font-semibold text-ink">{t("assets.hostDetail.sectionBaseline")}</h3>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Field
            label={t("assets.hostDetail.fieldBaselineScore")}
            value={host.baseline_score !== undefined ? <span className="text-lg font-semibold tabular-nums">{host.baseline_score}</span> : "—"}
          />
          <Field
            label={t("assets.hostDetail.fieldPassRate")}
            value={host.baseline_pass_rate !== undefined ? `${Math.round(host.baseline_pass_rate * 100)}%` : "—"}
          />
        </div>
      </Card>

      {host.tags && host.tags.length > 0 && (
        <Card className="p-5">
          <h3 className="mb-3 text-sm font-semibold text-ink">{t("assets.hosts.fieldTags")}</h3>
          <div className="flex flex-wrap gap-2">
            {host.tags.map((tag) => (
              <StatusTag key={tag} tone="neutral">
                {tag}
              </StatusTag>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/* ===================== Component versions (overview) ===================== */

interface ComponentRow {
  kind: "agent" | "plugin";
  name: string;
  version: string;
  status: string;
  needUpdate: boolean;
  latestVersion?: string;
}

function componentStatusTone(status: string): "success" | "warning" | "danger" | "neutral" {
  switch (status) {
    case "running":
    case "active":
      return "success";
    case "error":
      return "danger";
    case "stopped":
    case "not_installed":
      return "neutral";
    default:
      return "warning";
  }
}

function ComponentVersions({ host }: { host: Host }) {
  const { t } = useTranslation();
  const { data: plugins, isLoading } = useQuery({
    queryKey: ["host-plugins", host.host_id],
    queryFn: () => hostsApi.plugins(host.host_id),
    enabled: !!host.host_id,
  });

  const rows: ComponentRow[] = [
    {
      kind: "agent",
      name: "Agent",
      version: host.agent_version || "—",
      status: host.status === "online" ? "running" : "stopped",
      needUpdate: false,
    },
    ...(plugins ?? []).map<ComponentRow>((p) => ({
      kind: "plugin",
      name: p.name,
      version: p.version,
      status: p.status,
      needUpdate: p.need_update,
      latestVersion: p.latest_version,
    })),
  ];

  const columns: Column<ComponentRow>[] = [
    {
      key: "name",
      title: t("assets.hostDetail.colComponent"),
      render: (r) => (
        <div className="flex items-center gap-2">
          <StatusTag tone={r.kind === "agent" ? "info" : "neutral"}>
            {r.kind === "agent" ? "Agent" : t("assets.hostDetail.componentPlugin")}
          </StatusTag>
          <span className="font-medium text-ink">{r.name}</span>
        </div>
      ),
    },
    {
      key: "version",
      title: t("assets.hostDetail.colCurrentVersion"),
      render: (r) => (
        <span className="flex items-center gap-2">
          <span className="font-mono text-xs text-ink">{dash(r.version)}</span>
          {r.needUpdate && <StatusTag tone="warning">{t("assets.hostDetail.componentUpdatable")}</StatusTag>}
        </span>
      ),
    },
    {
      key: "latest",
      title: t("assets.hostDetail.colLatestVersion"),
      render: (r) => <span className="font-mono text-xs text-muted">{dash(r.latestVersion)}</span>,
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => (
        <StatusTag tone={componentStatusTone(r.status)}>
          {t(`assets.hostDetail.componentStatus.${r.status}`, r.status)}
        </StatusTag>
      ),
    },
  ];

  return (
    <Card className="p-5">
      <h3 className="mb-4 text-sm font-semibold text-ink">{t("assets.hostDetail.sectionComponents")}</h3>
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => `${r.kind}-${r.name}`}
        loading={isLoading}
        emptyText={t("common.noData")}
      />
    </Card>
  );
}

/* ============================ Alerts tab ============================ */

function AlertsTab({ hostId }: { hostId: string }) {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [keyword, setKeyword] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [detail, setDetail] = useState<Alert | null>(null);
  const queryClient = useQueryClient();
  const pageSize = 20;

  const { data, isLoading } = useQuery({
    queryKey: ["host-alerts", hostId, page, keyword, severity, status],
    queryFn: () =>
      alertsApi.list({
        page,
        page_size: pageSize,
        host_id: hostId,
        keyword: keyword || undefined,
        severity: severity || undefined,
        status: status || undefined,
      }),
  });

  const resolveMutation = useMutation({
    mutationFn: (id: number) => alertsApi.resolve(id, t("assets.hostDetail.resolveReason")),
    onSuccess: () => {
      toast.success(t("assets.hostDetail.alertResolved"));
      queryClient.invalidateQueries({ queryKey: ["host-alerts", hostId] });
      setDetail(null);
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : t("assets.hostDetail.opFailed")),
  });

  const statusTone = (s: Alert["status"]) =>
    s === "active" ? "danger" : s === "resolved" ? "success" : "neutral";

  const columns: Column<Alert>[] = [
    { key: "title", title: t("assets.hostDetail.colAlertTitle"), render: (r) => <span className="font-medium text-ink">{r.title}</span> },
    { key: "severity", title: t("assets.hostDetail.colSeverity"), render: (r) => <SeverityTag level={r.severity} /> },
    { key: "category", title: t("assets.hostDetail.colCategory"), render: (r) => dash(r.category) },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => <StatusTag tone={statusTone(r.status)}>{t(`assets.hostDetail.alertStatus.${r.status}`)}</StatusTag>,
    },
    { key: "first_seen_at", title: t("assets.hostDetail.colFirstSeen"), render: (r) => <span className="text-faint tabular-nums">{dash(r.first_seen_at)}</span> },
    {
      key: "ops",
      title: t("assets.hostDetail.colActions"),
      render: (r) => (
        <div className="flex gap-2">
          <Button variant="ghost" onClick={() => setDetail(r)}>
            {t("common.details")}
          </Button>
          {r.status === "active" && (
            <Button variant="ghost" onClick={() => resolveMutation.mutate(r.id)}>
              {t("assets.hostDetail.resolve")}
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <FilterBar>
        <SearchInput value={keyword} onChange={(v) => { setKeyword(v); setPage(1); }} placeholder={t("assets.hostDetail.alertSearch")} />
        <Select
          value={severity}
          onChange={(v) => { setSeverity(v); setPage(1); }}
          options={severityOptions(t)}
        />
        <Select
          value={status}
          onChange={(v) => { setStatus(v); setPage(1); }}
          options={[
            { label: t("assets.hostDetail.allStatus"), value: "" },
            { label: t("assets.hostDetail.alertStatus.active"), value: "active" },
            { label: t("assets.hostDetail.alertStatus.resolved"), value: "resolved" },
            { label: t("assets.hostDetail.alertStatus.ignored"), value: "ignored" },
          ]}
        />
      </FilterBar>
      <Card>
        <DataTable
          columns={columns}
          rows={data?.items ?? []}
          rowKey={(r) => String(r.id)}
          loading={isLoading}
          emptyText={t("common.noData")}
          onRowClick={(r) => setDetail(r)}
        />
        <Pagination page={page} pageSize={pageSize} total={data?.total ?? 0} onChange={setPage} />
      </Card>

      <Drawer open={!!detail} onClose={() => setDetail(null)} title={t("assets.hostDetail.alertDetailTitle")} width={620}>
        {detail && (
          <div className="space-y-4">
            <h3 className="text-base font-semibold text-ink">{detail.title}</h3>
            <div className="flex items-center gap-2">
              <SeverityTag level={detail.severity} />
              <StatusTag tone={statusTone(detail.status)}>{t(`assets.hostDetail.alertStatus.${detail.status}`)}</StatusTag>
            </div>
            <div className="space-y-3">
              <Field label={t("assets.hostDetail.colCategory")} value={dash(detail.category)} />
              {detail.description && <Field label={t("assets.hostDetail.fieldDescription")} value={detail.description} />}
              {detail.actual && <Field label={t("assets.hostDetail.fieldActual")} value={detail.actual} />}
              {detail.expected && <Field label={t("assets.hostDetail.fieldExpected")} value={detail.expected} />}
              {detail.fix_suggestion && <Field label={t("assets.hostDetail.fieldFixSuggestion")} value={detail.fix_suggestion} />}
              <Field label={t("assets.hostDetail.colFirstSeen")} value={dash(detail.first_seen_at)} />
              <Field label={t("assets.hostDetail.fieldLastSeen")} value={dash(detail.last_seen_at)} />
            </div>
            {detail.status === "active" && (
              <Button onClick={() => resolveMutation.mutate(detail.id)} disabled={resolveMutation.isPending}>
                {t("assets.hostDetail.resolve")}
              </Button>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
}

function severityOptions(t: TFunction) {
  return [
    { label: t("assets.hostDetail.allSeverity"), value: "" },
    { label: t("common.severity.critical"), value: "critical" },
    { label: t("common.severity.high"), value: "high" },
    { label: t("common.severity.medium"), value: "medium" },
    { label: t("common.severity.low"), value: "low" },
  ];
}

/* ============================ Vulnerabilities tab ============================ */

function VulnTab({ hostId }: { hostId: string }) {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [detail, setDetail] = useState<Vulnerability | null>(null);
  const pageSize = 20;

  const { data, isLoading } = useQuery({
    queryKey: ["host-vulns", hostId, page, search, severity, status],
    queryFn: () =>
      vulnApi.listVulns({
        page,
        page_size: pageSize,
        host_id: hostId,
        search: search || undefined,
        severity: severity || undefined,
        status: status || undefined,
      }),
  });

  const stats = data?.stats;

  const columns: Column<Vulnerability>[] = [
    {
      key: "cveId",
      title: t("assets.hostDetail.colCve"),
      render: (r) => (
        <a
          href={`https://nvd.nist.gov/vuln/detail/${r.cveId}`}
          target="_blank"
          rel="noreferrer"
          className="font-mono text-xs text-primary hover:underline"
          onClick={(e) => e.stopPropagation()}
        >
          {r.cveId}
        </a>
      ),
    },
    { key: "severity", title: t("assets.hostDetail.colSeverity"), render: (r) => <SeverityTag level={normalizeSeverity(r.severity)} /> },
    { key: "cvssScore", title: "CVSS", render: (r) => <span className="tabular-nums">{r.cvssScore?.toFixed(1) ?? "—"}</span> },
    { key: "component", title: t("assets.hostDetail.colComponent"), render: (r) => dash(r.component) },
    { key: "currentVersion", title: t("assets.hostDetail.colCurrentVersion"), render: (r) => <span className={mono}>{dash(r.currentVersion)}</span> },
    { key: "fixedVersion", title: t("assets.hostDetail.colFixedVersion"), render: (r) => <span className={mono}>{dash(r.fixedVersion)}</span> },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => <StatusTag tone={r.status === "patched" ? "success" : r.status === "ignored" ? "neutral" : "warning"}>{r.status}</StatusTag>,
    },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard compact label={t("assets.hostDetail.statVulnTotal")} value={stats?.total ?? 0} icon={Bug} />
        <StatCard compact label={t("assets.hostDetail.statVulnCritical")} value={stats?.critical ?? 0} icon={ShieldAlert} tone="danger" />
        <StatCard compact label={t("assets.hostDetail.statVulnHigh")} value={stats?.high ?? 0} icon={ShieldAlert} tone="warning" />
        <StatCard compact label={t("assets.hostDetail.statAffectedHosts")} value={stats?.affectedHosts ?? 0} icon={Boxes} />
      </div>
      <FilterBar>
        <SearchInput value={search} onChange={(v) => { setSearch(v); setPage(1); }} placeholder={t("assets.hostDetail.vulnSearch")} />
        <Select value={severity} onChange={(v) => { setSeverity(v); setPage(1); }} options={severityOptions(t)} />
        <Select
          value={status}
          onChange={(v) => { setStatus(v); setPage(1); }}
          options={[
            { label: t("assets.hostDetail.allStatus"), value: "" },
            { label: t("assets.hostDetail.vulnStatus.unpatched"), value: "unpatched" },
            { label: t("assets.hostDetail.vulnStatus.patched"), value: "patched" },
            { label: t("assets.hostDetail.vulnStatus.ignored"), value: "ignored" },
          ]}
        />
      </FilterBar>
      <Card>
        <DataTable
          columns={columns}
          rows={data?.items ?? []}
          rowKey={(r) => String(r.id)}
          loading={isLoading}
          emptyText={t("common.noData")}
          onRowClick={(r) => setDetail(r)}
        />
        <Pagination page={page} pageSize={pageSize} total={data?.total ?? 0} onChange={setPage} />
      </Card>

      <Drawer open={!!detail} onClose={() => setDetail(null)} title={t("assets.hostDetail.vulnDetailTitle")} width={620}>
        {detail && (
          <div className="space-y-4">
            <h3 className="font-mono text-base font-semibold text-ink">{detail.cveId}</h3>
            <div className="flex items-center gap-2">
              <SeverityTag level={normalizeSeverity(detail.severity)} />
              <StatusTag tone="neutral">CVSS {detail.cvssScore?.toFixed(1) ?? "—"}</StatusTag>
            </div>
            <div className="space-y-3">
              <Field label={t("assets.hostDetail.colComponent")} value={dash(detail.component)} />
              <Field label={t("assets.hostDetail.colCurrentVersion")} value={<span className={mono}>{dash(detail.currentVersion)}</span>} />
              <Field label={t("assets.hostDetail.colFixedVersion")} value={<span className={mono}>{dash(detail.fixedVersion)}</span>} />
              {detail.description && <Field label={t("assets.hostDetail.fieldDescription")} value={detail.description} />}
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}

/* ============================ Baseline tab ============================ */

function BaselineTab({ hostId }: { hostId: string }) {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const pageSize = 20;

  const { data, isLoading } = useQuery({
    queryKey: ["host-baseline", hostId, page, severity],
    queryFn: () =>
      baselineApi.listFixItems({
        page,
        page_size: pageSize,
        host_ids: [hostId],
        severities: severity ? [severity] : undefined,
      }),
  });

  // listFixItems has no keyword param; filter the current page client-side.
  const rows = (data?.items ?? []).filter((r) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return r.rule_id.toLowerCase().includes(q) || r.title.toLowerCase().includes(q);
  });

  const columns: Column<BaselineFixItem>[] = [
    { key: "rule_id", title: t("assets.hostDetail.colRuleId"), render: (r) => <span className={mono}>{r.rule_id}</span> },
    { key: "title", title: t("assets.hostDetail.colCheckTitle"), render: (r) => <span className="font-medium text-ink">{r.title}</span> },
    { key: "category", title: t("assets.hostDetail.colCategory"), render: (r) => dash(r.category) },
    { key: "severity", title: t("assets.hostDetail.colSeverity"), render: (r) => <SeverityTag level={r.severity} /> },
    {
      key: "reason",
      title: t("assets.hostDetail.colFailReason"),
      render: (r) => (
        <span className="block max-w-[320px] truncate text-muted" title={r.actual || r.expected || ""}>
          {dash(r.actual || r.expected)}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <FilterBar>
        <SearchInput value={search} onChange={(v) => { setSearch(v); }} placeholder={t("assets.hostDetail.baselineSearch")} />
        <Select value={severity} onChange={(v) => { setSeverity(v); setPage(1); }} options={severityOptions(t)} />
      </FilterBar>
      <Card>
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(r) => `${r.task_id}_${r.host_id}_${r.rule_id}`}
          loading={isLoading}
          emptyText={t("assets.hostDetail.baselineEmpty")}
        />
        <Pagination page={page} pageSize={pageSize} total={data?.total ?? 0} onChange={setPage} />
      </Card>
    </div>
  );
}

/* ============================ Antivirus tab ============================ */

function AntivirusTab({ hostId }: { hostId: string }) {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [keyword, setKeyword] = useState("");
  const [severity, setSeverity] = useState("");
  const pageSize = 20;

  const { data, isLoading } = useQuery({
    queryKey: ["host-virus", page, keyword, severity],
    queryFn: () =>
      virusApi.listResults({
        page,
        page_size: pageSize,
        keyword: keyword || undefined,
        severity: severity || undefined,
      }),
  });

  // listResults API has no host_id filter; scope to this host client-side.
  const rows = (data?.items ?? []).filter((r) => r.hostId === hostId);

  const actionTone = (a: string) =>
    a === "quarantined" ? "warning" : a === "deleted" ? "success" : a === "ignored" ? "neutral" : "danger";

  const columns: Column<VirusScanResult>[] = [
    {
      key: "filePath",
      title: t("assets.hostDetail.colFilePath"),
      render: (r) => (
        <span className="block max-w-[280px] truncate font-mono text-xs text-ink" title={r.filePath}>
          {r.filePath}
        </span>
      ),
    },
    { key: "threatName", title: t("assets.hostDetail.colThreatName"), render: (r) => <span className="font-medium text-ink">{dash(r.threatName)}</span> },
    { key: "severity", title: t("assets.hostDetail.colSeverity"), render: (r) => <SeverityTag level={normalizeSeverity(r.severity)} /> },
    { key: "action", title: t("assets.hostDetail.colAction"), render: (r) => <StatusTag tone={actionTone(r.action)}>{t(`assets.hostDetail.virusAction.${r.action}`, r.action)}</StatusTag> },
    { key: "detectedAt", title: t("assets.hostDetail.colDetectedAt"), render: (r) => <span className="text-faint tabular-nums">{dash(r.detectedAt)}</span> },
  ];

  return (
    <div className="space-y-4">
      <div className="rounded-control border border-border bg-surface-muted px-4 py-2.5 text-xs text-muted">
        {t("assets.hostDetail.virusScopeNote")}
      </div>
      <FilterBar>
        <SearchInput value={keyword} onChange={(v) => { setKeyword(v); setPage(1); }} placeholder={t("assets.hostDetail.virusSearch")} />
        <Select value={severity} onChange={(v) => { setSeverity(v); setPage(1); }} options={severityOptions(t)} />
      </FilterBar>
      <Card>
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(r) => String(r.id)}
          loading={isLoading}
          emptyText={t("common.noData")}
        />
        <Pagination page={page} pageSize={pageSize} total={data?.total ?? 0} onChange={setPage} />
      </Card>
    </div>
  );
}

/* ============================ Performance tab ============================ */

function lineOption(x: string[], series: { name: string; data: number[] }[], unit?: string) {
  return {
    color: chartColors,
    grid: baseGrid,
    tooltip: { trigger: "axis", ...softTooltip },
    legend: { right: 0, top: 0, ...legendStyle },
    xAxis: { type: "category", boundaryGap: false, data: x, ...axisStyle },
    yAxis: {
      type: "value",
      ...axisStyle,
      axisLabel: unit ? { ...axisStyle.axisLabel, formatter: `{value}${unit}` } : axisStyle.axisLabel,
    },
    series: series.map((s) => ({
      name: s.name,
      type: "line",
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 2.5 },
      areaStyle: { opacity: 0.05 },
      data: s.data,
    })),
  };
}

function pctTone(v: number): "default" | "danger" | "warning" | "success" {
  if (v > 90) return "danger";
  if (v > 70) return "warning";
  return "success";
}

function PerformanceTab() {
  const { t } = useTranslation();
  const [range, setRange] = useState<MonitorRange>("1h");
  const { data, isLoading } = useQuery({
    queryKey: ["host-perf", range],
    queryFn: () => monitorApi.hostMetrics(range),
  });

  const ov = data?.overview;
  const cpu = data?.cpu ?? [];
  const memory = data?.memory ?? [];
  const disk = data?.disk ?? [];
  const network = data?.network ?? [];
  const partitions = data?.partitions ?? [];

  const rangeItems = [
    { key: "1h", label: t("monitoring.range.1h") },
    { key: "6h", label: t("monitoring.range.6h") },
    { key: "24h", label: t("monitoring.range.24h") },
  ];

  const partColumns: Column<HostDiskPartition>[] = [
    { key: "mountPoint", title: t("monitoring.host.colMountPoint"), render: (r) => <span className="font-medium text-ink">{r.mountPoint}</span> },
    { key: "filesystem", title: t("monitoring.host.colFilesystem"), render: (r) => <span className="text-muted">{r.filesystem}</span> },
    { key: "total", title: t("monitoring.host.colTotal"), render: (r) => <span className="text-muted tabular-nums">{r.total}</span> },
    { key: "used", title: t("monitoring.host.colUsed"), render: (r) => <span className="text-muted tabular-nums">{r.used}</span> },
    { key: "available", title: t("monitoring.host.colAvailable"), render: (r) => <span className="text-muted tabular-nums">{r.available}</span> },
    { key: "usagePercent", title: t("monitoring.host.colUsage"), render: (r) => <span className="text-ink tabular-nums">{r.usagePercent.toFixed(1)}%</span> },
  ];

  return (
    <div className="space-y-4">
      <div className="rounded-control border border-border bg-surface-muted px-4 py-2.5 text-xs text-muted">
        {t("assets.hostDetail.perfScopeNote")}
      </div>
      <div className="flex justify-end">
        <Tabs items={rangeItems} active={range} onChange={(k) => setRange(k as MonitorRange)} />
      </div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        <StatCard label={t("monitoring.host.statCpu")} value={`${(ov?.cpu ?? 0).toFixed(1)}%`} icon={Cpu} tone={pctTone(ov?.cpu ?? 0)} />
        <StatCard label={t("monitoring.host.statMemory")} value={`${(ov?.memory ?? 0).toFixed(1)}%`} icon={MemoryStick} tone={pctTone(ov?.memory ?? 0)} />
        <StatCard label={t("monitoring.host.statDisk")} value={`${(ov?.disk ?? 0).toFixed(1)}%`} icon={HardDrive} tone={pctTone(ov?.disk ?? 0)} />
        <StatCard label={t("monitoring.host.statLoad")} value={(ov?.load ?? 0).toFixed(2)} icon={Gauge} tone="default" />
        <StatCard label={t("monitoring.host.statAgentCpu")} value={`${(ov?.agentCpu ?? 0).toFixed(1)}%`} icon={Activity} tone={pctTone(ov?.agentCpu ?? 0)} />
        <StatCard label={t("monitoring.host.statAgentMem")} value={`${(ov?.agentMemMB ?? 0).toFixed(1)} MB`} icon={Boxes} tone="default" />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard title={t("monitoring.host.chartCpu")} option={lineOption(cpu.map((d) => d.time), [{ name: t("monitoring.host.seriesCpu"), data: cpu.map((d) => d.usage) }], "%")} />
        <ChartCard title={t("monitoring.host.chartMemory")} option={lineOption(memory.map((d) => d.time), [{ name: t("monitoring.host.seriesMemory"), data: memory.map((d) => d.usage) }], "%")} />
        <ChartCard title={t("monitoring.host.chartDiskIo")} option={lineOption(disk.map((d) => d.time), [{ name: t("monitoring.host.seriesRead"), data: disk.map((d) => d.read) }, { name: t("monitoring.host.seriesWrite"), data: disk.map((d) => d.write) }])} />
        <ChartCard title={t("monitoring.host.chartNetwork")} option={lineOption(network.map((d) => d.time), [{ name: t("monitoring.host.seriesInbound"), data: network.map((d) => d.inbound) }, { name: t("monitoring.host.seriesOutbound"), data: network.map((d) => d.outbound) }])} />
      </div>
      <Card>
        <DataTable
          columns={partColumns}
          rows={partitions}
          rowKey={(r) => r.mountPoint}
          loading={isLoading}
          emptyText={t("monitoring.host.emptyPartitions")}
        />
      </Card>
    </div>
  );
}

/* ============================ Fingerprint tab ============================ */

interface FpConfig<T> {
  key: string;
  label: string;
  columns: Column<T>[];
  fetch: (params: { host_id?: string; page?: number; page_size?: number }) => Promise<Paged<T>>;
  rowId: (row: T) => string;
}
function defineFp<T>(cfg: FpConfig<T>): FpConfig<unknown> {
  return cfg as unknown as FpConfig<unknown>;
}

function buildFpTabs(t: TFunction): FpConfig<unknown>[] {
  return [
    defineFp<Port>({
      key: "ports",
      label: t("assets.fingerprint.tabPorts"),
      fetch: assetsApi.listPorts,
      rowId: (r) => `${r.host_id}-${r.protocol}-${r.port}`,
      columns: [
        { key: "protocol", title: t("assets.fingerprint.colProtocol"), render: (r) => dash(r.protocol) },
        { key: "port", title: t("assets.fingerprint.colPort"), render: (r) => <span className="tabular-nums">{r.port}</span> },
        { key: "process_name", title: t("assets.fingerprint.colProcess"), render: (r) => dash(r.process_name) },
        { key: "pid", title: "PID", render: (r) => <span className={mono}>{dash(r.pid)}</span> },
        { key: "state", title: t("common.status"), render: (r) => (r.state ? <StatusTag tone="info">{r.state}</StatusTag> : "—") },
      ],
    }),
    defineFp<Process>({
      key: "processes",
      label: t("assets.fingerprint.tabProcesses"),
      fetch: assetsApi.listProcesses,
      rowId: (r) => `${r.host_id}-${r.pid}`,
      columns: [
        { key: "pid", title: "PID", render: (r) => <span className={mono}>{dash(r.pid)}</span> },
        { key: "exe", title: t("assets.fingerprint.colExe"), render: (r) => <span className={mono}>{dash(r.exe)}</span> },
        { key: "cmdline", title: t("assets.fingerprint.colCmdline"), render: (r) => <span className={`${mono} block max-w-[280px] truncate`} title={r.cmdline}>{dash(r.cmdline)}</span> },
        { key: "username", title: t("assets.fingerprint.colUser"), render: (r) => dash(r.username) },
      ],
    }),
    defineFp<AssetUser>({
      key: "users",
      label: t("assets.fingerprint.tabUsers"),
      fetch: assetsApi.listUsers,
      rowId: (r) => `${r.host_id}-${r.username}`,
      columns: [
        { key: "username", title: t("assets.fingerprint.colUsername"), render: (r) => <span className="font-medium text-ink">{dash(r.username)}</span> },
        { key: "uid", title: "UID", render: (r) => <span className={mono}>{dash(r.uid)}</span> },
        { key: "gid", title: "GID", render: (r) => <span className={mono}>{dash(r.gid)}</span> },
        { key: "shell", title: "Shell", render: (r) => <span className={mono}>{dash(r.shell)}</span> },
        { key: "home_dir", title: t("assets.fingerprint.colHome"), render: (r) => <span className={mono}>{dash(r.home_dir)}</span> },
      ],
    }),
    defineFp<Software>({
      key: "software",
      label: t("assets.fingerprint.tabSoftware"),
      fetch: assetsApi.listSoftware,
      rowId: (r) => `${r.host_id}-${r.name}-${r.version ?? ""}`,
      columns: [
        { key: "name", title: t("common.name"), render: (r) => <span className="font-medium text-ink">{dash(r.name)}</span> },
        { key: "version", title: t("common.version"), render: (r) => <span className={mono}>{dash(r.version)}</span> },
        { key: "package_type", title: t("common.type"), render: (r) => (r.package_type ? <StatusTag tone="neutral">{r.package_type}</StatusTag> : "—") },
        { key: "vendor", title: t("assets.fingerprint.colVendor"), render: (r) => dash(r.vendor) },
      ],
    }),
    defineFp<Container>({
      key: "containers",
      label: t("assets.fingerprint.tabContainers"),
      fetch: assetsApi.listContainers,
      rowId: (r) => `${r.host_id}-${r.container_id}`,
      columns: [
        { key: "container_name", title: t("common.name"), render: (r) => <span className="font-medium text-ink">{dash(r.container_name)}</span> },
        { key: "image", title: t("assets.fingerprint.colImage"), render: (r) => <span className={`${mono} block max-w-[280px] truncate`} title={r.image}>{dash(r.image)}</span> },
        { key: "runtime", title: t("assets.fingerprint.colRuntime"), render: (r) => dash(r.runtime) },
        { key: "status", title: t("common.status"), render: (r) => (r.status ? <StatusTag tone={r.status.toLowerCase().includes("run") ? "success" : "neutral"}>{r.status}</StatusTag> : "—") },
      ],
    }),
    defineFp<Service>({
      key: "services",
      label: t("assets.fingerprint.tabServices"),
      fetch: assetsApi.listServices,
      rowId: (r) => `${r.host_id}-${r.service_name}`,
      columns: [
        { key: "service_name", title: t("assets.fingerprint.colServiceName"), render: (r) => <span className="font-medium text-ink">{dash(r.service_name)}</span> },
        { key: "service_type", title: t("common.type"), render: (r) => dash(r.service_type) },
        { key: "status", title: t("common.status"), render: (r) => (r.status ? <StatusTag tone={r.status.toLowerCase().includes("run") || r.status.toLowerCase() === "active" ? "success" : "neutral"}>{r.status}</StatusTag> : "—") },
      ],
    }),
    defineFp<Cron>({
      key: "crons",
      label: t("assets.fingerprint.tabCrons"),
      fetch: assetsApi.listCrons,
      rowId: (r) => `${r.host_id}-${r.user}-${r.schedule}`,
      columns: [
        { key: "user", title: t("assets.fingerprint.colUser"), render: (r) => dash(r.user) },
        { key: "schedule", title: t("assets.fingerprint.colSchedule"), render: (r) => <span className={mono}>{dash(r.schedule)}</span> },
        { key: "command", title: t("assets.fingerprint.colCommand"), render: (r) => <span className={`${mono} block max-w-[280px] truncate`} title={r.command}>{dash(r.command)}</span> },
      ],
    }),
  ];
}

function FingerprintTab({ hostId }: { hostId: string }) {
  const { t } = useTranslation();
  const tabs = useMemo(() => buildFpTabs(t), [t]);
  const [activeFp, setActiveFp] = useState("ports");
  const [page, setPage] = useState(1);
  const pageSize = 20;
  const current = tabs.find((tab) => tab.key === activeFp) ?? tabs[0];

  const { data, isLoading } = useQuery({
    queryKey: ["host-fp", hostId, activeFp, page],
    queryFn: () => current.fetch({ host_id: hostId, page, page_size: pageSize }),
  });

  return (
    <div className="space-y-4">
      <Tabs items={tabs.map((tab) => ({ key: tab.key, label: tab.label }))} active={activeFp} onChange={(k) => { setActiveFp(k); setPage(1); }} />
      <Card>
        <DataTable
          columns={current.columns}
          rows={data?.items ?? []}
          rowKey={(r) => current.rowId(r)}
          loading={isLoading}
          emptyText={t("common.noData")}
        />
        <Pagination page={page} pageSize={pageSize} total={data?.total ?? 0} onChange={setPage} />
      </Card>
    </div>
  );
}

/* ============================ Page ============================ */

export default function HostDetailPage() {
  const { t } = useTranslation();
  const router = useRouter();
  // Static export: read the host id from the query string at runtime.
  const [hostId, setHostId] = useState("");
  useEffect(() => {
    setHostId(new URLSearchParams(window.location.search).get("id") ?? "");
  }, []);
  const [activeTab, setActiveTab] = useState("overview");

  const { data: host, isLoading, isError } = useQuery({
    queryKey: ["host", hostId],
    queryFn: () => hostsApi.get(hostId),
    enabled: !!hostId,
  });

  const tabItems = [
    { key: "overview", label: t("assets.hostDetail.tabOverview") },
    { key: "alerts", label: t("assets.hostDetail.tabAlerts") },
    { key: "vulnerabilities", label: t("assets.hostDetail.tabVulnerabilities") },
    { key: "baseline", label: t("assets.hostDetail.tabBaseline") },
    { key: "antivirus", label: t("assets.hostDetail.tabAntivirus") },
    { key: "performance", label: t("assets.hostDetail.tabPerformance") },
    { key: "fingerprint", label: t("assets.hostDetail.tabFingerprint") },
  ];

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => router.push("/assets/hosts")}
          className="flex h-8 w-8 items-center justify-center rounded-control text-muted transition-colors hover:bg-surface-muted hover:text-ink"
          aria-label={t("common.back")}
        >
          <ArrowLeft size={18} />
        </button>
        <div className="flex min-w-0 items-center gap-3">
          <h1 className="truncate text-xl font-bold text-ink">{host?.hostname || t("assets.hosts.detailTitle")}</h1>
          {host && (
            <StatusTag tone={host.status === "online" ? "success" : "neutral"}>
              {host.status === "online" ? t("common.online") : t("common.offline")}
            </StatusTag>
          )}
        </div>
      </div>

      {isError ? (
        <Card className="p-5">
          <EmptyState title={t("assets.hostDetail.loadError")} desc={t("assets.hostDetail.loadErrorDesc")} />
        </Card>
      ) : (
        <>
          <Tabs items={tabItems} active={activeTab} onChange={setActiveTab} />

          {isLoading && !host ? (
            <Card className="p-5">
              <div className="py-10 text-center text-sm text-muted">{t("common.loading")}</div>
            </Card>
          ) : !host ? null : (
            <>
              {activeTab === "overview" && <OverviewTab host={host} />}
              {activeTab === "alerts" && <AlertsTab hostId={hostId} />}
              {activeTab === "vulnerabilities" && <VulnTab hostId={hostId} />}
              {activeTab === "baseline" && <BaselineTab hostId={hostId} />}
              {activeTab === "antivirus" && <AntivirusTab hostId={hostId} />}
              {activeTab === "performance" && <PerformanceTab />}
              {activeTab === "fingerprint" && <FingerprintTab hostId={hostId} />}
            </>
          )}
        </>
      )}
    </div>
  );
}
