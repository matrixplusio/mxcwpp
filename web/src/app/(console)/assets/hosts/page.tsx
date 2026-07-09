"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Server, Wifi, WifiOff } from "lucide-react";
import { hostsApi, businessLinesApi } from "@/lib/api/assets";
import type { Host, RuntimeType } from "@/lib/api/types";
import { useUrlState } from "@/hooks/useUrlState";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { CopyButton } from "@/components/ui/CopyButton";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Modal } from "@/components/ui/Modal";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

// OS family labels are proper nouns and stay untranslated.
const osFamilies: { label: string; value: string }[] = [
  { label: "CentOS", value: "centos" },
  { label: "Rocky", value: "rocky" },
  { label: "AlmaLinux", value: "almalinux" },
  { label: "RHEL", value: "rhel" },
  { label: "Ubuntu", value: "ubuntu" },
  { label: "Debian", value: "debian" },
  { label: "openEuler", value: "openeuler" },
  { label: "Kylin", value: "kylin" },
];
const osLabelMap: Record<string, string> = Object.fromEntries(osFamilies.map((o) => [o.value, o.label]));

export default function HostsPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const queryClient = useQueryClient();

  const osLabel = (f: string) => osLabelMap[(f || "").toLowerCase()] ?? (f || t("assets.hosts.unknown"));
  const statusMeta = (status: Host["status"]): { tone: "success" | "neutral"; label: string } => {
    if (status === "online") return { tone: "success", label: t("common.online") };
    if (status === "offline") return { tone: "neutral", label: t("common.offline") };
    return { tone: "neutral", label: status };
  };
  const statusOptions = [
    { label: t("assets.hosts.allStatus"), value: "" },
    { label: t("common.online"), value: "online" },
    { label: t("common.offline"), value: "offline" },
  ];
  const runtimeOptions = [
    { label: t("assets.hosts.allRuntime"), value: "" },
    { label: t("assets.hosts.runtimeVm"), value: "vm" },
    { label: t("assets.hosts.runtimeDocker"), value: "docker" },
    { label: t("assets.hosts.runtimeK8s"), value: "k8s" },
  ];
  const osFamilyOptions = [{ label: t("assets.hosts.allOs"), value: "" }, ...osFamilies];

  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    search: "",
    status: "",
    business_line: "",
    os_family: "",
    runtime_type: "",
  });

  const { data: statusDist } = useQuery({
    queryKey: ["hosts-status-dist"],
    queryFn: () => hostsApi.statusDistribution(),
  });
  const { data: blList } = useQuery({
    queryKey: ["business-lines-all"],
    queryFn: () => businessLinesApi.list({ page: 1, page_size: 200 }),
  });
  const businessLineOptions = [
    { label: t("assets.hosts.allBusinessLines"), value: "" },
    ...(blList?.items ?? []).map((b) => ({ label: b.name, value: b.code })),
  ];

  // 系统分布(后端 os-distribution 端点单条 GROUP BY,前端只做发行版 label + 主版本号拼接)
  const { data: osDistRaw } = useQuery({
    queryKey: ["hosts-os-dist"],
    queryFn: () => hostsApi.osDistribution(),
  });
  const osDist = (osDistRaw ?? [])
    .map((d) => {
      const major = (d.major || "").trim();
      const name = major ? `${osLabel(d.os_family)} ${major}` : osLabel(d.os_family);
      return { name, value: d.count };
    })
    .sort((a, b) => b.value - a.value);
  // 类型过多时折叠尾部为「其他 N」,避免撑爆卡片
  const OS_MAX = 7;
  const osDisplay =
    osDist.length > OS_MAX
      ? [
          ...osDist.slice(0, OS_MAX - 1),
          { name: t("assets.hosts.osOther"), value: osDist.slice(OS_MAX - 1).reduce((s, d) => s + d.value, 0) },
        ]
      : osDist;

  const { data, isLoading } = useQuery({
    queryKey: ["hosts", params],
    queryFn: () =>
      hostsApi.list({
        page: params.page,
        page_size: params.page_size,
        search: params.search || undefined,
        status: params.status || undefined,
        business_line: params.business_line || undefined,
        os_family: params.os_family || undefined,
        runtime_type: (params.runtime_type || undefined) as RuntimeType | undefined,
      }),
  });

  const rows = data?.items ?? [];

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const clearSelection = () => setSelected(new Set());

  const toggleRow = (key: string | number) => {
    const id = String(key);
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const toggleAll = (checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const r of rows) {
        if (checked) next.add(r.host_id);
        else next.delete(r.host_id);
      }
      return next;
    });
  };

  const onBatchSuccess = (msg: string) => {
    queryClient.invalidateQueries({ queryKey: ["hosts"] });
    queryClient.invalidateQueries({ queryKey: ["hosts-status-dist"] });
    clearSelection();
    toast.success(msg);
  };
  const onBatchError = (e: unknown) => {
    toast.error(e instanceof Error ? e.message : t("assets.hosts.opFailed"));
  };

  const restartMutation = useMutation({
    mutationFn: () => hostsApi.restartAgent([...selected]),
    onSuccess: () => {
      onBatchSuccess(t("assets.hosts.restartDone"));
      setRestartOpen(false);
    },
    onError: onBatchError,
  });
  const deleteMutation = useMutation({
    mutationFn: () => hostsApi.batchDelete([...selected]),
    onSuccess: () => {
      onBatchSuccess(t("assets.hosts.deleteDone"));
      setDeleteOpen(false);
    },
    onError: onBatchError,
  });
  const blMutation = useMutation({
    mutationFn: () => hostsApi.batchUpdateBusinessLine([...selected], blValue),
    onSuccess: () => {
      onBatchSuccess(t("assets.hosts.blUpdated"));
      setBlOpen(false);
    },
    onError: onBatchError,
  });
  const tagsMutation = useMutation({
    mutationFn: () =>
      hostsApi.batchUpdateTags(
        [...selected],
        tagsValue
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      ),
    onSuccess: () => {
      onBatchSuccess(t("assets.hosts.tagsUpdated"));
      setTagsOpen(false);
    },
    onError: onBatchError,
  });

  const [restartOpen, setRestartOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [blOpen, setBlOpen] = useState(false);
  const [blValue, setBlValue] = useState("");
  const [tagsOpen, setTagsOpen] = useState(false);
  const [tagsValue, setTagsValue] = useState("");

  const totalHosts = statusDist
    ? statusDist.running + statusDist.abnormal + statusDist.offline + statusDist.not_installed + statusDist.uninstalled
    : (data?.total ?? 0);
  const onlineCount = statusDist?.running ?? 0;
  const offlineCount = statusDist?.offline ?? 0;

  const columns: Column<Host>[] = [
    {
      key: "hostname",
      title: t("assets.hosts.colHostname"),
      render: (r) => (
        <div className="min-w-0">
          <div className="truncate font-medium text-ink">{r.hostname}</div>
          <div className="flex items-center gap-1.5">
            <span className="truncate text-xs text-faint">{r.host_id}</span>
            <CopyButton text={r.host_id} />
          </div>
        </div>
      ),
    },
    {
      key: "ipv4",
      title: t("assets.hosts.colIp"),
      render: (r) => <span className="block max-w-[200px] truncate text-faint">{r.ipv4?.join(", ") || "—"}</span>,
    },
    {
      key: "os",
      title: t("assets.hosts.colOs"),
      render: (r) => <span className="text-muted">{`${r.os_family} ${r.os_version}`.trim() || "—"}</span>,
    },
    {
      key: "business_line",
      title: t("assets.hosts.colBusinessLine"),
      render: (r) => r.business_line || "—",
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => {
        const m = statusMeta(r.status);
        return <StatusTag tone={m.tone}>{m.label}</StatusTag>;
      },
    },
    {
      key: "agent_version",
      title: t("assets.hosts.colAgentVersion"),
      render: (r) => <span className="font-mono text-xs text-faint">{r.agent_version || "—"}</span>,
    },
    {
      key: "last_heartbeat",
      title: t("assets.hosts.colLastHeartbeat"),
      render: (r) => <span className="text-faint tabular-nums">{r.last_heartbeat || "—"}</span>,
    },
  ];

  return (
    <>
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-[repeat(3,minmax(0,1fr))_1.8fr]">
        <StatCard compact label={t("assets.hosts.statTotal")} value={totalHosts} icon={Server} tone="default" />
        <StatCard compact label={t("common.online")} value={onlineCount} icon={Wifi} tone="success" />
        <StatCard compact label={t("common.offline")} value={offlineCount} icon={WifiOff} tone="warning" />
        <Card className="flex flex-col gap-1.5 p-3.5">
          <div className="text-sm text-muted">{t("assets.hosts.statOsDist")}</div>
          <div className="flex max-h-12 flex-wrap gap-x-3 gap-y-1 overflow-y-auto text-sm">
            {osDisplay.length === 0 ? (
              <span className="text-faint">—</span>
            ) : (
              osDisplay.map((d) => (
                <span key={d.name} className="whitespace-nowrap text-muted">
                  {d.name} <span className="font-semibold tabular-nums text-ink">{d.value}</span>
                </span>
              ))
            )}
          </div>
        </Card>
      </div>

      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={params.search}
            onChange={(v) => setParams({ search: v, page: 1 })}
            placeholder={t("assets.hosts.searchPlaceholder")}
          />
          <Select
            value={params.status}
            onChange={(v) => setParams({ status: v, page: 1 })}
            options={statusOptions}
          />
          <Select
            value={params.runtime_type}
            onChange={(v) => setParams({ runtime_type: v, page: 1 })}
            options={runtimeOptions}
          />
          <Select
            value={params.os_family}
            onChange={(v) => setParams({ os_family: v, page: 1 })}
            options={osFamilyOptions}
          />
          <Select
            value={params.business_line}
            onChange={(v) => setParams({ business_line: v, page: 1 })}
            options={businessLineOptions}
          />
        </FilterBar>
        <Card>
          {selected.size > 0 && (
            <div className="mb-3 flex flex-wrap items-center gap-2 rounded-control border border-border bg-bg px-4 py-2.5">
              <span className="text-sm font-medium text-ink">{t("assets.hosts.selected", { count: selected.size })}</span>
              <div className="ml-auto flex flex-wrap gap-2">
                <Button variant="ghost" onClick={() => setRestartOpen(true)}>
                  {t("assets.hosts.restartAgent")}
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setBlValue("");
                    setBlOpen(true);
                  }}
                >
                  {t("assets.hosts.changeBusinessLine")}
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setTagsValue("");
                    setTagsOpen(true);
                  }}
                >
                  {t("assets.hosts.addTags")}
                </Button>
                <Button variant="danger" onClick={() => setDeleteOpen(true)}>
                  {t("common.delete")}
                </Button>
                <Button variant="ghost" onClick={clearSelection}>
                  {t("assets.hosts.clearSelection")}
                </Button>
              </div>
            </div>
          )}
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(r) => r.host_id}
            loading={isLoading}
            emptyText={t("assets.hosts.empty")}
            onRowClick={(r) => router.push(`/assets/hosts/detail?id=${encodeURIComponent(r.host_id)}`)}
            selectable
            selectedKeys={selected}
            onToggleRow={(key) => toggleRow(key)}
            onToggleAll={toggleAll}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams({ page })}
          />
        </Card>
      </div>

      <ConfirmDialog
        open={restartOpen}
        title={t("assets.hosts.restartAgent")}
        desc={t("assets.hosts.restartConfirmDesc", { count: selected.size })}
        confirmText={t("assets.hosts.restartConfirmText")}
        danger={false}
        loading={restartMutation.isPending}
        onConfirm={() => restartMutation.mutate()}
        onCancel={() => setRestartOpen(false)}
      />
      <ConfirmDialog
        open={deleteOpen}
        title={t("assets.hosts.deleteTitle")}
        desc={t("assets.hosts.deleteConfirmDesc", { count: selected.size })}
        confirmText={t("common.delete")}
        danger
        loading={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate()}
        onCancel={() => setDeleteOpen(false)}
      />

      <Modal
        open={blOpen}
        onClose={() => setBlOpen(false)}
        title={t("assets.hosts.changeBusinessLine")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setBlOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => blMutation.mutate()} disabled={!blValue || blMutation.isPending}>
              {blMutation.isPending ? t("common.processing") : t("common.confirm")}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-muted">{t("assets.hosts.blModalTip", { count: selected.size })}</p>
          <Select
            value={blValue}
            onChange={setBlValue}
            placeholder={t("assets.hosts.blSelectPlaceholder")}
            className="w-full"
            options={(blList?.items ?? []).map((b) => ({ label: b.name, value: b.code }))}
          />
        </div>
      </Modal>

      <Modal
        open={tagsOpen}
        onClose={() => setTagsOpen(false)}
        title={t("assets.hosts.addTags")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setTagsOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => tagsMutation.mutate()} disabled={!tagsValue.trim() || tagsMutation.isPending}>
              {tagsMutation.isPending ? t("common.processing") : t("common.confirm")}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-muted">{t("assets.hosts.tagsModalTip", { count: selected.size })}</p>
          <Input
            value={tagsValue}
            onChange={(e) => setTagsValue(e.target.value)}
            placeholder={t("assets.hosts.tagsPlaceholder")}
          />
        </div>
      </Modal>
    </>
  );
}
