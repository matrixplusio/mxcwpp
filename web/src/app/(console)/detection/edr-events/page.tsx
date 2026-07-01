"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Activity, Cpu, FileText, Network } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { detectionApi } from "@/lib/api/detection";
import type { EdrEvent } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { Input } from "@/components/ui/Input";
import { Drawer } from "@/components/ui/Drawer";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag } from "@/components/ui/Tag";
import { CopyButton } from "@/components/ui/CopyButton";

interface ListParams {
  page: number;
  page_size: number;
  keyword: string;
  data_type: string;
  host_id: string;
  exe: string;
  event_type: string;
}

const EVENT_TYPE_OPTIONS = [
  "", "process_exec", "process_exit", "file_open", "file_write", "file_rename", "file_unlink", "file_chmod",
  "tcp_connect", "tcp_accept", "udp_send", "dns_query", "memfd_exec", "anonymous_exec",
];

const buildDataTypeLabel = (t: TFunction): Record<number, string> => ({
  3000: t("detection.edrEvents.typeProcess"),
  3001: t("detection.edrEvents.typeFile"),
  3002: t("detection.edrEvents.typeNetwork"),
  3003: t("detection.edrEvents.typeOther"),
});

const buildDataTypeOptions = (t: TFunction) => [
  { label: t("common.allType"), value: "" },
  { label: t("detection.edrEvents.optProcess"), value: "3000" },
  { label: t("detection.edrEvents.optFile"), value: "3001" },
  { label: t("detection.edrEvents.optNetwork"), value: "3002" },
  { label: t("detection.edrEvents.optOther"), value: "3003" },
];

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

export default function EdrEventsPage() {
  const { t } = useTranslation();
  const DATA_TYPE_LABEL = buildDataTypeLabel(t);
  const dataTypeOptions = buildDataTypeOptions(t);
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    keyword: "",
    data_type: "",
    host_id: "",
    exe: "",
    event_type: "",
  });
  const eventTypeOptions = EVENT_TYPE_OPTIONS.map((v) => ({
    label: v === "" ? t("common.allType") : v,
    value: v,
  }));

  const { data: stats } = useQuery({
    queryKey: ["edr-stats"],
    queryFn: () => detectionApi.edrEventStats(),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["edr-events", params],
    queryFn: () =>
      detectionApi.listEdrEvents({
        page: params.page,
        page_size: params.page_size,
        keyword: params.keyword || undefined,
        data_type: params.data_type ? Number(params.data_type) : undefined,
        host_id: params.host_id || undefined,
        exe: params.exe || undefined,
        event_type: params.event_type || undefined,
      }),
  });

  const [detail, setDetail] = useState<EdrEvent | null>(null);
  // 列表是 lite(缺 parent_exe/uid/FIM 上下文),点开后按 host_id+timestamp+pid 拉完整详情
  const { data: fullDetail } = useQuery({
    queryKey: ["edr-event-detail", detail?.host_id, detail?.timestamp, detail?.pid],
    queryFn: () =>
      detectionApi.edrEventDetail({
        host_id: detail!.host_id,
        timestamp: detail!.timestamp,
        pid: detail!.pid || undefined,
        event_type: detail!.event_type || undefined,
        file_path: detail!.file_path || undefined,
      }),
    enabled: !!detail,
  });
  const d = fullDetail ?? detail;

  const columns: Column<EdrEvent>[] = [
    {
      key: "timestamp",
      title: t("detection.edrEvents.colTime"),
      render: (r) => <span className="text-faint tabular-nums">{r.timestamp}</span>,
    },
    {
      key: "hostname",
      title: t("detection.edrEvents.colHost"),
      render: (r) => (
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            className="font-medium text-ink transition-colors hover:text-primary"
            title={t("detection.edrEvents.filterByThisHost")}
            onClick={(e) => {
              e.stopPropagation();
              setParams((p) => ({ ...p, host_id: r.host_id, page: 1 }));
            }}
          >
            {r.hostname || r.host_id}
          </button>
          <CopyButton text={r.host_id} />
        </div>
      ),
    },
    { key: "event_type", title: t("detection.edrEvents.colEventType"), render: (r) => <StatusTag tone="neutral">{r.event_type}</StatusTag> },
    {
      key: "exe",
      title: t("detection.edrEvents.colExe"),
      render: (r) => <span className="block max-w-[240px] truncate font-mono text-xs text-ink">{dash(r.exe)}</span>,
    },
    {
      key: "file_path",
      title: t("detection.edrEvents.colFilePath"),
      render: (r) => <span className="block max-w-[240px] truncate font-mono text-xs text-ink">{dash(r.file_path)}</span>,
    },
    {
      key: "remote_addr",
      title: t("detection.edrEvents.colRemoteAddr"),
      render: (r) => <span className="font-mono text-xs text-ink">{dash(r.remote_addr)}</span>,
    },
  ];

  return (
    <>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 mb-5">
        <StatCard compact label={t("detection.edrEvents.statTotal")} value={(stats?.total ?? 0).toLocaleString()} icon={Activity} tone="default" />
        <StatCard compact label={t("detection.edrEvents.statProcessExec")} value={(stats?.process_exec ?? 0).toLocaleString()} icon={Cpu} tone="default" />
        <StatCard compact label={t("detection.edrEvents.statFileOp")} value={(stats?.file_open ?? 0).toLocaleString()} icon={FileText} tone="default" />
        <StatCard compact label={t("detection.edrEvents.statNetwork")} value={(stats?.network_connect ?? 0).toLocaleString()} icon={Network} tone="default" />
      </div>

      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={params.keyword}
            onChange={(v) => setParams((p) => ({ ...p, keyword: v, page: 1 }))}
            placeholder={t("detection.edrEvents.searchPlaceholder")}
          />
          <Input
            value={params.host_id}
            onChange={(e) => setParams((p) => ({ ...p, host_id: e.target.value, page: 1 }))}
            placeholder={t("detection.edrEvents.filterHostId")}
            className="w-56"
          />
          <Input
            value={params.exe}
            onChange={(e) => setParams((p) => ({ ...p, exe: e.target.value, page: 1 }))}
            placeholder={t("detection.edrEvents.filterExe")}
            className="w-44"
          />
          <Select
            value={params.event_type}
            onChange={(v) => setParams((p) => ({ ...p, event_type: v, page: 1 }))}
            options={eventTypeOptions}
          />
          <Select
            value={params.data_type}
            onChange={(v) => setParams((p) => ({ ...p, data_type: v, page: 1 }))}
            options={dataTypeOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => `${r.host_id}-${r.timestamp}-${r.pid}`}
            loading={isLoading}
            emptyText={t("detection.edrEvents.empty")}
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

      <Drawer open={!!detail} onClose={() => setDetail(null)} title={t("detection.edrEvents.detailTitle")} width={560}>
        {d && (
          <div className="space-y-5">
            <div className="space-y-2">
              <Field label={t("detection.edrEvents.fieldTime")} value={<span className="tabular-nums">{d.timestamp}</span>} />
              <Field label={t("detection.edrEvents.fieldHost")} value={d.hostname || d.host_id} />
              <Field label={t("detection.edrEvents.fieldHostId")} value={<span className="inline-flex items-center gap-1.5">{d.host_id}<CopyButton text={d.host_id} /></span>} mono />
              <Field label={t("detection.edrEvents.fieldEventType")} value={<StatusTag tone="neutral">{d.event_type}</StatusTag>} />
              <Field label={t("detection.edrEvents.fieldDataType")} value={`${d.data_type} ${DATA_TYPE_LABEL[d.data_type] ?? ""}`.trim()} />
              <Field label={t("detection.edrEvents.fieldPid")} value={dash(d.pid)} mono />
              <Field label={t("detection.edrEvents.fieldExe")} value={dash(d.exe)} mono />
              {d.cmdline && <Field label={t("detection.edrEvents.fieldCmdline")} value={d.cmdline} mono />}
              <Field label={t("detection.edrEvents.fieldFilePath")} value={dash(d.file_path)} mono />
              <Field label={t("detection.edrEvents.fieldRemoteAddr")} value={dash(d.remote_addr)} mono />
            </div>

            {/* FIM 上下文:谁改的 / 谁登录的 / 改了什么 —— 文件事件溯源 */}
            {(d.username || d.login_user || d.login_uid || d.parent_exe || d.content_hash) && (
              <div className="space-y-2">
                <div className="text-sm font-medium text-ink">{t("detection.edrEvents.sectionFimContext")}</div>
                <Field label={t("detection.edrEvents.fieldActor")} value={d.username ? `${d.username} (uid=${dash(d.uid)})` : dash(d.uid)} mono />
                <Field label={t("detection.edrEvents.fieldLoginUser")} value={d.login_user ? `${d.login_user} (loginuid=${d.login_uid})` : dash(d.login_uid)} mono />
                <Field label={t("detection.edrEvents.fieldParentExe")} value={dash(d.parent_exe)} mono />
                {d.content_hash && <Field label={t("detection.edrEvents.fieldContentHash")} value={<span className="inline-flex items-center gap-1.5 break-all">{d.content_hash}<CopyButton text={d.content_hash} /></span>} mono />}
                {d.file_size && <Field label={t("detection.edrEvents.fieldFileSize")} value={`${d.file_size} bytes`} mono />}
              </div>
            )}
          </div>
        )}
      </Drawer>
    </>
  );
}
