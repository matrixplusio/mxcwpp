"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { detectionApi } from "@/lib/api/detection";
import type { HuntingQuery, HuntingResult } from "@/lib/api/types";
import { Card, CardHeader } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { Textarea } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { SeverityTag, StatusTag } from "@/components/ui/Tag";
import { EmptyState } from "@/components/ui/EmptyState";
import { toast } from "@/components/ui/toast";

type ResultRow = unknown[] | Record<string, unknown>;

// MQL 示例查询(点击填入编辑器)。均符合引擎语法,可直接运行。
const HUNT_EXAMPLES: Array<{ label: string; q: string }> = [
  { label: "进程执行", q: `search events | where event_type == "process_exec" | limit 50` },
  { label: "可疑下载", q: `search events | where exe contains "curl" || exe contains "wget" | limit 50` },
  { label: "外网外联TopIP", q: `search events | where event_type == "tcp_connect" | where is_private_ip(remote_addr) == false | stats count() by remote_addr | sort count desc | limit 20` },
  { label: "临时目录执行", q: `search events | where event_type == "process_exec" | where exe startswith "/tmp/" || exe startswith "/dev/shm/" | limit 50` },
  { label: "近24h按主机统计", q: `search events | where timestamp > now()-24h | stats count() by host_id | sort count desc` },
];

function cellValue(row: ResultRow, col: string, idx: number): string {
  const cell = Array.isArray(row) ? row[idx] : (row as Record<string, unknown>)[col];
  if (cell === null || cell === undefined) return "—";
  return String(cell);
}

export default function HuntingPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [mql, setMql] = useState("");
  const [result, setResult] = useState<HuntingResult | null>(null);
  const [page, setPage] = useState(1);
  const pageSize = 20;
  const [deleting, setDeleting] = useState<HuntingQuery | null>(null);

  const { data: queries, isLoading } = useQuery({
    queryKey: ["hunting-queries", page],
    queryFn: () => detectionApi.listHuntQueries({ page, page_size: pageSize }),
  });

  const executeMutation = useMutation({
    mutationFn: () => detectionApi.executeHunt(mql.trim()),
    onSuccess: (res) => setResult(res),
    onError: (e: Error) => toast.error(e.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => detectionApi.deleteHuntQuery(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hunting-queries"] });
      setDeleting(null);
      toast.success(t("common.deleted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const resultColumns: Column<ResultRow>[] = (result?.columns ?? []).map((col, idx) => ({
    key: `${col}-${idx}`,
    title: col,
    render: (row) => <span className="break-all font-mono text-xs text-ink">{cellValue(row, col, idx)}</span>,
  }));
  const resultRows: ResultRow[] = (result?.rows ?? []) as ResultRow[];

  const queryColumns: Column<HuntingQuery>[] = [
    { key: "name", title: t("detection.hunting.colName"), render: (r) => <span className="font-medium text-ink">{r.name}</span> },
    { key: "category", title: t("detection.hunting.colCategory"), render: (r) => <span className="text-muted">{r.category || "—"}</span> },
    { key: "severity", title: t("common.level"), render: (r) => <SeverityTag level={r.severity} /> },
    { key: "owner", title: t("detection.hunting.colOwner"), render: (r) => <span className="text-muted">{r.owner || "—"}</span> },
    {
      key: "is_builtin",
      title: t("detection.hunting.colSource"),
      render: (r) => <StatusTag tone={r.is_builtin ? "info" : "neutral"}>{r.is_builtin ? t("detection.hunting.sourceBuiltin") : t("detection.hunting.sourceCustom")}</StatusTag>,
    },
    { key: "last_hits", title: t("detection.hunting.colLastHits"), render: (r) => <span className="tabular-nums text-ink">{r.last_hits}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2">
          <button type="button" className="text-sm text-muted transition-colors hover:text-ink" onClick={() => setMql(r.mql)}>
            {t("detection.hunting.loadToEditor")}
          </button>
          {!r.is_builtin && (
            <button type="button" className="text-sm text-danger transition-colors hover:opacity-80" onClick={() => setDeleting(r)}>
              {t("common.delete")}
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="space-y-5">
        <Card>
          <CardHeader title={t("detection.hunting.mqlTitle")} />
          <div className="space-y-3 px-5 pb-5">
            <Textarea
              value={mql}
              onChange={(e) => setMql(e.target.value)}
              placeholder={t("detection.hunting.mqlPlaceholder")}
              className="min-h-32 font-mono"
            />
            <div className="flex justify-end">
              <Button onClick={() => executeMutation.mutate()} disabled={!mql.trim() || executeMutation.isPending}>
                {executeMutation.isPending ? t("detection.hunting.executing") : t("detection.hunting.execute")}
              </Button>
            </div>

            {/* 语法说明 + 示例(点击填入),解决"不知道怎么查" */}
            <div className="rounded-md border border-line bg-surface-muted p-3 text-xs">
              <div className="mb-1 font-medium text-ink">{t("detection.hunting.syntaxTitle")}</div>
              <p className="mb-2 text-muted">
                <code className="font-mono">search events | where &lt;条件&gt; | stats count() by &lt;字段&gt; | sort &lt;字段&gt; desc | limit N</code>
              </p>
              <p className="mb-2 text-faint">
                {t("detection.hunting.syntaxFields")}: event_type, exe, cmdline, parent_exe, file_path, remote_addr, remote_port, dns_server, pid, uid, host_id, timestamp ·
                操作符 == != contains startswith endswith matches in · 函数 is_private_ip() is_dns_tunnel() · 时间 now()-24h
              </p>
              <div className="space-y-1">
                {HUNT_EXAMPLES.map((ex) => (
                  <button
                    key={ex.q}
                    type="button"
                    className="block w-full truncate text-left font-mono text-faint transition-colors hover:text-primary"
                    title={ex.q}
                    onClick={() => setMql(ex.q)}
                  >
                    <span className="text-muted">{ex.label}:</span> {ex.q}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </Card>

        {result && (
          <Card>
            <CardHeader title={t("detection.hunting.resultTitle")} />
            <DataTable columns={resultColumns} rows={resultRows} rowKey={(r) => JSON.stringify(r)} emptyText={t("detection.hunting.resultEmpty")} />
            <div className="flex justify-end gap-4 border-t border-border px-4 py-2.5 text-xs text-faint">
              <span>
                {t("detection.hunting.rowsPrefix")} <span className="tabular-nums text-muted">{result.total_rows}</span> {t("detection.hunting.rowsSuffix")}
              </span>
              <span>
                {t("detection.hunting.elapsedPrefix")} <span className="tabular-nums text-muted">{result.elapsed_ms}</span> {t("detection.hunting.elapsedSuffix")}
              </span>
            </div>
          </Card>
        )}

        <Card>
          <CardHeader title={t("detection.hunting.savedTitle")} />
          {isLoading ? (
            <div className="px-5 py-10 text-center text-muted">{t("common.loading")}</div>
          ) : (queries?.items ?? []).length === 0 ? (
            <div className="px-5 pb-5">
              <EmptyState title={t("detection.hunting.empty")} desc="" />
            </div>
          ) : (
            <>
              <DataTable columns={queryColumns} rows={queries?.items ?? []} rowKey={(r) => r.id} emptyText={t("detection.hunting.empty")} />
              <Pagination page={page} pageSize={pageSize} total={queries?.total ?? 0} onChange={setPage} />
            </>
          )}
        </Card>
      </div>

      <ConfirmDialog
        open={!!deleting}
        title={t("detection.hunting.deleteTitle")}
        desc={deleting ? t("detection.hunting.deleteConfirmDesc", { name: deleting.name }) : undefined}
        loading={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}
