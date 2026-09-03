"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { baselineApi } from "@/lib/api/baseline";
import type { BaselineFixItem } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  severities: string;
}

const buildSeverityOptions = (t: TFunction) => [
  { label: t("common.allSeverity"), value: "" },
  { label: t("common.severity.critical"), value: "critical" },
  { label: t("common.severity.high"), value: "high" },
  { label: t("common.severity.medium"), value: "medium" },
  { label: t("common.severity.low"), value: "low" },
];

// 复合主键：task_id + host_id + rule_id
function rowKeyOf(r: BaselineFixItem): string {
  return `${r.task_id}|${r.host_id}|${r.rule_id}`;
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="text-ink">{value}</span>
    </div>
  );
}

export default function BaselineFixPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const severityOptions = buildSeverityOptions(t);
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, severities: "" });

  const { data, isLoading } = useQuery({
    queryKey: ["bl-fixable", params],
    queryFn: () =>
      baselineApi.listFixItems({
        page: params.page,
        page_size: params.page_size,
        severities: params.severities ? [params.severities] : undefined,
      }),
  });

  const rows = data?.items ?? [];

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [detail, setDetail] = useState<BaselineFixItem | null>(null);
  const [confirming, setConfirming] = useState(false);

  const selectableRows = rows.filter((r) => r.has_fix);
  const allSelected = selectableRows.length > 0 && selectableRows.every((r) => selected.has(rowKeyOf(r)));

  const toggleRow = (r: BaselineFixItem) => {
    if (!r.has_fix) return;
    const key = rowKeyOf(r);
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const toggleAll = () => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (allSelected) {
        selectableRows.forEach((r) => next.delete(rowKeyOf(r)));
      } else {
        selectableRows.forEach((r) => next.add(rowKeyOf(r)));
      }
      return next;
    });
  };

  const createMutation = useMutation({
    mutationFn: () => {
      const result_keys = rows
        .filter((r) => selected.has(rowKeyOf(r)))
        .map((r) => ({ task_id: r.task_id, host_id: r.host_id, rule_id: r.rule_id }));
      return baselineApi.createFixTask({ result_keys });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bl-fixable"] });
      setSelected(new Set());
      setConfirming(false);
      toast.success(t("baseline.fix.dispatched"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<BaselineFixItem>[] = [
    {
      key: "select",
      title: t("common.selectRow"),
      render: (r) => (
        <input
          type="checkbox"
          className="h-4 w-4 cursor-pointer accent-primary disabled:cursor-not-allowed disabled:opacity-40"
          checked={selected.has(rowKeyOf(r))}
          disabled={!r.has_fix}
          onChange={() => toggleRow(r)}
          onClick={(e) => e.stopPropagation()}
          aria-label={t("common.selectRow")}
        />
      ),
    },
    {
      key: "hostname",
      title: t("common.host"),
      render: (r) => (
        <div className="leading-tight">
          <div className="font-medium text-ink">{r.hostname || r.host_id}</div>
          <div className="text-xs text-faint tabular-nums">{r.ip}</div>
        </div>
      ),
    },
    { key: "title", title: t("baseline.fix.colCheckItem"), render: (r) => <span className="font-medium text-ink">{r.title}</span> },
    { key: "category", title: t("common.category"), render: (r) => <StatusTag tone="neutral">{r.category || "—"}</StatusTag> },
    { key: "severity", title: t("common.level"), render: (r) => <SeverityTag level={r.severity} /> },
    {
      key: "has_fix",
      title: t("baseline.fix.colFixPlan"),
      render: (r) => <StatusTag tone={r.has_fix ? "success" : "neutral"}>{r.has_fix ? t("baseline.fix.fixable") : t("baseline.fix.noFix")}</StatusTag>,
    },
  ];

  const selectedCount = selected.size;

  return (
    <>
      <div className="space-y-4">
        <FilterBar
          extra={
            <div className="flex items-center gap-3">
              <label className="flex cursor-pointer items-center gap-2 text-sm text-muted">
                <input
                  type="checkbox"
                  className="h-4 w-4 cursor-pointer accent-primary disabled:cursor-not-allowed disabled:opacity-40"
                  checked={allSelected}
                  disabled={selectableRows.length === 0}
                  onChange={toggleAll}
                />
                {t("baseline.fix.selectAll")}
              </label>
              {selectedCount > 0 && (
                <Button onClick={() => setConfirming(true)}>{t("baseline.fix.createFixTask", { count: selectedCount })}</Button>
              )}
            </div>
          }
        >
          <Select
            value={params.severities}
            onChange={(v) => setParams((p) => ({ ...p, severities: v, page: 1 }))}
            options={severityOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={rows}
            rowKey={(r) => rowKeyOf(r)}
            loading={isLoading}
            emptyText={t("baseline.fix.empty")}
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

      <Drawer open={!!detail} onClose={() => setDetail(null)} title={t("baseline.fix.detailTitle")} width={560}>
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold text-ink">{detail.title}</h2>
              <div className="flex items-center gap-2">
                <SeverityTag level={detail.severity} />
                <StatusTag tone={detail.has_fix ? "success" : "neutral"}>
                  {detail.has_fix ? t("baseline.fix.fixable") : t("baseline.fix.noFix")}
                </StatusTag>
              </div>
            </div>

            <div className="space-y-2">
              <Field label={t("common.host")} value={detail.hostname || detail.host_id} />
              <Field label="IP" value={<span className="tabular-nums">{detail.ip}</span>} />
              <Field label={t("common.category")} value={detail.category || "—"} />
              <Field label={t("baseline.fix.fieldRule")} value={<span className="font-mono text-xs">{detail.rule_id}</span>} />
            </div>

            {detail.actual && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("baseline.fix.fieldActual")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                  {detail.actual}
                </pre>
              </div>
            )}
            {detail.expected && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("baseline.fix.fieldExpected")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                  {detail.expected}
                </pre>
              </div>
            )}
            {detail.fix_suggestion && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("baseline.fix.fieldFixSuggestion")}</div>
                <div className="rounded-r-control border-l-4 border-primary bg-primary/5 p-3 text-sm leading-relaxed text-ink">
                  {detail.fix_suggestion}
                </div>
              </div>
            )}
            {detail.fix_command && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("baseline.fix.fieldFixCommand")}</div>
                <pre className="overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                  {detail.fix_command}
                </pre>
              </div>
            )}
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={confirming}
        danger
        title={t("baseline.fix.createTitle")}
        desc={t("baseline.fix.createConfirmDesc", { count: selectedCount })}
        confirmText={t("baseline.fix.createConfirm")}
        loading={createMutation.isPending}
        onConfirm={() => createMutation.mutate()}
        onCancel={() => setConfirming(false)}
      />
    </>
  );
}
