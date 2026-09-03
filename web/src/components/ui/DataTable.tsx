"use client";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils/cn";
import { EmptyState } from "./EmptyState";

export interface Column<T> {
  key: string;
  title: string;
  align?: "left" | "right" | "center";
  width?: string;
  render?: (row: T) => React.ReactNode;
}

interface Props<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string | number;
  loading?: boolean;
  emptyText?: string;
  onRowClick?: (row: T) => void;
  selectable?: boolean;
  selectedKeys?: Set<string | number>;
  onToggleRow?: (key: string | number, row: T) => void;
  onToggleAll?: (checked: boolean) => void;
}

const alignCls = {
  left: "text-left",
  right: "text-right",
  center: "text-center",
} as const;

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  emptyText,
  onRowClick,
  selectable,
  selectedKeys,
  onToggleRow,
  onToggleAll,
}: Props<T>) {
  const { t } = useTranslation();
  const safeRows = Array.isArray(rows) ? rows : [];
  const colCount = columns.length + (selectable ? 1 : 0);
  const allSelected =
    safeRows.length > 0 && selectedKeys != null && safeRows.every((r) => selectedKeys.has(rowKey(r)));

  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="bg-surface-muted/60 text-[12px] uppercase tracking-wide text-faint">
          {selectable && (
            <th style={{ width: 40 }} className="px-4 py-2.5 text-center">
              <input
                type="checkbox"
                className="h-4 w-4 accent-primary"
                checked={allSelected}
                onChange={() => onToggleAll?.(!allSelected)}
                aria-label={t("common.selectAll")}
              />
            </th>
          )}
          {columns.map((col) => (
            <th
              key={col.key}
              style={col.width ? { width: col.width } : undefined}
              className={cn("px-4 py-2.5 font-semibold", alignCls[col.align ?? "left"])}
            >
              {col.title}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {loading ? (
          <tr>
            <td colSpan={colCount} className="px-4 py-10 text-center text-muted">
              {t("common.loading")}
            </td>
          </tr>
        ) : safeRows.length === 0 ? (
          <tr>
            <td colSpan={colCount}>
              <EmptyState title={emptyText ?? t("common.noData")} desc="" />
            </td>
          </tr>
        ) : (
          safeRows.map((row, i) => {
            const key = rowKey(row);
            return (
              <tr
                key={`${key}-${i}`}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={cn(
                  "border-t border-border transition-colors hover:bg-bg",
                  onRowClick && "cursor-pointer",
                )}
              >
                {selectable && (
                  <td className="px-4 py-3 text-center" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-primary"
                      checked={selectedKeys?.has(key) ?? false}
                      onChange={() => onToggleRow?.(key, row)}
                      aria-label={t("common.selectRow")}
                    />
                  </td>
                )}
                {columns.map((col) => (
                  <td key={col.key} className={cn("px-4 py-3", alignCls[col.align ?? "left"])}>
                    {col.render ? col.render(row) : ((row as Record<string, React.ReactNode>)[col.key])}
                  </td>
                ))}
              </tr>
            );
          })
        )}
      </tbody>
    </table>
  );
}
