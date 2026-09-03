"use client";
import { useEffect } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils/cn";

interface Props {
  page: number;
  pageSize: number;
  total: number;
  onChange: (page: number) => void;
}

const btn = "inline-flex h-8 w-8 items-center justify-center rounded-control border border-border text-muted transition-colors hover:bg-bg disabled:opacity-40";

export function Pagination({ page, pageSize, total, onChange }: Props) {
  const { t } = useTranslation();
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  // 数据变少导致当前页越界时（如 page=2 但只剩 1 页）自动回弹到末页，避免渲染空列表
  useEffect(() => {
    if (total > 0 && page > totalPages) {
      onChange(totalPages);
    }
  }, [page, totalPages, total, onChange]);
  return (
    <div className="flex items-center justify-end gap-3 px-4 py-3 text-sm">
      <span className="text-muted">{t("common.totalItems", { count: total })}</span>
      <button type="button" className={cn(btn)} disabled={page <= 1} onClick={() => onChange(page - 1)} aria-label={t("common.prevPage")}>
        <ChevronLeft size={16} />
      </button>
      <span className="text-muted tabular-nums">
        {t("common.pageOf", { page, pages: totalPages })}
      </span>
      <button type="button" className={cn(btn)} disabled={page >= totalPages} onClick={() => onChange(page + 1)} aria-label={t("common.nextPage")}>
        <ChevronRight size={16} />
      </button>
    </div>
  );
}
