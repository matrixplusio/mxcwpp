"use client";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils/cn";

export interface DateRange {
  start: string;
  end: string;
}

interface Props {
  value: DateRange;
  onChange: (v: DateRange) => void;
  presets?: boolean;
  className?: string;
}

const inputBase =
  "h-10 rounded-control border border-border bg-surface px-3 text-sm text-ink outline-none transition-colors focus:border-primary focus:ring-4 focus:ring-primary/10";

const presetBtn =
  "h-8 rounded-control border border-border bg-surface px-3 text-sm text-muted transition-colors hover:bg-bg hover:text-ink";

function toLocalDateStr(d: Date): string {
  return [
    d.getFullYear(),
    String(d.getMonth() + 1).padStart(2, "0"),
    String(d.getDate()).padStart(2, "0"),
  ].join("-");
}

export function lastNDays(n: number): DateRange {
  const end = new Date();
  const start = new Date();
  start.setDate(end.getDate() - (n - 1));
  return {
    start: toLocalDateStr(start),
    end: toLocalDateStr(end),
  };
}

export function RangePicker({ value, onChange, presets = true, className }: Props) {
  const { t } = useTranslation();

  const presetList = [
    { label: t("common.last7Days"), days: 7 },
    { label: t("common.last30Days"), days: 30 },
    { label: t("common.last90Days"), days: 90 },
  ];

  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)}>
      {presets &&
        presetList.map(({ label, days }) => (
          <button
            key={days}
            type="button"
            className={presetBtn}
            onClick={() => onChange(lastNDays(days))}
          >
            {label}
          </button>
        ))}
      <input
        type="date"
        aria-label={t("common.startDate")}
        value={value.start}
        max={value.end || undefined}
        onChange={(e) => onChange({ ...value, start: e.target.value })}
        className={inputBase}
      />
      <span className="text-sm text-muted">–</span>
      <input
        type="date"
        aria-label={t("common.endDate")}
        value={value.end}
        min={value.start || undefined}
        onChange={(e) => onChange({ ...value, end: e.target.value })}
        className={inputBase}
      />
    </div>
  );
}
