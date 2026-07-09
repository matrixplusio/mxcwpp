"use client";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils/cn";
import type { Severity } from "@/lib/api/types";

const sevMap: Record<Severity, string> = {
  critical: "bg-danger/10 text-danger",
  high: "bg-warning/10 text-warning",
  medium: "bg-primary/10 text-primary",
  low: "bg-muted/10 text-muted",
};

export function SeverityTag({ level }: { level: Severity }) {
  const { t } = useTranslation();
  return <span className={cn("inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium", sevMap[level])}>{t(`common.severity.${level}`)}</span>;
}

type StatusTone = "success" | "warning" | "danger" | "info" | "neutral";
const toneMap: Record<StatusTone, string> = {
  success: "bg-success/10 text-success",
  warning: "bg-warning/10 text-warning",
  danger: "bg-danger/10 text-danger",
  info: "bg-info/10 text-info",
  neutral: "bg-muted/10 text-muted",
};
export function StatusTag({ tone, children }: { tone: StatusTone; children: React.ReactNode }) {
  return <span className={cn("inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium", toneMap[tone])}>{children}</span>;
}
