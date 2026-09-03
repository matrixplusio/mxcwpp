"use client";
import React from "react";
import { useTranslation } from "react-i18next";
import { ArrowLeft, Download } from "lucide-react";
import { cn } from "@/lib/utils/cn";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";

export interface ExecutiveReportProps {
  meta: {
    title: string;
    subtitleEn?: string;
    infoRows: { label: string; value: string }[];
    company?: string;
  };
  banner?: { tone: "success" | "warning" | "danger" | "info"; text: string };
  sections: { title: string; content: React.ReactNode }[];
  recommendation?: { assessment: string; suggestions: string[]; disclaimer?: string };
  onBack: () => void;
  onExportPdf?: () => void;
  exporting?: boolean;
}

const bannerTones: Record<"success" | "warning" | "danger" | "info", string> = {
  success: "bg-success/10 border border-success/20 text-success",
  warning: "bg-warning/10 border border-warning/20 text-warning",
  danger: "bg-danger/10 border border-danger/20 text-danger",
  info: "bg-info/10 border border-info/20 text-info",
};

export function ExecutiveReport({
  meta,
  banner,
  sections,
  recommendation,
  onBack,
  onExportPdf,
  exporting,
}: ExecutiveReportProps) {
  const { t } = useTranslation();
  const nonEmptySections = sections.filter((s) => Boolean(s.content));

  return (
    <div className="space-y-5">
      {/* Top bar */}
      <div className="flex items-center gap-3">
        <Button variant="ghost" onClick={onBack}>
          <ArrowLeft size={16} />
          {t("operations.taskReport.execReport.back")}
        </Button>
        {onExportPdf && (
          <Button
            variant="primary"
            onClick={onExportPdf}
            disabled={exporting}
            className="ml-auto"
          >
            <Download size={16} />
            {exporting
              ? t("operations.taskReport.execReport.exporting")
              : t("operations.taskReport.execReport.exportPdf")}
          </Button>
        )}
      </div>

      {/* Cover card */}
      <Card className="p-6">
        <div className="mb-4">
          <h1 className="text-2xl font-bold text-ink">{meta.title}</h1>
          {meta.subtitleEn && (
            <p className="mt-1 text-sm text-muted">{meta.subtitleEn}</p>
          )}
        </div>
        <div className="grid grid-cols-2 gap-x-6 gap-y-3 md:grid-cols-3 lg:grid-cols-4">
          {meta.infoRows.map((row) => (
            <div key={row.label} className="flex flex-col gap-0.5">
              <span className="text-xs uppercase tracking-wide text-faint">
                {row.label}
              </span>
              <span className="text-sm text-ink">{row.value}</span>
            </div>
          ))}
        </div>
        {meta.company && (
          <p className="mt-4 border-t border-border pt-3 text-xs text-faint">
            {meta.company}
          </p>
        )}
      </Card>

      {/* Colored conclusion banner */}
      {banner && (
        <div
          className={cn(
            "rounded-card px-5 py-3 text-sm font-medium",
            bannerTones[banner.tone],
          )}
        >
          {banner.text}
        </div>
      )}

      {/* Auto-numbered sections (skip entries with falsy content) */}
      {nonEmptySections.map((sec, idx) => (
        <Card key={`${idx + 1}-${sec.title}`}>
          <CardHeader title={`${idx + 1}. ${sec.title}`} />
          <div className="px-5 pb-5">{sec.content}</div>
        </Card>
      ))}

      {/* Recommendation card */}
      {recommendation && (
        <Card>
          <CardHeader
            title={t("operations.taskReport.execReport.recommendation")}
          />
          <div className="space-y-4 px-5 pb-5">
            <p className="text-sm leading-relaxed text-ink">
              {recommendation.assessment}
            </p>
            {recommendation.suggestions.length > 0 && (
              <div>
                <p className="mb-2 text-xs uppercase tracking-wide text-faint">
                  {t("operations.taskReport.execReport.suggestions")}
                </p>
                <ol className="list-decimal space-y-1 pl-5 text-sm text-ink">
                  {recommendation.suggestions.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ol>
              </div>
            )}
            {recommendation.disclaimer && (
              <p className="text-xs text-faint">{recommendation.disclaimer}</p>
            )}
          </div>
        </Card>
      )}

      {/* Appendix disclaimer footer */}
      <p className="pb-4 text-center text-xs text-faint">
        {t("operations.taskReport.execReport.appendixText")}
      </p>
    </div>
  );
}
