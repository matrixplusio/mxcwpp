"use client";
import { Inbox } from "lucide-react";
import { useTranslation } from "react-i18next";

export function EmptyState({ title, desc }: { title?: string; desc?: string }) {
  const { t } = useTranslation();
  const resolvedTitle = title ?? t("common.empty.building");
  const resolvedDesc = desc ?? t("common.empty.buildingDesc");
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <Inbox className="text-muted" size={40} />
      <h3 className="mt-4 text-base font-semibold text-ink">{resolvedTitle}</h3>
      {resolvedDesc && <p className="mt-1 text-sm text-muted">{resolvedDesc}</p>}
    </div>
  );
}
