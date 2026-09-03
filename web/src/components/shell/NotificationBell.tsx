"use client";
import { useEffect, useRef, useState } from "react";
import { Bell } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { alertsApi } from "@/lib/api/alerts";
import { SeverityTag } from "@/components/ui/Tag";

const READ_KEY = "notif_read_baseline";

export function NotificationBell() {
  const { t } = useTranslation();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const [readBaseline, setReadBaseline] = useState(0);

  useEffect(() => {
    const v = Number(localStorage.getItem(READ_KEY) ?? "0");
    setReadBaseline(Number.isFinite(v) ? v : 0);
  }, []);

  const { data: stats } = useQuery({
    queryKey: ["alerts-stats"],
    queryFn: () => alertsApi.statistics(),
    refetchInterval: 60000,
  });
  const { data: recent } = useQuery({
    queryKey: ["alerts", { page: 1, page_size: 6, status: "active" }],
    queryFn: () => alertsApi.list({ page: 1, page_size: 6, status: "active" }),
    enabled: open,
  });

  const active = stats?.active ?? 0;
  const unread = Math.max(0, active - readBaseline);
  const items = recent?.items ?? [];

  const markAllRead = () => {
    setReadBaseline(active);
    localStorage.setItem(READ_KEY, String(active));
  };

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const go = (path: string) => { setOpen(false); router.push(path); };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex h-9 w-9 items-center justify-center rounded-control text-muted transition-colors hover:bg-bg hover:text-ink"
        title={t("header.notifications")}
      >
        <Bell size={18} />
        {unread > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[10px] font-semibold text-white ring-2 ring-surface">
            {unread > 99 ? "99+" : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-11 z-50 w-80 overflow-hidden rounded-card border border-border bg-surface shadow-float">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div className="flex items-baseline gap-2">
              <span className="text-sm font-semibold text-ink">{t("header.pendingAlerts")}</span>
              <span className="text-xs text-muted">{t("header.items", { n: active })}</span>
            </div>
            {unread > 0 && (
              <button onClick={markAllRead} className="text-xs font-medium text-primary hover:underline">
                {t("header.markAllRead")}
              </button>
            )}
          </div>
          <div className="max-h-80 overflow-y-auto">
            {items.length === 0 ? (
              <div className="px-4 py-10 text-center text-sm text-muted">{t("header.noPendingAlerts")}</div>
            ) : (
              items.map((a) => (
                <button
                  key={a.id}
                  onClick={() => go("/alert-center/alerts")}
                  className="flex w-full flex-col gap-1 border-b border-border px-4 py-2.5 text-left transition-colors last:border-0 hover:bg-bg"
                >
                  <div className="flex items-center gap-2">
                    <SeverityTag level={a.severity} />
                    <span className="min-w-0 flex-1 truncate text-sm font-medium text-ink">{a.title}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs text-faint">
                    <span className="truncate">{a.host?.hostname ?? a.host_id}</span>
                    <span className="shrink-0 tabular-nums">{a.last_seen_at}</span>
                  </div>
                </button>
              ))
            )}
          </div>
          <button
            onClick={() => go("/alert-center/alerts")}
            className="w-full border-t border-border py-2.5 text-center text-sm font-medium text-primary transition-colors hover:bg-bg"
          >
            {t("header.viewAllAlerts")}
          </button>
        </div>
      )}
    </div>
  );
}
