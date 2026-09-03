"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/Button";
import type { IncidentEvent } from "@/lib/api/types";

interface Props {
  events: IncidentEvent[];
  disabled?: boolean;
  submitting?: boolean;
  onComment: (body: string, ref?: string) => void;
}

const typeTone: Record<IncidentEvent["type"], string> = {
  assigned: "bg-primary/10 text-primary",
  acked: "bg-primary/10 text-primary",
  comment: "bg-muted/10 text-muted",
  evidence: "bg-warning/10 text-warning",
  escalated: "bg-danger/10 text-danger",
  verdict: "bg-success/10 text-success",
  resolved: "bg-success/10 text-success",
};

/**
 * 事件处置时间线。
 *
 * 一条事件的调查过程是连续叙事：谁在什么时候、基于什么、做了什么决定。
 * 复盘唯一要看的就是这个，所以状态变更、研判备注与证据引用按时间正序排在一起，
 * 而不是分散在几处各看各的。
 */
export function IncidentTimeline({ events, disabled, submitting, onComment }: Props) {
  const { t } = useTranslation();
  const [body, setBody] = useState("");
  const [ref, setRef] = useState("");

  return (
    <div className="space-y-3">
      {events.length === 0 ? (
        <div className="text-sm text-muted">{t("alerts.incident.timelineEmpty")}</div>
      ) : (
        <ol className="space-y-2.5">
          {events.map((e) => (
            <li key={e.id} className="flex gap-2.5">
              <span
                className={`mt-0.5 h-fit shrink-0 rounded-control px-1.5 py-0.5 text-xs ${typeTone[e.type] ?? "bg-muted/10 text-muted"}`}
              >
                {t(`alerts.incident.event_${e.type}` as never, { defaultValue: e.type }) as string}
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-sm text-ink">{e.body}</div>
                <div className="text-xs text-faint">
                  {/* 直接渲染后端返回的本地时间串，与全站一致。*/}
                  {e.actor} · <span className="tabular-nums">{e.created_at}</span>
                  {e.ref && <span className="ml-1 font-mono">· {e.ref}</span>}
                </div>
              </div>
            </li>
          ))}
        </ol>
      )}

      {!disabled && (
        <div className="space-y-2 border-t border-line pt-3">
          <div className="text-sm font-medium text-ink">{t("alerts.incident.addComment")}</div>
          <textarea
            className="w-full rounded-control border border-line bg-surface p-2 text-sm text-ink outline-none focus:border-primary"
            rows={2}
            value={body}
            placeholder={t("alerts.incident.commentPlaceholder")}
            onChange={(ev) => setBody(ev.target.value)}
          />
          <input
            className="w-full rounded-control border border-line bg-surface p-2 text-sm text-ink outline-none focus:border-primary"
            value={ref}
            placeholder={t("alerts.incident.commentRefPlaceholder")}
            onChange={(ev) => setRef(ev.target.value)}
          />
          <div className="flex justify-end">
            <Button
              disabled={body.trim() === "" || submitting}
              onClick={() => {
                onComment(body.trim(), ref.trim() || undefined);
                setBody("");
                setRef("");
              }}
            >
              {t("alerts.incident.submitComment")}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
