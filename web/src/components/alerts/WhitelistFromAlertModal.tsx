"use client";
import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { whitelistApi } from "@/lib/api/alerts";
import type { Alert } from "@/lib/api/types";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { FormField } from "@/components/ui/FormField";
import { Input, Textarea } from "@/components/ui/Input";
import { toast } from "@/components/ui/toast";

/** 从告警命中字段（actual 为 JSON）里取一个字符串值。 */
export function alertField(actual: string | undefined, key: string): string {
  if (!actual) return "";
  try {
    const o = JSON.parse(actual);
    return o[key] != null ? String(o[key]) : "";
  } catch {
    return "";
  }
}


interface Props {
  alert: Alert | null;
  onClose: () => void;
  onDone: () => void;
}

/**
 * 把一条告警的命中条件转成白名单（抑制规则）。
 * 预填规则、主机与进程，命令行留给操作者按需收窄；
 * critical 告警至少要保留进程 / 命令行 / 来源网段之一，否则后端会拒绝。
 */
export function WhitelistFromAlertModal({ alert, onClose, onDone }: Props) {
  const { t } = useTranslation();
  const [exe, setExe] = useState("");
  const [cmdline, setCmdline] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("30");

  useEffect(() => {
    if (!alert) return;
    const e = alertField(alert.actual, "exe") || alertField(alert.actual, "comm");
    setExe(e);
    setCmdline("");
    setSourceIp("");
    setReason("");
    setDays("30");
  }, [alert]);

  const mutation = useMutation({
    mutationFn: () => {
      if (!alert) throw new Error("no alert");
      return whitelistApi.create({
        name: `${alert.rule_id}-${(alert.host?.hostname || alert.host_id).slice(0, 24)}`,
        rule_id: alert.rule_id,
        host_id: alert.host_id,
        exe: exe.trim() || undefined,
        cmdline: cmdline.trim() || undefined,
        source_ip_cidr: sourceIp.trim() || undefined,
        reason: reason.trim(),
        expires_in_days: Number(days) || undefined,
      });
    },
    onSuccess: () => {
      toast.success(t("alerts.suppress.created"));
      onDone();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const critical = alert?.severity === "critical";
  const hasEvidence = !!(exe.trim() || cmdline.trim() || sourceIp.trim());
  const canSubmit = reason.trim() !== "" && (!critical || hasEvidence) && !mutation.isPending;

  return (
    <Modal
      open={!!alert}
      onClose={onClose}
      title={t("alerts.suppress.title")}
      width={520}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button onClick={() => mutation.mutate()} disabled={!canSubmit}>
            {mutation.isPending ? t("common.saving") : t("common.save")}
          </Button>
        </>
      }
    >
      {alert && (
        <div className="space-y-4">
          <p className="text-sm text-muted">{t("alerts.suppress.desc")}</p>
          <div className="space-y-1 rounded-control bg-surface-muted p-3 text-sm">
            <div className="flex gap-3">
              <span className="w-16 shrink-0 text-muted">{t("alerts.whitelist.colRuleId")}</span>
              <span className="font-mono text-xs text-ink">{alert.rule_id}</span>
            </div>
            <div className="flex gap-3">
              <span className="w-16 shrink-0 text-muted">{t("alerts.whitelist.colHostId")}</span>
              <span className="font-mono text-xs text-ink">{alert.host?.hostname || alert.host_id}</span>
            </div>
          </div>
          <FormField label={t("alerts.whitelist.colExe")}>
            <Input value={exe} onChange={(e) => setExe(e.target.value)} placeholder={t("alerts.whitelist.exePlaceholder")} />
          </FormField>
          <FormField label={t("alerts.whitelist.colCmdline")}>
            <Input
              value={cmdline}
              onChange={(e) => setCmdline(e.target.value)}
              placeholder={t("alerts.whitelist.cmdlinePlaceholder")}
            />
          </FormField>
          <FormField label={t("alerts.whitelist.colSourceIpCidr")}>
            <Input
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              placeholder={t("alerts.whitelist.sourceIpPlaceholder")}
            />
          </FormField>
          {critical && (
            <p className={`text-xs ${hasEvidence ? "text-faint" : "text-danger"}`}>{t("alerts.whitelist.criticalHint")}</p>
          )}
          <FormField label={t("alerts.whitelist.expiresInDays")}>
            <Input type="number" min={1} max={90} value={days} onChange={(e) => setDays(e.target.value)} />
          </FormField>
          <FormField label={t("alerts.whitelist.colReason")} required>
            <Textarea value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("alerts.whitelist.reasonPlaceholder")} />
          </FormField>
        </div>
      )}
    </Modal>
  );
}
