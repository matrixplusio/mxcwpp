"use client";
import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { alertsApi } from "@/lib/api/alerts";
import type { Alert, AlertVerdict } from "@/lib/api/types";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { FormField } from "@/components/ui/FormField";
import { Textarea } from "@/components/ui/Input";
import { toast } from "@/components/ui/toast";

export type CloseAction = "resolve" | "ignore";

const verdicts: AlertVerdict[] = ["true_positive", "false_positive", "benign_true_positive"];

interface Props {
  alert: Alert | null;
  action: CloseAction;
  /** 预选的结论，例如「标记误报」入口传 false_positive */
  defaultVerdict?: AlertVerdict;
  /** 覆盖默认标题与确认按钮文案（如「标记误报」入口） */
  title?: string;
  confirmText?: string;
  onClose: () => void;
  onDone: () => void;
}

/**
 * 关闭告警：研判结论与处置说明都必填。
 * 结论用于规则质量统计，说明用于事后审计——缺一个，这次处置就无从复核。
 */
export function CloseAlertModal({ alert, action, defaultVerdict, title, confirmText, onClose, onDone }: Props) {
  const { t } = useTranslation();
  const [verdict, setVerdict] = useState<AlertVerdict | "">("");
  const [reason, setReason] = useState("");

  useEffect(() => {
    if (alert) {
      setVerdict(defaultVerdict ?? "");
      setReason("");
    }
  }, [alert, defaultVerdict]);

  const mutation = useMutation({
    mutationFn: () => {
      if (!alert || !verdict) throw new Error(t("alerts.close.needVerdict"));
      const body = { verdict, reason: reason.trim() };
      return action === "resolve" ? alertsApi.resolve(alert.id, body) : alertsApi.ignore(alert.id, body);
    },
    onSuccess: () => {
      toast.success(t(action === "resolve" ? "alerts.list.resolved" : "alerts.list.ignored"));
      onDone();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const canSubmit = !!verdict && reason.trim() !== "" && !mutation.isPending;

  return (
    <Modal
      open={!!alert}
      onClose={onClose}
      title={title ?? t(action === "resolve" ? "alerts.close.resolveTitle" : "alerts.close.ignoreTitle")}
      width={520}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button onClick={() => mutation.mutate()} disabled={!canSubmit}>
            {mutation.isPending
              ? t("common.processing")
              : confirmText ?? t(action === "resolve" ? "alerts.close.confirmResolve" : "alerts.close.confirmIgnore")}
          </Button>
        </>
      }
    >
      {alert && (
        <div className="space-y-4">
          <p className="text-sm text-muted">{alert.title}</p>
          <FormField label={t("alerts.close.verdict")} required>
            <div className="space-y-2" role="radiogroup">
              {verdicts.map((v) => (
                <label
                  key={v}
                  className={`flex cursor-pointer gap-3 rounded-card border p-3 transition-colors ${
                    verdict === v ? "border-primary bg-primary/5" : "border-border hover:border-border-strong hover:bg-bg"
                  }`}
                >
                  <input
                    type="radio"
                    name="verdict"
                    className="mt-0.5 accent-primary"
                    checked={verdict === v}
                    onChange={() => setVerdict(v)}
                  />
                  <span>
                    <span className="block text-sm font-medium text-ink">{t(`alerts.verdict.${v}`)}</span>
                    <span className="block text-xs text-muted">{t(`alerts.close.verdictHint.${v}`)}</span>
                  </span>
                </label>
              ))}
            </div>
          </FormField>
          <FormField label={t("alerts.close.reason")} required>
            <Textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder={t("alerts.close.reasonPlaceholder")}
            />
          </FormField>
          {verdict && verdict !== "true_positive" && (
            <p className="text-xs text-faint">{t("alerts.close.whitelistHint")}</p>
          )}
        </div>
      )}
    </Modal>
  );
}
