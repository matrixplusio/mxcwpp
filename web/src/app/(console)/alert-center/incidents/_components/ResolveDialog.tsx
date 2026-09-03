"use client";

import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import type { IncidentVerdict } from "@/lib/api/types";

interface Props {
  open: boolean;
  title?: string;
  submitting?: boolean;
  onCancel: () => void;
  onSubmit: (verdict: IncidentVerdict, reason: string) => void;
}

/**
 * 关闭事件对话框。
 *
 * 关闭必须给出研判结论与原因，所以不能用只有"确认/取消"的 ConfirmDialog。
 * 后端会拒绝缺任一项的请求，这里同样挡在前面——让人在点下去之前就知道要填什么，
 * 而不是提交后收到一个报错。
 */
export function ResolveDialog({ open, title, submitting, onCancel, onSubmit }: Props) {
  const { t } = useTranslation();
  const [verdict, setVerdict] = useState<IncidentVerdict | "">("");
  const [reason, setReason] = useState("");

  const verdicts: { value: IncidentVerdict; label: string; hint: string }[] = [
    {
      value: "true_positive",
      label: t("alerts.incident.verdictTruePositive"),
      hint: t("alerts.incident.verdictTruePositiveHint"),
    },
    {
      value: "false_positive",
      label: t("alerts.incident.verdictFalsePositive"),
      hint: t("alerts.incident.verdictFalsePositiveHint"),
    },
    {
      value: "benign_true_positive",
      label: t("alerts.incident.verdictBenign"),
      hint: t("alerts.incident.verdictBenignHint"),
    },
  ];

  const canSubmit = verdict !== "" && reason.trim() !== "" && !submitting;

  const reset = () => {
    setVerdict("");
    setReason("");
  };

  return (
    <Modal
      open={open}
      title={t("alerts.incident.resolveTitle")}
      onClose={() => {
        reset();
        onCancel();
      }}
    >
      <div className="space-y-4">
        {title && <div className="text-sm text-muted">{title}</div>}

        <div>
          <div className="mb-2 text-sm font-medium text-ink">
            {t("alerts.incident.verdictLabel")}
            <span className="ml-1 text-danger">*</span>
          </div>
          <div className="space-y-2">
            {verdicts.map((v) => (
              <label
                key={v.value}
                className="flex cursor-pointer items-start gap-2 rounded-control border border-line p-2.5 transition-colors hover:border-primary/50"
              >
                <input
                  type="radio"
                  name="verdict"
                  className="mt-1"
                  checked={verdict === v.value}
                  onChange={() => setVerdict(v.value)}
                />
                <span className="min-w-0">
                  <span className="block text-sm text-ink">{v.label}</span>
                  <span className="block text-xs text-muted">{v.hint}</span>
                </span>
              </label>
            ))}
          </div>
        </div>

        <div>
          <div className="mb-2 text-sm font-medium text-ink">
            {t("alerts.incident.closeReasonLabel")}
            <span className="ml-1 text-danger">*</span>
          </div>
          <textarea
            className="w-full rounded-control border border-line bg-surface p-2.5 text-sm text-ink outline-none focus:border-primary"
            rows={3}
            value={reason}
            placeholder={t("alerts.incident.closeReasonPlaceholder")}
            onChange={(e) => setReason(e.target.value)}
          />
          <div className="mt-1 text-xs text-muted">
            {t("alerts.incident.closeReasonHint")}
          </div>
        </div>

        <div className="flex justify-end gap-2">
          <Button
            variant="ghost"
            onClick={() => {
              reset();
              onCancel();
            }}
          >
            {t("common.cancel")}
          </Button>
          <Button
            disabled={!canSubmit}
            onClick={() => {
              if (!canSubmit) return;
              onSubmit(verdict as IncidentVerdict, reason.trim());
              reset();
            }}
          >
            {t("alerts.incident.resolve")}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
