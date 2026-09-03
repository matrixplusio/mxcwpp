"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { detectionApi } from "@/lib/api/detection";
import type { DetectionRule, RuleStage } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Modal } from "@/components/ui/Modal";
import { toast } from "@/components/ui/toast";
import { AlertTriangle, ArrowUp, ArrowDown } from "lucide-react";

/** 阶段顺序，用于渲染进度条。 */
const STAGES: RuleStage[] = ["draft", "shadow", "context", "alert"];

/** 各阶段的样式。只有 alert 用告警色——它是唯一会打扰到人的阶段。 */
const stageTone: Record<RuleStage, string> = {
  draft: "bg-muted/10 text-muted",
  shadow: "bg-primary/10 text-primary",
  context: "bg-warning/10 text-warning",
  alert: "bg-danger/10 text-danger",
};

/** 阶段徽章，可在列表与详情复用。 */
export function StageBadge({ stage }: { stage?: RuleStage | "" }) {
  const { t } = useTranslation();
  // 存量规则尚未回填时按 alert 显示：它的实际行为就是告警，
  // 显示成"未设置"会让人以为它已经不响了。
  const s = (stage || "alert") as RuleStage;
  return (
    <span className={`rounded-control px-1.5 py-0.5 text-xs ${stageTone[s]}`}>
      {t(`detection.stage.${s}` as never, { defaultValue: s }) as string}
    </span>
  );
}

/** 精确率展示：样本不足时显示占位符而不是 0。 */
function PrecisionValue({ value, judged }: { value: number | null; judged: number }) {
  const { t } = useTranslation();
  if (value === null) {
    return (
      <span className="text-sm text-muted" title={t("detection.lifecycle.precisionUnknownHint")}>
        {/* 不渲染成 0：0 会被读成"精确率为零"，而实际含义是"样本不够，不知道"。 */}
        {t("detection.lifecycle.precisionUnknown")}
      </span>
    );
  }
  return (
    <span className={`text-lg font-semibold ${value >= 0.85 ? "text-success" : "text-danger"}`}>
      {(value * 100).toFixed(1)}%
      <span className="ml-1 text-xs font-normal text-faint">
        ({t("detection.lifecycle.judgedCount", { count: judged })})
      </span>
    </span>
  );
}

/**
 * 规则生命周期面板。
 *
 * 晋级由数据决定，所以这里必须把数据摆出来：不满足条件时直接显示差在哪，
 * 而不是让人点一次、看一句"不满足条件"、再自己猜门槛。
 */
export function RuleLifecycle({ rule }: { rule: DetectionRule }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [demoting, setDemoting] = useState(false);
  const [demoteStage, setDemoteStage] = useState<RuleStage>("shadow");
  const [demoteReason, setDemoteReason] = useState("");

  const promotionQuery = useQuery({
    queryKey: ["rule-promotion", rule.id],
    queryFn: () => detectionApi.rulePromotion(rule.id),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["rule-promotion", rule.id] });
    queryClient.invalidateQueries({ queryKey: ["detection-rules"] });
  };

  const promote = useMutation({
    mutationFn: () => detectionApi.promoteRule(rule.id),
    onSuccess: (d) => {
      invalidate();
      toast.success(t("detection.lifecycle.promoted", { stage: d.to }));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const demote = useMutation({
    mutationFn: () => detectionApi.demoteRule(rule.id, demoteStage, demoteReason.trim()),
    onSuccess: () => {
      invalidate();
      setDemoting(false);
      setDemoteReason("");
      toast.success(t("detection.lifecycle.demoted"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const current = (rule.stage || "alert") as RuleStage;
  const decision = promotionQuery.data;
  const quality = decision?.quality;

  return (
    <div className="space-y-3">
      {/* 阶段进度 */}
      <Card className="p-4">
        <div className="mb-3 text-sm font-medium text-ink">{t("detection.lifecycle.title")}</div>
        <div className="flex items-center gap-1.5">
          {STAGES.map((s, i) => {
            const reached = STAGES.indexOf(current) >= i;
            return (
              <div key={s} className="flex flex-1 items-center gap-1.5">
                <div className="flex-1">
                  <div
                    className={`h-1.5 rounded-full ${reached ? "bg-primary" : "bg-line"}`}
                  />
                  <div className={`mt-1 text-xs ${s === current ? "font-semibold text-ink" : "text-faint"}`}>
                    {t(`detection.stage.${s}` as never, { defaultValue: s }) as string}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        <p className="mt-2 text-xs text-muted">{t("detection.lifecycle.stageHint")}</p>
      </Card>

      {/* 检测质量 */}
      <Card className="p-4">
        <div className="mb-2 text-sm font-medium text-ink">{t("detection.lifecycle.quality")}</div>
        {promotionQuery.isError ? (
          // 取不到就说取不到，不能显示成"精确率 0"。
          <div className="text-sm text-danger">{t("detection.lifecycle.loadFailed")}</div>
        ) : promotionQuery.isLoading ? (
          <div className="text-sm text-muted">{t("common.loading")}</div>
        ) : quality ? (
          <div className="space-y-2">
            <PrecisionValue value={quality.precision} judged={quality.judged} />
            <div className="grid grid-cols-4 gap-2 text-xs">
              <div>
                <div className="text-faint">{t("detection.lifecycle.tp")}</div>
                <div className="text-ink">{quality.true_positive}</div>
              </div>
              <div>
                <div className="text-faint">{t("detection.lifecycle.fp")}</div>
                <div className="text-ink">{quality.false_positive}</div>
              </div>
              <div>
                {/* 单独列出：它不是误报，但也不该被当成纯粹的成功。 */}
                <div className="text-faint">{t("detection.lifecycle.benign")}</div>
                <div className="text-ink">{quality.benign_true_positive}</div>
              </div>
              <div>
                <div className="text-faint">{t("detection.lifecycle.undetermined")}</div>
                <div className="text-ink">{quality.undetermined}</div>
              </div>
            </div>
            <p className="text-xs text-muted">{t("detection.lifecycle.benignHint")}</p>
          </div>
        ) : null}
      </Card>

      {/* 晋级 / 降级 */}
      <Card className="p-4">
        <div className="mb-2 text-sm font-medium text-ink">{t("detection.lifecycle.transition")}</div>
        {decision && !decision.eligible && decision.reasons.length > 0 && (
          <div className="mb-3 space-y-1">
            {/* 直接列出差距，省掉"点一次才知道不行"的来回。 */}
            {decision.reasons.map((r) => (
              <div key={r} className="flex items-start gap-1.5 text-sm text-warning">
                <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                <span>{r}</span>
              </div>
            ))}
          </div>
        )}
        <div className="flex gap-2">
          <Button
            disabled={!decision?.eligible || promote.isPending || !decision?.to}
            onClick={() => promote.mutate()}
          >
            <ArrowUp size={14} className="mr-1 inline" />
            {decision?.to
              ? t("detection.lifecycle.promoteTo", { stage: decision.to })
              : t("detection.lifecycle.atTop")}
          </Button>
          <Button variant="ghost" onClick={() => setDemoting(true)}>
            <ArrowDown size={14} className="mr-1 inline" />
            {t("detection.lifecycle.demote")}
          </Button>
        </div>
      </Card>

      <Modal
        open={demoting}
        title={t("detection.lifecycle.demoteTitle")}
        onClose={() => setDemoting(false)}
      >
        <div className="space-y-3">
          <p className="text-sm text-muted">{t("detection.lifecycle.demoteHint")}</p>
          <select
            className="w-full rounded-control border border-line bg-surface p-2 text-sm text-ink"
            value={demoteStage}
            onChange={(e) => setDemoteStage(e.target.value as RuleStage)}
          >
            {STAGES.filter((s) => STAGES.indexOf(s) < STAGES.indexOf(current)).map((s) => (
              <option key={s} value={s}>
                {t(`detection.stage.${s}` as never, { defaultValue: s }) as string}
              </option>
            ))}
          </select>
          <textarea
            className="w-full rounded-control border border-line bg-surface p-2.5 text-sm text-ink outline-none focus:border-primary"
            rows={3}
            value={demoteReason}
            placeholder={t("detection.lifecycle.demoteReasonPlaceholder")}
            onChange={(e) => setDemoteReason(e.target.value)}
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setDemoting(false)}>
              {t("common.cancel")}
            </Button>
            {/* 必须写原因：否则以后没人知道它为什么被关小了。 */}
            <Button
              disabled={demoteReason.trim() === "" || demote.isPending}
              onClick={() => demote.mutate()}
            >
              {t("detection.lifecycle.demote")}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
