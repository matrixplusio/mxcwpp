import { Card } from "./Card";
import { cn } from "@/lib/utils/cn";
import { STAT_UNKNOWN } from "@/lib/utils/stat";
import type { LucideIcon } from "lucide-react";

interface Props {
  label: string;
  value: string | number;
  icon: LucideIcon;
  tone?: "default" | "danger" | "warning" | "success";
  compact?: boolean;
  /**
   * 数据取不到。渲染为占位符而非数字。
   *
   * 请求失败时若照常渲染 `?? 0`，看板会显示"0 个高危漏洞"——值班读到的是
   * "环境干净"，实际是"后端没答上来"。这两件事必须能区分。
   */
  error?: boolean;
  /** 加载中。同样不渲染数字，避免把中间态当作结论。 */
  loading?: boolean;
  /** 取不到时的悬浮说明，默认给出通用文案。 */
  errorHint?: string;
}
const tones = {
  default: "text-primary bg-gradient-to-br from-primary/15 to-primary/5",
  danger: "text-danger bg-gradient-to-br from-danger/15 to-danger/5",
  warning: "text-warning bg-gradient-to-br from-warning/15 to-warning/5",
  success: "text-success bg-gradient-to-br from-success/15 to-success/5",
};

export function StatCard({
  label,
  value,
  icon: Icon,
  tone = "default",
  compact = false,
  error = false,
  loading = false,
  errorHint,
}: Props) {
  const unavailable = error || loading;
  // 取不到时一律走中性色：让失败的卡片保持 danger/success 配色会强化误读，
  // 比如"0 台失陷主机"配绿色，看起来像一条好消息。
  const iconTone = unavailable ? "text-muted bg-muted/10" : tones[tone];
  const hint = error
    ? (errorHint ?? "数据获取失败，此处不代表 0")
    : loading
      ? "加载中"
      : undefined;

  return (
    <Card className={cn("flex items-center gap-3 transition-all duration-200 hover:-translate-y-0.5", compact ? "p-3.5" : "p-5 gap-4")}>
      <div className={cn("rounded-control flex items-center justify-center shrink-0", iconTone, compact ? "h-9 w-9" : "h-11 w-11")}>
        <Icon size={compact ? 17 : 20} />
      </div>
      <div className="min-w-0">
        <div
          className={cn(
            "font-bold leading-tight tabular-nums truncate",
            unavailable ? "text-muted" : "text-ink",
            compact ? "text-xl" : "text-2xl",
          )}
          title={hint}
          aria-label={error ? `${label}: 数据获取失败` : undefined}
        >
          {unavailable ? STAT_UNKNOWN : value}
        </div>
        <div className={cn("text-muted truncate", compact ? "text-xs" : "text-sm")}>{label}</div>
      </div>
    </Card>
  );
}
