"use client";
import { CopyButton } from "./CopyButton";

/**
 * 表格里的主机列：主机名一行、host_id 一行，都限宽截断。
 * host_id 是 64 位无空格哈希，整串显示会把列撑到 500px 左右，1280 宽下整张表出现横向滚动。
 * 只有 host_id 时它占第一行；compact 只显示一行（放在别的列下面当副标题时用）。
 */
export function HostCell({ hostname, hostId, compact = false }: { hostname?: string | null; hostId?: string | null; compact?: boolean }) {
  if (!hostname && !hostId) return <span className="text-faint">—</span>;
  const id = hostId ? (
    <span className="flex min-w-0 items-center gap-1">
      <span title={hostId} className="block max-w-[8rem] truncate font-mono text-xs text-faint">{hostId}</span>
      <CopyButton text={hostId} />
    </span>
  ) : null;
  if (compact) {
    return hostname ? <span title={hostId ?? undefined} className="block max-w-[14rem] truncate text-xs text-faint">{hostname}</span> : id;
  }
  if (!hostname) return id;
  return (
    <div className="min-w-0">
      <div title={hostname} className="max-w-[11rem] truncate font-medium text-ink">{hostname}</div>
      {id}
    </div>
  );
}
