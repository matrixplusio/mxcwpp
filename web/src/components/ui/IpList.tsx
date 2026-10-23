"use client";

/**
 * 表格里的 IP 列：只显示第一个，其余折成「+N」，悬停看全部。
 * 主机常带容器网桥等多块网卡，整串拼接会把这一列撑到数百像素、挤掉其它列。
 */
export function IpList({ ips, className = "" }: { ips?: string[] | null; className?: string }) {
  if (!ips?.length) return <span className={className}>—</span>;
  return (
    <span className={`whitespace-nowrap ${className}`} title={ips.join("\n")}>
      {ips[0]}
      {ips.length > 1 && <span className="ml-1 text-xs text-faint">+{ips.length - 1}</span>}
    </span>
  );
}
