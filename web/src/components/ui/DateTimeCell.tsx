"use client";

/**
 * 表格里的时间列：「日期 时间」拆成上下两行。单行要 190px 左右，在 1280 宽下会把列多的表挤出横向滚动。
 */
export function DateTimeCell({ value, className = "" }: { value?: string | null; className?: string }) {
  if (!value) return <span className={className}>—</span>;
  const [date, time] = value.split(" ");
  return (
    <div className={`whitespace-nowrap tabular-nums ${className}`}>
      <div>{date}</div>
      {time && <div className="text-xs">{time}</div>}
    </div>
  );
}
