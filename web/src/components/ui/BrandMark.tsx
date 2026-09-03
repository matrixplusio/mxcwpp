/** 扁平品牌标识:渐变圆角方块 + 白色「矩阵盾」(盾形 + 互联节点),贴 Isora 蓝调极简风。 */
export function BrandMark({ size = 36 }: { size?: number }) {
  const inner = Math.round(size * 0.62);
  return (
    <div
      className="flex shrink-0 items-center justify-center rounded-card bg-gradient-to-br from-primary to-accent text-white shadow-lg shadow-primary/20"
      style={{ width: size, height: size }}
    >
      <svg width={inner} height={inner} viewBox="0 0 24 24" fill="none" aria-hidden>
        <path
          d="M12 2.4 19 5.1 V11 c0 4.7-3 8-7 9.6 C8 19 5 15.7 5 11 V5.1 Z"
          fill="white"
          fillOpacity="0.16"
          stroke="white"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
        <path d="M9 9.4 15 9.4 M9 9.4 12 14 M15 9.4 12 14" stroke="white" strokeWidth="1.1" strokeOpacity="0.75" />
        <circle cx="9" cy="9.4" r="1.35" fill="white" />
        <circle cx="15" cy="9.4" r="1.35" fill="white" />
        <circle cx="12" cy="14" r="1.35" fill="white" />
      </svg>
    </div>
  );
}
