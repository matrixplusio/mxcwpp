/**
 * 统计数值的展示状态。
 *
 * 平台里大量卡片写成 `data?.total ?? 0`：请求失败时渲染成 0，看板上就是一片
 * "0 个高危漏洞、0 台失陷主机"。值班看到的是"环境干净"，实际是"后端没答上来"——
 * 这两件事在安全产品里必须能区分，把它们显示成同一个数字是最危险的一种谎报。
 *
 * 规则：缺失即 UNKNOWN，不是达标。失败与加载中都不得渲染成数字。
 */
export type StatState = "ok" | "loading" | "error";

export interface StatDisplay {
  state: StatState;
  /** 可直接渲染的文本。error/loading 时为占位符而非数字。 */
  text: string;
  /** 仅 state==="ok" 时有值。 */
  value?: number | string;
}

/** 失败占位符：明确表示"取不到"，与 0 有本质区别。 */
export const STAT_UNKNOWN = "—";

interface QueryLike {
  isError?: boolean;
  isLoading?: boolean;
  isPending?: boolean;
}

/**
 * 把 TanStack Query 的结果映射为展示状态。
 *
 * 判定顺序是刻意的：先看 error 再看 loading。查询失败后重试期间同时为
 * error 与 loading，此时应显示"取不到"而不是"加载中"——后者会让人以为再等等就好。
 */
export function statFromQuery(
  query: QueryLike | undefined,
  value: number | string | null | undefined,
  format?: (v: number | string) => string,
): StatDisplay {
  if (query?.isError) {
    return { state: "error", text: STAT_UNKNOWN };
  }
  if (query?.isLoading || query?.isPending) {
    return { state: "loading", text: STAT_UNKNOWN };
  }
  if (value === null || value === undefined) {
    // 请求成功但字段缺失：同样是"取不到"，不能当作 0。
    return { state: "error", text: STAT_UNKNOWN };
  }
  return {
    state: "ok",
    text: format ? format(value) : String(value),
    value,
  };
}

/**
 * 计算百分比。分母为 0 或缺失时返回 UNKNOWN 而不是 100% 或 0%。
 *
 * "0 项检查全部通过 = 100% 合规"是同一类谎报：没测过不等于测过了且通过。
 */
export function statPercent(
  passed: number | null | undefined,
  total: number | null | undefined,
): StatDisplay {
  if (
    passed === null || passed === undefined ||
    total === null || total === undefined ||
    total <= 0
  ) {
    return { state: "error", text: STAT_UNKNOWN };
  }
  const pct = Math.round((passed / total) * 1000) / 10;
  return { state: "ok", text: `${pct}%`, value: pct };
}
