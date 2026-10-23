import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

/**
 * StatCard 失败态覆盖的棘轮。
 *
 * 平台里大量卡片写作 `value={data?.x ?? 0}`：请求失败时渲染成 0，看板显示
 * "0 个高危漏洞、0 台失陷主机"。值班读到"环境干净"，实际是后端没答上来。
 * StatCard 已支持 error/loading 并在此时渲染占位符，但调用方要把状态传进来才生效。
 *
 * 存量尚未改完（多 query 页面需人工判断哪个查询对应哪张卡，自动改会接错）。
 * 本测试把欠债数量钉住：可以变少，不能变多——新增卡片必须带上失败态。
 */
const APP_DIR = path.resolve(__dirname, "../../app");

/** 已知未接失败态的 StatCard 数量上限。修复后请下调，不得上调。 */
const MAX_UNGUARDED = 0;

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (full.endsWith(".tsx")) out.push(full);
  }
  return out;
}

/**
 * 只统计"可能把失败渲染成 0"的卡片：value 用了可选链或 ?? 兜底。
 *
 * 由父组件保证数据已加载后才渲染的子视图（value={s.passed_checks}）不在此列——
 * 它们不存在兜底成 0 的路径，强加失败态只是噪音。
 */
function isFallbackValue(card: string): boolean {
  const m = card.match(/value=\{([^}]*)\}/);
  if (!m) return false;
  return m[1].includes("??") || m[1].includes("?.");
}

function countStatCards(src: string): { total: number; guarded: number } {
  const lines = src.split("\n");
  let total = 0;
  let guarded = 0;
  let buffer = "";
  let inCard = false;
  for (const line of lines) {
    if (!inCard && line.includes("<StatCard")) {
      inCard = true;
      buffer = line;
    } else if (inCard) {
      buffer += " " + line;
    }
    if (inCard && buffer.includes("/>")) {
      if (!isFallbackValue(buffer)) {
        inCard = false;
        buffer = "";
        continue;
      }
      total++;
      // 认可两种写法：展开 statState，或显式传 error=。
      // 认可三种写法：展开任意 xxxState、显式 error=、或 loading=。
      if (/\{\.\.\.\w*State\}/.test(buffer) || /\berror=\{/.test(buffer) || /\bloading=\{/.test(buffer))
        guarded++;
      inCard = false;
      buffer = "";
    }
  }
  return { total, guarded };
}

describe("StatCard 失败态覆盖", () => {
  it("未接失败态的卡片数量不得增加", () => {
    let total = 0;
    let guarded = 0;
    const offenders: string[] = [];
    for (const file of walk(APP_DIR)) {
      const src = readFileSync(file, "utf8");
      if (!src.includes("<StatCard")) continue;
      const c = countStatCards(src);
      total += c.total;
      guarded += c.guarded;
      if (c.total > c.guarded) {
        offenders.push(`${path.relative(APP_DIR, file)}: ${c.total - c.guarded}/${c.total}`);
      }
    }
    const unguarded = total - guarded;
    expect(total).toBeGreaterThan(0); // 扫描失效时立即暴露，而不是静默通过
    expect(
      unguarded,
      `未接失败态的 StatCard 共 ${unguarded} 个（上限 ${MAX_UNGUARDED}）。\n` +
        `请求失败时它们会把 0 当作真实数值渲染。\n待处理:\n  ${offenders.join("\n  ")}`,
    ).toBeLessThanOrEqual(MAX_UNGUARDED);
  });
});
