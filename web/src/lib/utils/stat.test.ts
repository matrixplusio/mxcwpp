import { describe, expect, it } from "vitest";
import { STAT_UNKNOWN, statFromQuery, statPercent } from "./stat";

describe("statFromQuery", () => {
  // 这条是整个模块存在的理由：请求失败渲染成 0，看板上就是"0 个高危漏洞"，
  // 值班读到"环境干净"，实际是后端没答上来。
  it("请求失败时不得渲染成数字", () => {
    const got = statFromQuery({ isError: true }, 0);
    expect(got.state).toBe("error");
    expect(got.text).toBe(STAT_UNKNOWN);
    expect(got.value).toBeUndefined();
  });

  it("加载中不得渲染成数字", () => {
    expect(statFromQuery({ isLoading: true }, 42).text).toBe(STAT_UNKNOWN);
    expect(statFromQuery({ isPending: true }, 42).text).toBe(STAT_UNKNOWN);
  });

  // 失败后重试期间 error 与 loading 同时为真。此时显示"加载中"会让人以为
  // 再等等就好，实际是取不到——必须以 error 为准。
  it("失败重试期间以失败为准，而非加载中", () => {
    expect(statFromQuery({ isError: true, isLoading: true }, 0).state).toBe("error");
  });

  // 请求成功但字段缺失同样是"取不到"，不能当作 0。
  it("字段缺失按取不到处理", () => {
    expect(statFromQuery({}, null).state).toBe("error");
    expect(statFromQuery({}, undefined).state).toBe("error");
  });

  it("正常值照常渲染，包括真实的 0", () => {
    const zero = statFromQuery({}, 0);
    expect(zero.state).toBe("ok");
    expect(zero.text).toBe("0");
    expect(zero.value).toBe(0);
  });

  it("支持自定义格式化", () => {
    expect(statFromQuery({}, 1234, (v) => `${v} 台`).text).toBe("1234 台");
  });
});

describe("statPercent", () => {
  // "0 项检查全部通过 = 100% 合规"与把失败显示成 0 是同一类谎报：
  // 没测过不等于测过了且通过。
  it("分母为 0 时不得渲染成 100% 或 0%", () => {
    expect(statPercent(0, 0).text).toBe(STAT_UNKNOWN);
    expect(statPercent(5, 0).text).toBe(STAT_UNKNOWN);
  });

  it("缺失值按取不到处理", () => {
    expect(statPercent(null, 10).state).toBe("error");
    expect(statPercent(5, undefined).state).toBe("error");
  });

  it("正常计算并保留一位小数", () => {
    expect(statPercent(1, 3).text).toBe("33.3%");
    expect(statPercent(10, 10).text).toBe("100%");
    expect(statPercent(0, 10).text).toBe("0%");
  });
});
