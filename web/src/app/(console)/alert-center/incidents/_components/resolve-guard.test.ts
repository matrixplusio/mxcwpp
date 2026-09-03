import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * 关闭事件的前端约束。
 *
 * 后端拒绝缺研判结论或原因的关闭请求。前端必须同样挡住，否则用户点了提交
 * 才收到报错——而更糟的情况是有人把校验只做在一侧，另一侧悄悄放行。
 *
 * 用源码断言而非渲染测试：这里要守的是"约束存在且没被删掉"，
 * 而不是某个按钮的具体样式。
 */
const DIALOG = path.resolve(__dirname, "./ResolveDialog.tsx");

describe("关闭事件对话框", () => {
  const src = readFileSync(DIALOG, "utf8");

  it("提交前必须同时具备研判结论与原因", () => {
    // canSubmit 必须同时检查两者，缺任一项都不能放行。
    expect(src).toMatch(/verdict !== ""/);
    expect(src).toMatch(/reason\.trim\(\) !== ""/);
  });

  it("提交按钮在条件不满足时禁用", () => {
    expect(src).toMatch(/disabled=\{!canSubmit\}/);
  });

  it("三档研判结论齐全", () => {
    // benign_true_positive 单列一档：把它算进误报会让正常规则被错误调松。
    for (const v of ["true_positive", "false_positive", "benign_true_positive"]) {
      expect(src).toContain(`"${v}"`);
    }
  });

  it("不得绕过 canSubmit 直接提交", () => {
    expect(src).toMatch(/if \(!canSubmit\) return;/);
  });
});
