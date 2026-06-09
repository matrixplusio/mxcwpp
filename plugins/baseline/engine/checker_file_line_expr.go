package engine

// FileLineExprChecker 实现 Elkeid 风格 filter + result 表达式的文件行检查。
//
// Elkeid yaml 例:
//
//	check:
//	  rules:
//	    - type: "file_line_expr"        # 转换后
//	      param: ["/etc/login.defs", '\s*\t*PASS_MAX_DAYS\s*\t*(\d+)']
//	      result: '$(<=)90'
//
// result 表达式语法 (兼容 Elkeid):
//
//	$(<=)N / $(>=)N / $(=)N / $(!=)N / $(<)N / $(>)N — 数值比较 (filter group1 为数值)
//	$(not)REGEX                                       — 文件不含此正则
//	$(EXPR1)$(&&)$(EXPR2)                             — 且
//	$(EXPR1)$(||)$(EXPR2)                             — 或
//
// 设计目标: 直接消费 Elkeid 1077 行基线 yaml 转出的 JSON。

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// FileLineExprChecker 文件行 + 表达式检查器。
type FileLineExprChecker struct {
	logger *zap.Logger
}

// NewFileLineExprChecker 构造。
func NewFileLineExprChecker(logger *zap.Logger) *FileLineExprChecker {
	return &FileLineExprChecker{logger: logger}
}

// Check 执行检查。
func (c *FileLineExprChecker) Check(_ context.Context, rule *CheckRule) (*CheckResult, error) {
	if len(rule.Param) < 1 {
		return nil, fmt.Errorf("file_line_expr requires at least 1 param: [file_path, filter_regex?]")
	}
	filePath := rule.Param[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		// 文件不存在 → 视为不通过 (而非 error, 多数基线项预期文件存在)
		return &CheckResult{
			Pass:     false,
			Actual:   fmt.Sprintf("文件不存在: %s", filePath),
			Expected: rule.Result,
		}, nil
	}
	var filterRe *regexp.Regexp
	if len(rule.Param) >= 2 && rule.Param[1] != "" {
		filterRe, err = regexp.Compile(rule.Param[1])
		if err != nil {
			return nil, fmt.Errorf("invalid filter regex: %w", err)
		}
	}
	pass, actual := evalLineExpr(string(data), filterRe, rule.Result)
	return &CheckResult{
		Pass:     pass,
		Actual:   actual,
		Expected: rule.Result,
	}, nil
}

// evalLineExpr 解析 Elkeid result 表达式并求值。
func evalLineExpr(content string, filterRe *regexp.Regexp, expr string) (bool, string) {
	if expr == "" {
		// 空 result → 只要 filter 命中即 pass
		if filterRe == nil {
			return true, "no expression"
		}
		if filterRe.MatchString(content) {
			return true, "filter matched"
		}
		return false, "filter not matched"
	}
	// 拆 && / ||
	if parts, op := splitTopLevel(expr); len(parts) > 1 {
		results := make([]bool, len(parts))
		actuals := make([]string, len(parts))
		for i, p := range parts {
			results[i], actuals[i] = evalLineExpr(content, filterRe, p)
		}
		switch op {
		case "&&":
			for _, r := range results {
				if !r {
					return false, strings.Join(actuals, " && ")
				}
			}
			return true, strings.Join(actuals, " && ")
		case "||":
			for _, r := range results {
				if r {
					return true, strings.Join(actuals, " || ")
				}
			}
			return false, strings.Join(actuals, " || ")
		}
	}
	// 单原子
	return evalAtomic(content, filterRe, expr)
}

// splitTopLevel 把 "$(A)$(&&)$(B)$(&&)$(C)" 拆成 ["$(A)", "$(B)", "$(C)"]。
func splitTopLevel(expr string) ([]string, string) {
	if strings.Contains(expr, "$(&&)") {
		return strings.Split(expr, "$(&&)"), "&&"
	}
	if strings.Contains(expr, "$(||)") {
		return strings.Split(expr, "$(||)"), "||"
	}
	return []string{expr}, ""
}

// evalAtomic 单 $(op)val 原子求值。
func evalAtomic(content string, filterRe *regexp.Regexp, expr string) (bool, string) {
	// $(not)PATTERN → content 不含 PATTERN
	if strings.HasPrefix(expr, "$(not)") {
		pat := expr[len("$(not)"):]
		re, err := regexp.Compile(pat)
		if err != nil {
			return false, "invalid not pattern: " + pat
		}
		if re.MatchString(content) {
			return false, "matched but expected absent: " + pat
		}
		return true, "absent: " + pat
	}
	// $(op)value → 数值比较 (用 filter group1)
	for _, op := range []string{"<=", ">=", "!=", "<", ">", "="} {
		token := "$(" + op + ")"
		if strings.HasPrefix(expr, token) {
			valStr := expr[len(token):]
			expect, err := strconv.Atoi(strings.TrimSpace(valStr))
			if err != nil {
				return false, "invalid op value: " + valStr
			}
			if filterRe == nil {
				return false, "op requires filter to capture number"
			}
			// 抓第一处匹配的 group1
			m := filterRe.FindStringSubmatch(content)
			if len(m) < 2 {
				return false, "filter not matched or no capture"
			}
			actual, err := strconv.Atoi(strings.TrimSpace(m[1]))
			if err != nil {
				return false, "captured non-numeric: " + m[1]
			}
			pass := compareNum(actual, op, expect)
			return pass, fmt.Sprintf("actual=%d %s %d", actual, op, expect)
		}
	}
	// 兜底: 当成 regex match
	re, err := regexp.Compile(expr)
	if err != nil {
		return false, "invalid expr regex: " + expr
	}
	if re.MatchString(content) {
		return true, "matched: " + expr
	}
	return false, "not matched: " + expr
}

func compareNum(a int, op string, b int) bool {
	switch op {
	case "<=":
		return a <= b
	case ">=":
		return a >= b
	case "<":
		return a < b
	case ">":
		return a > b
	case "=":
		return a == b
	case "!=":
		return a != b
	}
	return false
}
