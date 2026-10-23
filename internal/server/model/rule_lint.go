package model

import (
	"fmt"
	"regexp"
)

// shortExeContains 匹配对 exe / parent_exe 做一两个字符的子串匹配。
var shortExeContains = regexp.MustCompile(`exe\.contains\("([^"]{1,2})"\)`)

// LintRuleExpression 检查检测规则表达式里会大面积误报的写法，返回问题描述；没有问题返回空串。
//
// exe 是完整路径，`exe.contains("w")` 会命中路径里任何带 w 的进程，`exe.contains("nc")`
// 会命中 runc、rsync、unbound-anchor……这类规则在全舰队每台主机上持续响，
// 最终被整批忽略，真正的命中也跟着看不见。按进程名精确匹配：
// `(exe == "nc" || exe.endsWith("/nc"))`。命令行参数上的短串（如 cmdline.contains("-e")）不在此列。
func LintRuleExpression(expr string) string {
	if m := shortExeContains.FindStringSubmatch(expr); m != nil {
		return fmt.Sprintf(`exe.contains("%s") 会命中任何路径里带 %q 的进程，请改为按进程名匹配：(exe == "%s" || exe.endsWith("/%s"))`,
			m[1], m[1], m[1], m[1])
	}
	return ""
}
