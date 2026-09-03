// Package execpolicy 提供 agent 侧下发命令的执行边界。
//
// 核心立场：只要命令还以字符串形式交给 /bin/sh，整个 shell 语法就都是攻击面，
// 靠"危险词黑名单 + 前缀白名单"不可能收敛——前缀只约束第一个词，参数空间完全开放。
// 因此本包提供的是"结构化 argv + 显式允许集"，而不是又一层字符串过滤。
package execpolicy

import (
	"fmt"
	"strings"
	"unicode"
)

// MaxCommandLen 是下发命令的长度上限。
const MaxCommandLen = 4096

// shellMeta 是能改变命令**结构**的字符：分隔、串联、替换、重定向、引号、转义。
// 出现其一即拒绝——这些正是把"一条包管理器命令"变成"任意多条命令"的手段。
//
// 刻意不含通配符（* ? [ ] { }）：本包的 argv 直接交给 exec，不经 shell，通配符不会被
// 展开，只是普通字面量；把它们也拒掉会误伤 dnf --setopt=*.skip_if_unavailable=1
// 这类现网在用的合法参数，属于用安全之名砍功能。
const shellMeta = ";|&$`()<>'\"\\"

// ValidateNoControlChars 拒绝控制字符。
//
// 换行/回车尤其关键：sh -c 把 \n 当作命令分隔符，而只检查 ; | & 的校验器会放行
// "yum install foo\n<任意命令>"。制表符允许（部分配置类命令的合法分隔）。
func ValidateNoControlChars(s string) error {
	for i, r := range s {
		if r == '\t' {
			continue
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("命令含控制字符（偏移 %d，U+%04X），拒绝执行", i, r)
		}
	}
	return nil
}

// ValidateLength 校验命令长度上限。
func ValidateLength(s string) error {
	if len(s) > MaxCommandLen {
		return fmt.Errorf("命令长度 %d 超过上限 %d", len(s), MaxCommandLen)
	}
	return nil
}

// SplitArgv 把命令切成 argv，供 exec.Command 直接使用（不经 shell）。
//
// 只按空白切分：不做引号解析、不做转义处理、不做展开。任何 token 含 shell 元字符
// 一律拒绝——本包的执行路径没有 shell，元字符只会被当作字面量传给程序，与调用方
// 的意图必然不符，静默放行比报错危险得多。
func SplitArgv(command string) ([]string, error) {
	if err := ValidateLength(command); err != nil {
		return nil, err
	}
	if err := ValidateNoControlChars(command); err != nil {
		return nil, err
	}
	argv := strings.Fields(command)
	if len(argv) == 0 {
		return nil, fmt.Errorf("命令为空")
	}
	for _, tok := range argv {
		if i := strings.IndexAny(tok, shellMeta); i >= 0 {
			return nil, fmt.Errorf("命令片段 %q 含 shell 元字符 %q，拒绝执行", tok, tok[i:i+1])
		}
	}
	return argv, nil
}
