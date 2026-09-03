package forensics

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/matrixplusio/mxcwpp/internal/common/execpolicy"
)

// 取证命令的执行边界。
//
// 旧实现是"正则黑名单 + sh -c"：列举 rm -rf / dd / mkfs 等形态并放行其余一切。
// 这个方向反了——黑名单要穷举无穷的攻击形态，而 sh -c 让攻击者拥有完整 shell 语法
// （管道、替换、重定向、换行分隔），任何未被列举的写法都是缺口。取证的实际需求是
// "读取主机状态"，是一个有限且可枚举的集合，因此改为白名单 + argv 直接 exec。
//
// 取证命令按定义只读：不允许任何写入、执行、网络外联或改变系统状态的程序与参数。

// shortFlagRe 匹配组合短选项（如 ps aux 的 -ef、ss 的 -tulnp）。
// 只允许纯字母，因而不含 = ，无法携带值去改写程序行为。
var shortFlagRe = regexp.MustCompile(`^-[a-zA-Z]+$`)

// pathOperandRe 约束路径/名称类操作数。不允许 .. 以外的特殊构造由 SplitArgv 兜底
// （shell 元字符已在切分阶段拒绝），此处只保证是个可打印的普通路径或标识符。
var pathOperandRe = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

// numericOperandRe 约束纯数字操作数（PID、行数等）。
var numericOperandRe = regexp.MustCompile(`^[0-9]+$`)

// forensicSpec 描述一个允许的取证程序。
type forensicSpec struct {
	// subcommands 非空时，argv[1] 必须命中其一（如 ip addr、systemctl status）。
	subcommands map[string]bool
	// allowShortFlags 允许 -abc 形式的组合短选项。
	allowShortFlags bool
	// flags 额外允许的精确选项。
	flags map[string]bool
	// bareFlags 是不带前导 - 的关键字（ps aux 的 BSD 风格、ip 的 show/list）。
	// 它们按关键字校验，不计入操作数。
	bareFlags map[string]bool
	// maxOperands 限制操作数个数，0 表示不限。用于挡住"允许的子命令 + 写操作动词"
	// 这类形态（如 ip link set eth0 down：set/eth0/down 是三个裸词）。
	maxOperands int
	// valueFlags 允许"选项 值"形式的选项，值按 operand 规则校验。
	valueFlags map[string]bool
	// operand 约束非选项参数；nil 表示不接受任何操作数。
	operand *regexp.Regexp
}

func fset(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// allowedForensicBins 是允许执行的只读取证程序。
//
// 刻意不包含 find：它的 -exec / -delete / -fprintf 可以执行命令与写文件，
// 无法靠参数约束保证只读。需要按条件找文件请用 file_get 或补充专用 action。
// 同样不包含任何编辑器、解释器（python/perl/awk 的 -e）、下载工具与包管理器。
var allowedForensicBins = map[string]forensicSpec{
	// 进程与会话
	"ps":     {allowShortFlags: true, flags: fset("-ef", "--no-headers"), bareFlags: fset("aux", "auxww", "ax", "axjf", "ef"), operand: nil},
	"lsof":   {allowShortFlags: true, valueFlags: fset("-p", "-i", "-u"), operand: pathOperandRe},
	"id":     {operand: pathOperandRe},
	"w":      {allowShortFlags: true},
	"who":    {allowShortFlags: true},
	"last":   {allowShortFlags: true, valueFlags: fset("-n"), operand: numericOperandRe},
	"uptime": {allowShortFlags: true},

	// 网络
	"ss":      {allowShortFlags: true},
	"netstat": {allowShortFlags: true},
	// ip 的子命令后只允许 show/list 与一个设备名。写操作动词（set/add/del/flush 等）
	// 会被"最多一个操作数"挡住：ip link set eth0 down 有 set/eth0/down 三个裸词。
	"ip": {
		subcommands: fset("addr", "a", "route", "r", "link", "l", "neigh", "n", "rule"),
		flags:       fset("-4", "-6", "-br", "-brief"),
		bareFlags:   fset("show", "list", "s", "l"),
		operand:     pathOperandRe,
		maxOperands: 1,
	},

	// 文件系统与文件内容
	"ls":         {allowShortFlags: true, operand: pathOperandRe},
	"stat":       {allowShortFlags: true, operand: pathOperandRe},
	"cat":        {operand: pathOperandRe},
	"head":       {allowShortFlags: true, valueFlags: fset("-n", "-c"), operand: pathOperandRe},
	"tail":       {allowShortFlags: true, valueFlags: fset("-n", "-c"), operand: pathOperandRe},
	"file":       {operand: pathOperandRe},
	"readlink":   {allowShortFlags: true, operand: pathOperandRe},
	"sha256sum":  {operand: pathOperandRe},
	"md5sum":     {operand: pathOperandRe},
	"df":         {allowShortFlags: true, operand: pathOperandRe},
	"mount":      {allowShortFlags: true},
	"getcap":     {allowShortFlags: true, operand: pathOperandRe},
	"lsattr":     {allowShortFlags: true, operand: pathOperandRe},
	"getenforce": {},
	"sestatus":   {allowShortFlags: true},

	// 主机与内核
	"uname":    {allowShortFlags: true},
	"hostname": {allowShortFlags: true},
	"date":     {allowShortFlags: true},
	"free":     {allowShortFlags: true},
	"dmesg":    {allowShortFlags: true, flags: fset("--ctime")},

	// 账户与计划任务
	"getent":  {subcommands: fset("passwd", "group", "hosts", "shadow", "services"), operand: pathOperandRe},
	"crontab": {flags: fset("-l"), valueFlags: fset("-u"), operand: pathOperandRe},

	// 服务与日志
	"systemctl": {
		subcommands: fset("status", "show", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "cat"),
		flags:       fset("--no-pager", "--all", "-a", "--failed"),
		operand:     pathOperandRe,
	},
	"journalctl": {
		allowShortFlags: true,
		flags:           fset("--no-pager", "--dmesg"),
		valueFlags:      fset("-u", "-n", "-p"),
		operand:         pathOperandRe,
	},

	// 包管理器的查询子命令（只读）
	"rpm":  {flags: fset("-qa", "-qi", "-ql", "-qf", "-V", "-Va", "-q"), operand: pathOperandRe},
	"dpkg": {flags: fset("-l", "-s", "-S", "-L", "--list", "--status"), operand: pathOperandRe},
}

// ParseForensicArgv 校验取证命令并返回可直接交给 exec.Command 的 argv。
// 返回的 argv 永远不经 shell 执行。
func ParseForensicArgv(command string) ([]string, error) {
	argv, err := execpolicy.SplitArgv(command)
	if err != nil {
		return nil, err
	}

	spec, ok := allowedForensicBins[argv[0]]
	if !ok {
		return nil, fmt.Errorf("程序 %q 不在只读取证白名单内", argv[0])
	}

	rest := argv[1:]
	if len(spec.subcommands) > 0 {
		// 子命令可以出现在前置选项之后（如 ip -br link），先跳过前导选项再判定。
		idx := 0
		for idx < len(rest) && strings.HasPrefix(rest[idx], "-") {
			if !spec.flags[rest[idx]] && !(spec.allowShortFlags && shortFlagRe.MatchString(rest[idx])) {
				return nil, fmt.Errorf("参数 %q 不在 %s 的允许选项内", rest[idx], argv[0])
			}
			idx++
		}
		if idx >= len(rest) {
			return nil, fmt.Errorf("%s 缺少子命令", argv[0])
		}
		if !spec.subcommands[rest[idx]] {
			return nil, fmt.Errorf("%s 的子命令 %q 不被允许", argv[0], rest[idx])
		}
		rest = append(rest[:idx:idx], rest[idx+1:]...)
	}

	operands := 0
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		if spec.bareFlags[arg] {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			switch {
			case spec.flags[arg]:
			case spec.valueFlags[arg]:
				// 带值选项：消费下一个参数并按操作数规则校验。
				if i+1 >= len(rest) {
					return nil, fmt.Errorf("选项 %q 缺少取值", arg)
				}
				i++
				if !validOperand(spec, rest[i]) {
					return nil, fmt.Errorf("选项 %q 的取值 %q 非法", arg, rest[i])
				}
			case spec.allowShortFlags && shortFlagRe.MatchString(arg):
			default:
				return nil, fmt.Errorf("参数 %q 不在 %s 的允许选项内", arg, argv[0])
			}
			continue
		}
		if !validOperand(spec, arg) {
			return nil, fmt.Errorf("操作数 %q 非法或 %s 不接受操作数", arg, argv[0])
		}
		operands++
		if spec.maxOperands > 0 && operands > spec.maxOperands {
			return nil, fmt.Errorf("%s 的操作数超过 %d 个（疑似写操作而非查询）", argv[0], spec.maxOperands)
		}
	}
	return argv, nil
}

// validOperand 判断操作数是否满足该程序的约束。
func validOperand(spec forensicSpec, arg string) bool {
	if spec.operand == nil {
		// 少数程序（如 ps）不接受操作数，但数字型 PID 参数是常见且无害的用法。
		return numericOperandRe.MatchString(arg)
	}
	return spec.operand.MatchString(arg) || numericOperandRe.MatchString(arg)
}
