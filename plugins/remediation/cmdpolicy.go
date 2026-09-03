package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/matrixplusio/mxcwpp/internal/common/execpolicy"
)

// 修复命令的执行边界。
//
// 旧实现是"危险词黑名单 + 前缀白名单 + /bin/sh -c"，这个组合不成立：前缀只约束第一个
// 词，参数空间完全开放，而且只要还经 shell，任何未被列举的语法都是缺口。实测可绕过的
// 例子包括 "yum install foo\n<任意命令>"（换行是 sh 的命令分隔符，旧校验只查 ; | &）、
// "rpm -i /tmp/evil.rpm"、"pip install /tmp/evil.tar.gz"、"apt-get install ./evil.deb"
// （三者都会以 root 跑包内脚本）以及 "dnf install -c /tmp/evil.conf pkg"（改用攻击者仓库）。
//
// 现在改为：切成 argv → 逐项对照允许集 → 不经 shell 直接 exec。未显式允许的
// 程序、子命令、参数一律拒绝。

// pkgOperandRe 约束包名（可带 =版本）。不允许 / 因而排除了本地路径与 URL；
// 不允许以 . 或 - 开头，避免 "./x.deb" 与参数伪装。
var pkgOperandRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*(=[A-Za-z0-9._+:~-]+)?$`)

// serviceOperandRe 约束 systemd 单元名。
var serviceOperandRe = regexp.MustCompile(`^[A-Za-z0-9@._-]+$`)

// pkgFileSuffixes 是包文件后缀。安装本地包文件会以 root 执行包内维护者脚本
// （rpm %post / dpkg maintainer script / python setup.py），等同任意代码执行，一律拒绝。
var pkgFileSuffixes = []string{".rpm", ".deb", ".tar.gz", ".tgz", ".whl", ".zip", ".tar", ".egg"}

// binSpec 描述一个被允许的程序及其可用参数面。
type binSpec struct {
	// subcommands 允许的子命令（argv[1]）。
	subcommands map[string]bool
	// flags 允许的无值选项，精确匹配。
	flags map[string]bool
	// flagPatterns 允许的带值选项，整体正则匹配。
	// 带值选项必须逐个显式放行：--setopt / -c / --installroot / --downloaddir /
	// --repofrompath 都能改写包管理器的取包来源或落地位置，等同任意代码执行，
	// 所以只放行确有运维需要且值域受限的那几个。
	flagPatterns []*regexp.Regexp
	// operand 约束非选项参数。
	operand *regexp.Regexp
	// operandRequired 为 false 时允许无操作数（如 apt-get update）。
	operandRequired bool
}

// setoptSkipUnavailableRe 只放行 --setopt=[<repo>.]skip_if_unavailable=0|1。
// 现网整机更新链依赖它跳过临时不可用的仓库；其余 --setopt（reposdir、gpgcheck、
// installroot 等）一律拒绝，避免把取包来源指向攻击者。
var setoptSkipUnavailableRe = regexp.MustCompile(`^--setopt=([A-Za-z0-9_*.?-]+\.)?skip_if_unavailable=[01]$`)

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// pipOperandRe 约束 pip 包名（可带 ==版本）。同样不允许 /，因而排除本地 sdist 与 URL。
var pipOperandRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?(==[A-Za-z0-9._+!-]+)?$`)

// allowedBins 是允许执行的程序集合。
//
// 刻意不包含 rpm 与 dpkg：它们的安装操作**只接受文件路径**，而安装本地包会以 root
// 运行包内维护者脚本，没有任何操作数形式是安全的——无法通过参数约束挽救，只能移除。
// 需要装包一律走包管理器从已配置仓库按包名取。
//
// pip 保留但操作数收紧到"包名[==版本]"：它的风险同样来自安装本地/远程文件
// （pip install /tmp/evil.tar.gz 会以 root 跑 setup.py），按包名从 PyPI 安装则与
// 信任发行版仓库属于同一层级的信任模型，不应因此砍掉 python 组件的修复能力。
var allowedBins = map[string]binSpec{
	"yum": {
		subcommands:     set("update", "upgrade", "install", "downgrade"),
		flags:           set("-y", "--assumeyes", "-q", "--quiet", "--security", "--bugfix"),
		flagPatterns:    []*regexp.Regexp{setoptSkipUnavailableRe},
		operand:         pkgOperandRe,
		operandRequired: false,
	},
	"dnf": {
		subcommands:     set("update", "upgrade", "install", "downgrade"),
		flags:           set("-y", "--assumeyes", "-q", "--quiet", "--security", "--bugfix"),
		flagPatterns:    []*regexp.Regexp{setoptSkipUnavailableRe},
		operand:         pkgOperandRe,
		operandRequired: false,
	},
	"apt-get": {
		subcommands:     set("install", "update", "upgrade", "dist-upgrade"),
		flags:           set("-y", "--yes", "--assume-yes", "-q", "--quiet", "--only-upgrade", "--no-install-recommends"),
		operand:         pkgOperandRe,
		operandRequired: false,
	},
	"apt": {
		subcommands:     set("install", "update", "upgrade", "full-upgrade"),
		flags:           set("-y", "--yes", "--assume-yes", "-q", "--quiet", "--only-upgrade", "--no-install-recommends"),
		operand:         pkgOperandRe,
		operandRequired: false,
	},
	"pip": {
		subcommands:     set("install"),
		flags:           set("-q", "--quiet", "--upgrade", "-U", "--no-input"),
		operand:         pipOperandRe,
		operandRequired: true,
	},
	"pip3": {
		subcommands:     set("install"),
		flags:           set("-q", "--quiet", "--upgrade", "-U", "--no-input"),
		operand:         pipOperandRe,
		operandRequired: true,
	},
	"systemctl": {
		subcommands:     set("restart", "reload"),
		flags:           set("--no-block"),
		operand:         serviceOperandRe,
		operandRequired: true,
	},
}

// matchesFlagPattern 判断带值选项是否命中允许的整体形式。
func matchesFlagPattern(patterns []*regexp.Regexp, arg string) bool {
	for _, re := range patterns {
		if re.MatchString(arg) {
			return true
		}
	}
	return false
}

// parseRemediationArgv 校验修复命令并返回可直接交给 exec.Command 的 argv。
// 返回的 argv 永远不经 shell 执行。
func parseRemediationArgv(command string) ([]string, error) {
	argv, err := execpolicy.SplitArgv(command)
	if err != nil {
		return nil, err
	}

	spec, ok := allowedBins[argv[0]]
	if !ok {
		return nil, fmt.Errorf("程序 %q 不在允许集内（仅允许 apt/apt-get/yum/dnf/systemctl）", argv[0])
	}
	if len(argv) < 2 {
		return nil, fmt.Errorf("%s 缺少子命令", argv[0])
	}
	if !spec.subcommands[argv[1]] {
		return nil, fmt.Errorf("%s 的子命令 %q 不被允许", argv[0], argv[1])
	}

	operands := 0
	for _, arg := range argv[2:] {
		if strings.HasPrefix(arg, "-") {
			if spec.flags[arg] {
				continue
			}
			if !matchesFlagPattern(spec.flagPatterns, arg) {
				return nil, fmt.Errorf("参数 %q 不在 %s 的允许选项内", arg, argv[0])
			}
			continue
		}
		if !spec.operand.MatchString(arg) {
			return nil, fmt.Errorf("操作数 %q 非法（不允许路径、URL 或特殊字符）", arg)
		}
		lower := strings.ToLower(arg)
		for _, suffix := range pkgFileSuffixes {
			if strings.HasSuffix(lower, suffix) {
				return nil, fmt.Errorf("拒绝安装本地包文件 %q（包内维护者脚本会以 root 执行）", arg)
			}
		}
		operands++
	}

	if spec.operandRequired && operands == 0 {
		return nil, fmt.Errorf("%s %s 缺少操作数", argv[0], argv[1])
	}
	return argv, nil
}
