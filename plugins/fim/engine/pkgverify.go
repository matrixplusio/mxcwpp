package engine

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

// 包管理器对照：区分「升级改写」与「被人替换」。
//
// 哈希变了本身说明不了什么——dnf-automatic 之类的无人值守更新每天都在改写 /usr/bin。
// 唯一可靠的判据是包数据库：文件属于某个包，且与包数据库记录的摘要/属性一致，
// 就是包管理器写进去的。不一致、不属于任何包、或者校验跑不起来，一律保持原级别。
//
// 局限：拿到 root 的攻击者可以连包数据库一起改，这条判据防不住它；
// 它解决的是「例行升级淹没真告警」，不是替代完整性校验本身。

const (
	pkgVerifyCmdTimeout = 60 * time.Second
	// pkgVerifyMaxPackages 单轮最多校验的包数。一次大版本升级可能动上千个包，
	// 超出部分保持原级别（宁可多报），不让一轮扫描被校验拖住。
	pkgVerifyMaxPackages = 300
)

// cmdRunner 执行外部命令，返回合并输出与退出码；命令根本没跑起来时返回 error。
type cmdRunner func(ctx context.Context, name string, args ...string) (out string, exitCode int, err error)

func execRunner(ctx context.Context, name string, args ...string) (string, int, error) {
	cctx, cancel := context.WithTimeout(ctx, pkgVerifyCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && cctx.Err() == nil {
			return string(out), ee.ExitCode(), nil
		}
		return string(out), -1, err
	}
	return string(out), 0, nil
}

// PkgVerifier 判断哪些变更文件与包数据库一致。
type PkgVerifier struct {
	logger   *zap.Logger
	run      cmdRunner
	lookPath func(string) (string, error)
}

// NewPkgVerifier 创建校验器。
func NewPkgVerifier(logger *zap.Logger) *PkgVerifier {
	return &PkgVerifier{logger: logger, run: execRunner, lookPath: exec.LookPath}
}

// Verify 返回「与包数据库一致」的路径 → 所属包。不在结果里的路径一律视为未通过。
//
// metaChanged 标出哪些路径动了权限或属主：dpkg --verify 只校验摘要，
// 这类变更它看不见，不能据此判一致。
func (v *PkgVerifier) Verify(ctx context.Context, paths []string, metaChanged map[string]bool) map[string]string {
	if len(paths) == 0 {
		return nil
	}
	switch {
	case v.has("rpm"):
		return v.verifyWith(ctx, paths, v.rpmOwner, v.rpmVerify, nil)
	case v.has("dpkg"):
		return v.verifyWith(ctx, paths, v.dpkgOwner, v.dpkgVerify, metaChanged)
	}
	return nil
}

func (v *PkgVerifier) has(bin string) bool {
	_, err := v.lookPath(bin)
	return err == nil
}

func (v *PkgVerifier) verifyWith(
	ctx context.Context, paths []string,
	owner func(context.Context, string) []string,
	verify func(context.Context, string) (map[string]bool, bool),
	metaChanged map[string]bool,
) map[string]string {
	byPkg := map[string][]string{}
	var order []string
	for _, p := range paths {
		if metaChanged[p] {
			continue
		}
		pkgs := owner(ctx, p)
		// 多个包同时声明拥有一个文件时无法确定以谁为准，按未通过处理。
		if len(pkgs) != 1 {
			continue
		}
		if _, seen := byPkg[pkgs[0]]; !seen {
			order = append(order, pkgs[0])
		}
		byPkg[pkgs[0]] = append(byPkg[pkgs[0]], p)
	}

	out := map[string]string{}
	for i, pkg := range order {
		if i >= pkgVerifyMaxPackages {
			v.logger.Warn("变更涉及的包过多，其余保持原级别",
				zap.Int("packages", len(order)), zap.Int("limit", pkgVerifyMaxPackages))
			break
		}
		bad, ok := verify(ctx, pkg)
		if !ok {
			continue
		}
		for _, p := range byPkg[pkg] {
			if !bad[p] {
				out[p] = pkg
			}
		}
	}
	return out
}

// rpmOwner 返回拥有该路径的包（NVRA）。
func (v *PkgVerifier) rpmOwner(ctx context.Context, path string) []string {
	out, code, err := v.run(ctx, "rpm", "-qf", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n", "--", path)
	if err != nil || code != 0 {
		return nil
	}
	return nonEmptyLines(out)
}

// rpmVerify 校验整个包，返回不一致的文件集合；第二个返回值表示结果可信。
func (v *PkgVerifier) rpmVerify(ctx context.Context, pkg string) (map[string]bool, bool) {
	out, _, err := v.run(ctx, "rpm", "-V", "--", pkg)
	if err != nil {
		return nil, false
	}
	// rpm -V 有不一致就返回非零，退出码区分不了「有文件被改」和「出错了」，只能看输出：
	// 每一行都必须是校验结果行，出现任何别的内容（包没装、数据库损坏）都不可信。
	return parseVerifyOutput(out)
}

// dpkgOwner 返回拥有该路径的包。
//
// usrmerge 的系统上 dpkg 记录的是 /bin/ls 而不是 /usr/bin/ls，按实际路径查不到归属，
// 这类文件保持原级别——宁可少降级，不按别名猜。
func (v *PkgVerifier) dpkgOwner(ctx context.Context, path string) []string {
	out, code, err := v.run(ctx, "dpkg", "-S", "--", path)
	if err != nil || code != 0 {
		return nil
	}
	for _, line := range nonEmptyLines(out) {
		if strings.HasPrefix(line, "diversion ") {
			continue
		}
		i := strings.LastIndex(line, ": ")
		if i < 0 || line[i+2:] != path {
			continue
		}
		var pkgs []string
		for _, p := range strings.Split(line[:i], ",") {
			if p = strings.TrimSpace(p); p != "" {
				pkgs = append(pkgs, p)
			}
		}
		return pkgs
	}
	return nil
}

func (v *PkgVerifier) dpkgVerify(ctx context.Context, pkg string) (map[string]bool, bool) {
	out, code, err := v.run(ctx, "dpkg", "--verify", "--", pkg)
	if err != nil || (code != 0 && strings.TrimSpace(out) == "") {
		return nil, false
	}
	return parseVerifyOutput(out)
}

// parseVerifyOutput 解析 rpm -V / dpkg --verify 的输出（两者格式相同）：
//
//	S.5....T.  c /etc/foo.conf
//	??5??????    /usr/bin/bar
//	missing   c /etc/baz
func parseVerifyOutput(out string) (map[string]bool, bool) {
	bad := map[string]bool{}
	for _, line := range nonEmptyLines(out) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, false
		}
		attr := fields[0]
		if attr != "missing" && !isVerifyAttr(attr) {
			return nil, false
		}
		path := fields[len(fields)-1]
		if !strings.HasPrefix(path, "/") {
			return nil, false
		}
		bad[path] = true
	}
	return bad, true
}

// isVerifyAttr 校验结果的属性列：9 位（dpkg 为 9 位，rpm 为 8–9 位），每位是 . ? 或大写/数字标记。
func isVerifyAttr(s string) bool {
	if len(s) < 8 || len(s) > 9 {
		return false
	}
	for _, c := range s {
		if c != '.' && c != '?' && !(c >= 'A' && c <= 'Z') && c != '5' {
			return false
		}
	}
	return true
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
