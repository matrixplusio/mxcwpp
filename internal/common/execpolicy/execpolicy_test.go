package execpolicy

import (
	"strings"
	"testing"
)

// TestValidateNoControlChars 换行/回车/NUL 必须被拒。
// sh -c 把 \n 与 \r 当作命令分隔符，只检查 ; | & 的校验器会放行
// "yum install foo\n<任意命令>"，这是实测可用的注入路径。
func TestValidateNoControlChars(t *testing.T) {
	bad := []string{
		"yum install foo\ntouch /tmp/pwned",
		"yum install foo\rtouch /tmp/pwned",
		"yum install foo\x00rm -rf /",
		"yum install \x1b[31mfoo",
	}
	for _, s := range bad {
		if err := ValidateNoControlChars(s); err == nil {
			t.Errorf("ValidateNoControlChars(%q) 应拒绝", s)
		}
	}
	if err := ValidateNoControlChars("yum install foo -y"); err != nil {
		t.Errorf("正常命令被误拒: %v", err)
	}
	if err := ValidateNoControlChars("a\tb"); err != nil {
		t.Errorf("制表符应放行: %v", err)
	}
}

// TestSplitArgv_RejectsStructuralMeta 能改变命令结构的元字符一律拒绝。
func TestSplitArgv_RejectsStructuralMeta(t *testing.T) {
	for _, s := range []string{
		"a; b", "a | b", "a && b", "a $(b)", "a `b`", "a > f", "a < f",
		`a "b"`, "a 'b'", `a \; b`,
	} {
		if _, err := SplitArgv(s); err == nil {
			t.Errorf("SplitArgv(%q) 应拒绝", s)
		}
	}
}

// TestSplitArgv_AllowsGlobChars 通配符不经 shell 不会展开，属普通字面量，
// 拒掉会误伤 dnf --setopt=*.skip_if_unavailable=1 这类现网参数。
func TestSplitArgv_AllowsGlobChars(t *testing.T) {
	argv, err := SplitArgv("dnf upgrade -y --setopt=*.skip_if_unavailable=1")
	if err != nil {
		t.Fatalf("通配符参数被误拒: %v", err)
	}
	if len(argv) != 4 || argv[3] != "--setopt=*.skip_if_unavailable=1" {
		t.Fatalf("argv = %v", argv)
	}
}

// TestSplitArgv_Basics 空命令与超长命令。
func TestSplitArgv_Basics(t *testing.T) {
	if _, err := SplitArgv("   "); err == nil {
		t.Error("空命令应拒绝")
	}
	if _, err := SplitArgv(strings.Repeat("a", MaxCommandLen+1)); err == nil {
		t.Error("超长命令应拒绝")
	}
}
