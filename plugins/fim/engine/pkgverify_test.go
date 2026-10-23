package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeRunner 按「命令 + 参数」返回预设输出。
type fakeRunner map[string]struct {
	out  string
	code int
}

func (f fakeRunner) run(_ context.Context, name string, args ...string) (string, int, error) {
	key := name + " " + strings.Join(args, " ")
	r, ok := f[key]
	if !ok {
		return "", 1, nil
	}
	return r.out, r.code, nil
}

func newFakeVerifier(bin string, f fakeRunner) *PkgVerifier {
	return &PkgVerifier{
		logger: zap.NewNop(),
		run:    f.run,
		lookPath: func(b string) (string, error) {
			if b == bin {
				return "/usr/bin/" + b, nil
			}
			return "", errors.New("not found")
		},
	}
}

const rpmQF = "rpm -qf --qf %{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n -- "

// TestRPM_UpgradeVsTamper 升级改写的文件判一致；同包内被改过的、不属于任何包的都不算。
func TestRPM_UpgradeVsTamper(t *testing.T) {
	v := newFakeVerifier("rpm", fakeRunner{
		rpmQF + "/usr/bin/ls":    {out: "coreutils-8.32-35.el9.x86_64\n"},
		rpmQF + "/usr/bin/cat":   {out: "coreutils-8.32-35.el9.x86_64\n"},
		rpmQF + "/usr/bin/evil":  {out: "file /usr/bin/evil is not owned by any package\n", code: 1},
		rpmQF + "/usr/sbin/sshd": {out: "openssh-server-8.7p1-38.el9.x86_64\n"},
		// cat 被人改过：rpm -V 列出它，非零退出
		"rpm -V -- coreutils-8.32-35.el9.x86_64": {out: "S.5....T.    /usr/bin/cat\n", code: 1},
		// 包数据库读不出来：输出不是校验行，整个包不可信
		"rpm -V -- openssh-server-8.7p1-38.el9.x86_64": {out: "error: rpmdb: damaged header\n", code: 1},
	})
	got := v.Verify(context.Background(), []string{"/usr/bin/ls", "/usr/bin/cat", "/usr/bin/evil", "/usr/sbin/sshd"}, nil)
	if len(got) != 1 || got["/usr/bin/ls"] != "coreutils-8.32-35.el9.x86_64" {
		t.Fatalf("只有 /usr/bin/ls 应判一致，实际 %v", got)
	}
}

// TestDPKG_MetaChangeNotTrusted dpkg --verify 只看摘要，权限/属主变更不能据此判一致。
func TestDPKG_MetaChangeNotTrusted(t *testing.T) {
	v := newFakeVerifier("dpkg", fakeRunner{
		"dpkg -S -- /usr/bin/ls":     {out: "coreutils: /usr/bin/ls\n"},
		"dpkg -S -- /usr/bin/sudo":   {out: "sudo: /usr/bin/sudo\n"},
		"dpkg -S -- /usr/bin/multi":  {out: "a, b: /usr/bin/multi\n"},
		"dpkg --verify -- coreutils": {},
		"dpkg --verify -- sudo":      {},
	})
	got := v.Verify(context.Background(),
		[]string{"/usr/bin/ls", "/usr/bin/sudo", "/usr/bin/multi"},
		map[string]bool{"/usr/bin/sudo": true})
	if len(got) != 1 || got["/usr/bin/ls"] != "coreutils" {
		t.Fatalf("只有 /usr/bin/ls 应判一致（sudo 动了权限、multi 归属不唯一），实际 %v", got)
	}
}

// TestNoPackageManager 没有包管理器时什么都不判，保持原级别。
func TestNoPackageManager(t *testing.T) {
	v := newFakeVerifier("none", fakeRunner{})
	if got := v.Verify(context.Background(), []string{"/usr/bin/ls"}, nil); len(got) != 0 {
		t.Fatalf("无包管理器不应判一致，实际 %v", got)
	}
}

func TestParseVerifyOutput(t *testing.T) {
	bad, ok := parseVerifyOutput("S.5....T.  c /etc/foo.conf\nmissing   /usr/lib/x.so\n??5??????   /usr/bin/bar\n")
	if !ok || !bad["/etc/foo.conf"] || !bad["/usr/lib/x.so"] || !bad["/usr/bin/bar"] {
		t.Fatalf("解析错误: ok=%v bad=%v", ok, bad)
	}
	if _, ok := parseVerifyOutput("package foo is not installed\n"); ok {
		t.Fatal("非校验行应判不可信")
	}
}

// TestMarkStale 基线过期这一轮只降不丢：critical/high 压到 medium，其余不动，全部打标。
func TestMarkStale(t *testing.T) {
	evs := []FIMEvent{{Severity: "critical"}, {Severity: "high"}, {Severity: "low"}, {Severity: "info"}}
	markStale(evs, time.Now().Add(-100*time.Hour))
	want := []string{"medium", "medium", "low", "info"}
	for i, ev := range evs {
		if ev.Severity != want[i] || !ev.ChangeDetail.BaselineStale || ev.ChangeDetail.LastScanAt == "" {
			t.Errorf("事件 %d: severity=%s stale=%v", i, ev.Severity, ev.ChangeDetail.BaselineStale)
		}
	}
}
