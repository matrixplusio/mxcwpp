package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrePushGateExists 推送闸门必须存在，且默认拒绝。
//
// 仓库里其余门禁检查的都是「内容对不对」——有没有生产标识、包有没有接线、
// 路由有没有登记。没有一道管「顺序对不对」。而 CLAUDE.md 的开发流程里
// 最要紧的一条恰恰是顺序：先上生产验证，再推 GitHub，因为部署可以回滚、
// 推送不可收回。2026-09-04 这条规则被违反了两次，理由是「CI 绿了就该推」——
// 一条没人定过的标准。
//
// 这道测试不能保证任何人真的走了第 7 步，它只保证那个默认拒绝的闸还在：
// 推送得是一个显式做出、留下痕迹的动作，而不是顺手。
func TestPrePushGateExists(t *testing.T) {
	root := repoRootFromDeploy(t)
	path := filepath.Join(root, ".githooks", "pre-push")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf(".githooks/pre-push 不见了：%v\n"+
			"没有它，推送就退回到全靠自觉——而自觉已经失效过。", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error(".githooks/pre-push 没有可执行位，git 不会调用它——" +
			"闸门看着在，实际不生效")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)

	// 闸门的写法可以变，这三件事不能没有。
	for _, want := range []struct{ needle, why string }{
		{"github.com", "必须只拦 GitHub，本地与备份 remote 不该被挡"},
		{"push-approval", "必须要求一个显式的批准记录，否则默认就是放行"},
		{"exit 1", "没有批准时必须以非零退出，否则拦不住任何东西"},
		{"leakscan.sh", "必须先过内容扫描，批准记录不能替代它"},
		{".production-identifiers", "本地字典缺席时必须拒绝，否则扫描悄悄变弱"},
	} {
		if !strings.Contains(script, want.needle) {
			t.Errorf("pre-push 里找不到 %q：%s", want.needle, want.why)
		}
	}

	// 一次批准只能放行一次，否则它会变成长期敞开的后门。
	if !strings.Contains(script, `rm -f "$approval_file"`) {
		t.Error("批准记录没有用后即焚；留着它，第一次批准会永久放行后续所有推送")
	}
}

// TestPrePushBlocksLeaks 用真实 git 仓库跑 pre-push，钉住内容扫描的几条硬性质。
//
// 只检查脚本里「有没有这几个词」挡不住逻辑写错。这里模拟 git 调用 hook 的方式
// （参数是 remote 名与 URL，stdin 是待推引用），逐条验证：
//   - 批准记录放不过内容扫描；
//   - 旧 commit 里出过、后来删掉的内容照样拦——它们一样会被推出去；
//   - commit message 也在扫描范围内；
//   - 本地字典里的名字会被拦，字典缺失时拒绝推送；
//   - 干净的内容加上批准记录可以推，非 GitHub 的 remote 不受影响。
func TestPrePushBlocksLeaks(t *testing.T) {
	root := repoRootFromDeploy(t)
	const githubURL = "git@github.com:example/example.git"

	type commit struct{ file, content, msg string }
	cases := []struct {
		name     string
		commits  []commit
		noDict   bool
		url      string
		wantPass bool
	}{
		{name: "生产数字，即使已批准", commits: []commit{
			{"a.go", "// prod 实测 1234 台主机计数器全为 0\n", "fix: a"}, // leakscan:example
		}},
		{name: "旧 commit 出现过、新 commit 已删掉", commits: []commit{
			{"a.go", "// 生产上曾有 11,111 条关联被误判\n", "fix: a"}, // leakscan:example
			{"a.go", "// 大部分关联会被误判\n", "fix: reword"},
		}},
		{name: "commit message", commits: []commit{
			{"a.go", "package a\n", "fix: prod 实测 999 台全部掉线"}, // leakscan:example
		}},
		{name: "本地字典里的名字", commits: []commit{
			{"a.go", "// see acme-internal-node-01\n", "fix: a"}, // leakscan:example
		}},
		{name: "不该公开的文件", commits: []commit{
			{"local-reports/notes.md", "hi\n", "docs: notes"},
		}},
		{name: "字典缺失", noDict: true, commits: []commit{
			{"a.go", "package a\n", "fix: a"},
		}},
		{name: "干净且已批准", wantPass: true, commits: []commit{
			{"a.go", "package a\n", "fix: a"},
		}},
		{name: "非 GitHub remote 不管", url: "/srv/backup.git", wantPass: true, commits: []commit{
			{"a.go", "// prod 实测 1234 台\n", "fix: a"}, // leakscan:example
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			git := func(args ...string) string {
				t.Helper()
				cmd := exec.Command("git", args...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null",
					"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
					"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
				return strings.TrimSpace(string(out))
			}
			git("init", "-q", "-b", "main")
			for _, f := range []string{"pre-push", "leakscan.sh", "prod-claim-patterns"} {
				copyFile(t, filepath.Join(root, ".githooks", f), filepath.Join(dir, ".githooks", f))
			}
			if !tc.noDict {
				writeFile(t, filepath.Join(dir, ".production-identifiers"), "acme-internal-\n")
			}
			for _, c := range tc.commits {
				writeFile(t, filepath.Join(dir, c.file), c.content)
				git("add", c.file)
				git("commit", "-q", "--no-verify", "-m", c.msg)
			}
			head := git("rev-parse", "HEAD")
			writeFile(t, filepath.Join(dir, ".git", "push-approval"), head+"\n")

			url := tc.url
			if url == "" {
				url = githubURL
			}
			cmd := exec.Command("bash", ".githooks/pre-push", "origin", url)
			cmd.Dir = dir
			cmd.Stdin = strings.NewReader("refs/heads/main " + head + " refs/heads/main " + strings.Repeat("0", 40) + "\n")
			out, err := cmd.CombinedOutput()
			if tc.wantPass && err != nil {
				t.Fatalf("应放行却被拦下：\n%s", out)
			}
			if !tc.wantPass && err == nil {
				t.Fatalf("应拦下却放行了：\n%s", out)
			}
		})
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
