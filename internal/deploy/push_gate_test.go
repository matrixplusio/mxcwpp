package deploy

import (
	"os"
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
