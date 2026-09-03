package scheduler

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestVerifyStarted_DetectsMissing 自检必须能发现未启动的调度器。
//
// 这正是它存在的理由：AC 曾有两份初始化文件，规则同步与 IOC 同步只写在
// 没有调用方的那份里，于是两项能力静默缺失数月——没有任何报错，
// 日志、指标、测试全都正常。能发现它的只有"谁真的跑起来了"这个运行时事实。
func TestVerifyStarted_DetectsMissing(t *testing.T) {
	resetRegistryForTest()
	t.Cleanup(resetRegistryForTest)

	// 只登记一部分，模拟漏接线
	MarkStarted("plugin_update")
	MarkStarted("agent_update")

	missing := VerifyStarted(zap.NewNop())
	if len(missing) == 0 {
		t.Fatal("漏了 6 个调度器却报告全部正常——自检形同虚设")
	}
	for _, name := range []string{"ioc_sync", "rule_sync"} {
		if !slices.Contains(missing, name) {
			t.Errorf("%q 未启动却没被列入 missing", name)
		}
	}
}

// TestVerifyStarted_AllPresent 全部登记时不得误报。
//
// 误报的代价是这条自检会被当成噪声关掉，那就退回到没有自检的状态。
func TestVerifyStarted_AllPresent(t *testing.T) {
	resetRegistryForTest()
	t.Cleanup(resetRegistryForTest)

	for _, name := range ExpectedSchedulers {
		MarkStarted(name)
	}
	if missing := VerifyStarted(zap.NewNop()); len(missing) != 0 {
		t.Errorf("全部已启动却报告缺失 %v", missing)
	}
}

// TestEveryExpectedSchedulerRegistersItself 期望清单里的每一项，
// 都必须在本包里有对应的 MarkStarted 调用。
//
// 否则会出现另一种失效：清单登记了某个调度器，但它自己从不 MarkStarted，
// 于是自检永远报它缺失，最后大家学会忽略这条告警。
func TestEveryExpectedSchedulerRegistersItself(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	marked := map[string]bool{}
	re := regexp.MustCompile(`MarkStarted\("([a-z_]+)"\)`)
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", n, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			marked[m[1]] = true
		}
	}

	for _, name := range ExpectedSchedulers {
		if !marked[name] {
			t.Errorf("%q 在 ExpectedSchedulers 里，但没有任何调度器调用 MarkStarted(%q)——"+
				"自检会永远报它缺失", name, name)
		}
	}
}

// TestWiredSchedulersAreExpected 反向校验：本包里 MarkStarted 的每一项
// 都应出现在期望清单中。
//
// 漏登记不会导致能力缺失，但会让自检的覆盖面悄悄缩水——
// 新加的调度器如果没进清单，它哪天不启动了同样没人知道。
func TestWiredSchedulersAreExpected(t *testing.T) {
	dir, _ := os.Getwd()
	entries, _ := os.ReadDir(dir)
	re := regexp.MustCompile(`MarkStarted\("([a-z_]+)"\)`)

	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(dir, n))
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			if !slices.Contains(ExpectedSchedulers, m[1]) {
				t.Errorf("%s 调用了 MarkStarted(%q)，但它不在 ExpectedSchedulers 里——"+
					"请登记，否则它将来不启动也不会被发现", n, m[1])
			}
		}
	}
}

// TestIOCAndRuleSyncAreExpected 点名固定这两项。
//
// 它们是这次事故的当事人：全机群 edr_ioc_count 为 0，
// agent 规则无法热更新。若哪天有人从清单里移除它们，这里会拦下。
func TestIOCAndRuleSyncAreExpected(t *testing.T) {
	for _, name := range []string{"ioc_sync", "rule_sync"} {
		if !slices.Contains(ExpectedSchedulers, name) {
			t.Errorf("%q 必须留在 ExpectedSchedulers 中；"+
				"它曾因只写在无调用方的初始化文件里而静默缺失数月", name)
		}
	}
}
