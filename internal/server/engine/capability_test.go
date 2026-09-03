package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("未找到仓库根，跳过")
		}
		dir = parent
	}
}

var stageCtorRe = regexp.MustCompile(`func (New\w*Stage)\(`)

// declaredConstructors 扫描本包内实际定义的 Stage 构造器。
func declaredConstructors(t *testing.T) map[string]bool {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "internal", "server", "engine")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read engine dir: %v", err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range stageCtorRe.FindAllStringSubmatch(string(data), -1) {
			out[m[1]] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("未扫描到任何 Stage 构造器——正则或目录结构已变，测试失效")
	}
	return out
}

// wiredConstructors 扫描引擎入口实际接进流水线的构造器。
func wiredConstructors(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "cmd", "server", "engine", "main.go"))
	if err != nil {
		t.Fatalf("read engine main: %v", err)
	}
	re := regexp.MustCompile(`stages = append\(stages, engine\.(New\w*Stage)\(`)
	out := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatal("未扫描到任何已接线 Stage——入口写法已变，测试失效")
	}
	return out
}

// TestCapabilityManifest_CoversEveryConstructor 每个 Stage 构造器都必须在清单里登记。
//
// 漏登记意味着一项能力游离在事实基线之外：没人知道它是在跑、还是死代码，
// 而对外宣称能力时正是照着清单说的。
func TestCapabilityManifest_CoversEveryConstructor(t *testing.T) {
	declared := declaredConstructors(t)
	inManifest := map[string]bool{}
	for _, c := range Capabilities {
		inManifest[c.Constructor] = true
	}

	for ctor := range declared {
		if !inManifest[ctor] {
			t.Errorf("构造器 %s 未在能力清单中登记", ctor)
		}
	}
	for ctor := range inManifest {
		if !declared[ctor] {
			t.Errorf("清单登记了 %s，但代码中不存在该构造器（陈旧条目）", ctor)
		}
	}
}

// TestCapabilityManifest_WiringMatchesReality 清单声明的接线状态必须与入口代码一致。
//
// 两个方向都要查：声明已接线却没接，是清单在吹；声明未接线却接了，
// 是能力在没被登记的情况下悄悄上线，同样不可接受。
func TestCapabilityManifest_WiringMatchesReality(t *testing.T) {
	wired := wiredConstructors(t)
	for _, c := range Capabilities {
		actuallyWired := wired[c.Constructor]
		switch {
		case c.Wired() && !actuallyWired:
			t.Errorf("%s 声明为已接线（status=%s），但引擎入口未接入", c.Name, c.Status)
		case !c.Wired() && actuallyWired:
			t.Errorf("%s 声明为未接线，但引擎入口已接入——请更新清单状态与告警去向", c.Name)
		}
	}
}

// TestCapabilityManifest_DeadEndSinkHasNoConsumer 标为 dead_end 的能力，
// 其告警去向必须确实无人消费；一旦补上消费端，本测试会提示把状态改回 active。
func TestCapabilityManifest_DeadEndSinkHasNoConsumer(t *testing.T) {
	var hasDeadEnd bool
	for _, c := range Capabilities {
		if c.Status == StatusDeadEnd {
			hasDeadEnd = true
			if c.Sink == SinkNone {
				t.Errorf("%s 标为 dead_end 却没有告警去向，状态自相矛盾", c.Name)
			}
			if c.Note == "" {
				t.Errorf("%s 标为 dead_end 必须说明原因，否则无人知道缺什么", c.Name)
			}
		}
	}
	if !hasDeadEnd {
		return
	}
	if consumesEngineAlertTopic(t) {
		t.Error("mxcwpp.engine.alert 已有消费者，dead_end 能力应重新评估为 active 并更新清单")
	}
}

// consumesEngineAlertTopic 判断是否已有代码订阅 engine.alert。
func consumesEngineAlertTopic(t *testing.T) bool {
	t.Helper()
	root := repoRoot(t)
	found := false
	for _, dir := range []string{
		filepath.Join(root, "internal", "server", "consumer"),
		filepath.Join(root, "cmd", "server", "consumer"),
	} {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			if strings.Contains(string(data), "TopicEngineAlert") {
				found = true
			}
			return nil
		})
	}
	return found
}

// TestCapabilityManifest_SummaryMatchesEntries 摘要必须由清单算出，不得手写偏离。
func TestCapabilityManifest_SummaryMatchesEntries(t *testing.T) {
	s := SummarizeCapabilities()
	if s.Total != len(Capabilities) {
		t.Errorf("Total=%d，清单实际 %d 条", s.Total, len(Capabilities))
	}
	if s.Active+s.DeadEnd+s.Starved+s.Unwired != s.Total {
		t.Errorf("分档合计 %d 与总数 %d 不符（存在未归档状态）",
			s.Active+s.DeadEnd+s.Starved+s.Unwired, s.Total)
	}
	if s.Declared != s.Active {
		t.Errorf("可对外宣称数 %d 应等于 active 数 %d——dead_end / starved / unwired 都不得宣称",
			s.Declared, s.Active)
	}
}

// TestCapabilitiesEndpoint 清单必须能被机器读取——方案要求"产出并发布"，
// 只存在于源码里的清单没法被运维或交付流程核对。
func TestCapabilitiesEndpoint(t *testing.T) {
	h := NewHTTPHandler(zap.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/capabilities", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", rec.Code)
	}
	var body struct {
		Summary      CapabilitySummary `json:"summary"`
		Capabilities []Capability      `json:"capabilities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非合法 JSON: %v", err)
	}
	if len(body.Capabilities) != len(Capabilities) {
		t.Errorf("接口返回 %d 项，清单 %d 项", len(body.Capabilities), len(Capabilities))
	}
	if body.Summary.Declared != SummarizeCapabilities().Active {
		t.Error("摘要中可宣称数与 active 数不一致")
	}
	// 不可用的能力必须带上原因，否则读到清单的人不知道缺什么。
	for _, c := range body.Capabilities {
		if c.Status == StatusDeadEnd && c.Note == "" {
			t.Errorf("%s 为 dead_end 但未说明原因", c.Name)
		}
	}
}

// TestCapabilityManifest_StarvedHasNote starved 必须说明缺的是哪个输入。
//
// 这一档描述的是"结构完整、管道为空"——Stage 注册了、指标导出了、状态表建了，
// 唯独没有任何采集器产生它要读的字段。这种失效不会报错、不会变慢，
// 只会永远是零条，所以清单里必须写清楚缺什么，否则下一个人只会看到
// 一个"已接线"的能力和一片空数据，重新把已经查过的路再走一遍。
func TestCapabilityManifest_StarvedHasNote(t *testing.T) {
	for _, c := range Capabilities {
		if c.Status != StatusStarved {
			continue
		}
		if c.Note == "" {
			t.Errorf("%s 标为 starved 却没有 Note，必须写明缺失的输入是什么", c.Name)
		}
	}
}

// TestCapabilityManifest_StarvedIsNotDeclarable starved 不得计入可对外宣称的能力。
func TestCapabilityManifest_StarvedIsNotDeclarable(t *testing.T) {
	for _, c := range Capabilities {
		if c.Status == StatusStarved && c.Usable() {
			t.Errorf("%s 是 starved 却被判为 Usable——它从未产出过任何结果，不能对外宣称", c.Name)
		}
	}
}
