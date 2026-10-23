package notify

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 通知里「查看详情」指向的页面必须真实存在：前端对不存在的路径退回首页，
// 用户点开只看到安全概览，曾有四类通知都是这样。
func TestNotificationLinksExist(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	var src []byte
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src = append(src, b...)
	}
	// 形如 "%s/alert-center/alerts?id=%d"、base + "/alert-center/alerts"
	re := regexp.MustCompile(`(?:"%s|base \+ ")(/[a-z0-9\-/]+)`)
	found := 0
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		found++
		route := strings.TrimSuffix(m[1], "/")
		page := filepath.Join("..", "..", "..", "web", "src", "app", "(console)", route, "page.tsx")
		if _, err := os.Stat(page); err != nil {
			t.Errorf("通知链接 %s 没有对应的前端页面（%s）", route, page)
		}
	}
	if found < 5 {
		t.Fatalf("只找到 %d 个通知链接，匹配规则可能失效", found)
	}
}

func TestAlertSourceCategory(t *testing.T) {
	cases := map[string]model.NotifyCategory{
		model.AlertSourceDetection:       model.NotifyCategoryDetection,
		model.AlertSourcePrometheusInfra: model.NotifyCategoryInfraAlert,
		model.AlertSourceBaseline:        model.NotifyCategoryBaselineAlert,
		"":                               model.NotifyCategoryBaselineAlert,
		model.AlertSourceBehavior:        model.NotifyCategoryBehaviorAlert, // 灰度类别，统一出口按 notify_categories 判断
	}
	for src, want := range cases {
		if got := alertSourceCategory(src); got != want {
			t.Errorf("alertSourceCategory(%q) = %q, want %q", src, got, want)
		}
	}
}

// 没有主机的类别，测试卡片不应带业务线：真实告警不会有，测试样例要和真实一致。
func TestSampleEventNoHostNoBusinessLine(t *testing.T) {
	for _, c := range []model.NotifyCategory{model.NotifyCategoryInfraAlert, model.NotifyCategoryKubeAlert} {
		if m := SampleEvent(c); m.HostID != "" || m.Hostname != "" || m.BusinessLine != "" || m.IP != "" {
			t.Errorf("%s 测试样例带了主机信息: %+v", c, m)
		}
	}
}
