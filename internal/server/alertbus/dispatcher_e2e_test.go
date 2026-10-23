package alertbus

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/notify"
)

// 按业务线分群：两条 Web 业务线进同一个群，支付业务线进另一个群，全局群都收；
// 没有主机的告警（基础设施）只进全局群。走真实的通知服务与 HTTP 发送。
func TestDispatch_BusinessLineRouting(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]string{} // 路径 → 收到的标题
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got[r.URL.Path] = append(got[r.URL.Path], body["title"].(string))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	db, c := newTestDB(t), newClock()
	for _, ddl := range []string{
		`CREATE TABLE hosts (host_id TEXT PRIMARY KEY, hostname TEXT, ipv4 TEXT, business_line TEXT, tags TEXT)`,
		`CREATE TABLE notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, name TEXT, description TEXT,
			notify_category TEXT, enabled INTEGER, type TEXT, severities TEXT, scope TEXT, scope_value TEXT,
			frontend_url TEXT, config TEXT, created_at DATETIME, updated_at DATETIME)`,
		`INSERT INTO hosts (host_id, hostname, business_line) VALUES ('h-web', 'web-01', 'BL-WEB-A'), ('h-pay', 'pay-01', 'BL-PAY')`,
	} {
		if err := db.Exec(ddl).Error; err != nil {
			t.Fatal(err)
		}
	}
	scope := func(bls ...string) string {
		b, _ := json.Marshal(model.ScopeValueData{BusinessLines: bls})
		return string(b)
	}
	for _, ch := range []struct {
		path, scopeType, scopeValue string
	}{
		{"/web", string(model.NotificationScopeBusinessLine), scope("BL-WEB-A", "BL-WEB-B")},
		{"/pay", string(model.NotificationScopeBusinessLine), scope("BL-PAY")},
		{"/all", string(model.NotificationScopeGlobal), ""},
	} {
		if err := db.Create(&model.Notification{
			Name: ch.path, NotifyCategory: model.NotifyCategoryDetection, Enabled: true, Type: model.NotificationTypeWebhook,
			Severities: model.StringArray{"critical"}, Scope: model.NotificationScope(ch.scopeType), ScopeValue: ch.scopeValue,
			Config: model.NotificationConfig{WebhookURL: srv.URL + ch.path},
		}).Error; err != nil {
			t.Fatal(err)
		}
	}

	for _, e := range []Event{
		{Category: model.NotifyCategoryDetection, Source: "cel", HostID: "h-web", Severity: "critical", Title: "web-告警", DedupKey: "a"},
		{Category: model.NotifyCategoryDetection, Source: "cel", HostID: "h-pay", Severity: "critical", Title: "pay-告警", DedupKey: "b"},
		{Category: model.NotifyCategoryDetection, Source: "prom", Severity: "critical", Title: "无主机告警", DedupKey: "c"},
	} {
		publish(t, db, c, e)
	}

	svc := notify.NewNotificationService(db, nil)
	svc.SetHTTPClient(srv.Client()) // 本地假 webhook 在 SSRF 受限网段内
	d := NewDispatcher(db, nil, enabled(model.NotifyCategoryDetection))
	d.notify = svc
	d.now = c.now
	d.DispatchOnce()

	var hostnames []string
	db.Model(&model.AlertNotifyEvent{}).Order("id").Pluck("hostname", &hostnames)
	if len(hostnames) != 3 || hostnames[0] != "web-01" || hostnames[1] != "pay-01" || hostnames[2] != "" {
		t.Fatalf("分发时补全的主机名应写回事件行（通知记录页靠它显示）: %v", hostnames)
	}

	mu.Lock()
	defer mu.Unlock()
	want := map[string][]string{
		"/web": {"web-告警"},
		"/pay": {"pay-告警"},
		"/all": {"web-告警", "pay-告警", "无主机告警"},
	}
	for path, titles := range want {
		if len(got[path]) != len(titles) {
			t.Fatalf("%s 收到 %v，期望 %v", path, got[path], titles)
		}
		for i := range titles {
			if got[path][i] != titles[i] {
				t.Fatalf("%s 收到 %v，期望 %v", path, got[path], titles)
			}
		}
	}
}
