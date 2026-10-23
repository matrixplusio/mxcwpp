package gcppubsub

import (
	"strconv"
	"strings"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// 审计日志里的集群名是 GKE 的真实集群名，平台登记名是人起的，两者通常不同。
// 原先只按登记名匹配，所有消息都被当成「集群未接入」丢掉。
func TestFindClusterByGKEName(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// kube_clusters 的 updated_at 带 MySQL 专有的 ON UPDATE，sqlite 建不了；只建匹配用到的列。
	if err := db.Exec("CREATE TABLE kube_clusters (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, " +
		"gcp_enabled BOOLEAN, gcp_project_id TEXT, gcp_subscription TEXT, gcp_cluster_name TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	for _, row := range [][]any{
		{"app-cluster", true, "p-prod", "sub-prod", "gke-app-cluster-a"},
		{"gke-test-cluster-b", true, "p-uat", "sub-uat", ""}, // 没填 GKE 名，登记名就是 GKE 名
		{"off-cluster", false, "p-prod", "sub-prod", "off-gke"},
	} {
		if err := db.Exec("INSERT INTO kube_clusters (name, gcp_enabled, gcp_project_id, gcp_subscription, gcp_cluster_name) VALUES (?, ?, ?, ?, ?)", row...).Error; err != nil {
			t.Fatal(err)
		}
	}
	consumer := func(sub string) *Consumer {
		return NewConsumer(ClusterGCPConfig{Subscription: sub}, db, zap.NewNop(), nil)
	}

	if c, err := consumer("sub-prod").findCluster(LogResourceLabels{ClusterName: "gke-app-cluster-a", ProjectID: "p-prod"}); err != nil || c.Name != "app-cluster" {
		t.Errorf("应按 GKE 集群名匹配到 app-cluster：%q err=%v", c.Name, err)
	}
	if c, err := consumer("sub-uat").findCluster(LogResourceLabels{ClusterName: "gke-test-cluster-b", ProjectID: "p-uat"}); err != nil || c.Name != "gke-test-cluster-b" {
		t.Errorf("没填 GKE 名时应回退到登记名：%q err=%v", c.Name, err)
	}
	for name, tc := range map[string]struct {
		sub    string
		labels LogResourceLabels
	}{
		"项目不符":             {"sub-prod", LogResourceLabels{ClusterName: "gke-app-cluster-a", ProjectID: "p-other"}},
		"订阅不符":             {"sub-uat", LogResourceLabels{ClusterName: "gke-app-cluster-a", ProjectID: "p-prod"}},
		"未启用 GCP 审计":       {"sub-prod", LogResourceLabels{ClusterName: "off-gke", ProjectID: "p-prod"}},
		"填了 GKE 名后登记名不再算数": {"sub-prod", LogResourceLabels{ClusterName: "app-cluster", ProjectID: "p-prod"}},
	} {
		if _, err := consumer(tc.sub).findCluster(tc.labels); err != gorm.ErrRecordNotFound {
			t.Errorf("%s：不该匹配上，err=%v", name, err)
		}
	}
}

// 匹配不上的告警限频，且限频表不能被消息内容撑到无界。
func TestWarnUnmatchedBounded(t *testing.T) {
	c := NewConsumer(ClusterGCPConfig{Subscription: "s"}, nil, zap.NewNop(), nil)
	for i := 0; i < unmatchedMaxKeys*3; i++ {
		c.warnUnmatched(LogResourceLabels{ProjectID: "p", ClusterName: strings.Repeat("x", 300) + strconv.Itoa(i)})
	}
	if n := len(c.lastUnmatched); n > unmatchedMaxKeys {
		t.Fatalf("限频表应有上限，得 %d", n)
	}
	for k := range c.lastUnmatched {
		if len(k) > 200 {
			t.Fatalf("键应被截断，长度 %d", len(k))
		}
	}
}
