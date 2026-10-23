package transfer

import (
	"sync"
	"testing"
)

// 统计必须区分共享证书与一机一证，并且只看在线连接。
//
// 这个数字是升级 AgentCenter 的闸门：报小了会让运维以为迁移完成，
// 而升级瞬间那些 agent 会全部被拒且不会自愈。
func TestCertMigrationProgress(t *testing.T) {
	s := &Service{
		connections: map[string]*Connection{
			"a1": {AgentID: "a1", SharedCert: true},
			"a2": {AgentID: "a2", SharedCert: true},
			"a3": {AgentID: "a3", SharedCert: false},
		},
		connMu: sync.RWMutex{},
	}

	got := s.CertMigrationProgress()
	if got.Online != 3 {
		t.Fatalf("在线数应为 3，实际 %d", got.Online)
	}
	if got.StillShared != 2 {
		t.Fatalf("仍用共享证书应为 2，实际 %d", got.StillShared)
	}
	if got.PerAgent != 1 {
		t.Fatalf("已换单机证书应为 1，实际 %d", got.PerAgent)
	}
	if len(got.SharedAgentIDs) != 2 {
		t.Fatalf("应列出 2 个待迁移 agent，实际 %d", len(got.SharedAgentIDs))
	}
}

// 全部迁移完成时 still_shared 必须为 0——这是闸门放行的唯一依据。
func TestCertMigrationProgress_AllMigrated(t *testing.T) {
	s := &Service{
		connections: map[string]*Connection{
			"a1": {AgentID: "a1", SharedCert: false},
			"a2": {AgentID: "a2", SharedCert: false},
		},
	}
	got := s.CertMigrationProgress()
	if got.StillShared != 0 {
		t.Fatalf("全部迁移后应为 0，实际 %d", got.StillShared)
	}
}

// 无连接时不能 panic，且返回空列表而非 nil——
// 部署脚本按 JSON 字段解析，nil 会序列化成 null 影响判断。
func TestCertMigrationProgress_Empty(t *testing.T) {
	s := &Service{connections: map[string]*Connection{}}
	got := s.CertMigrationProgress()
	if got.Online != 0 || got.StillShared != 0 {
		t.Fatalf("空连接应全为 0，实际 %+v", got)
	}
	if got.SharedAgentIDs == nil {
		t.Fatal("应返回空切片而非 nil，否则 JSON 里是 null")
	}
}

// 待迁移列表要截断，迁移初期它等于整个机群。
func TestCertMigrationProgress_ListTruncated(t *testing.T) {
	conns := make(map[string]*Connection, 250)
	for i := range 250 {
		id := string(rune('a'+i%26)) + string(rune('a'+i/26))
		conns[id] = &Connection{AgentID: id, SharedCert: true}
	}
	s := &Service{connections: conns}
	got := s.CertMigrationProgress()
	if len(got.SharedAgentIDs) > 100 {
		t.Fatalf("列表应截断到 100，实际 %d", len(got.SharedAgentIDs))
	}
	if got.StillShared != len(conns) {
		t.Fatalf("计数不受截断影响，应为 %d，实际 %d", len(conns), got.StillShared)
	}
}
