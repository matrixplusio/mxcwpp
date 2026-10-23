package transfer

import (
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/common/agentident"
	"github.com/matrixplusio/mxcwpp/internal/server/config"
)

func identityService(t *testing.T, mode string) *Service {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.Exec(`CREATE TABLE hosts (host_id TEXT PRIMARY KEY, machine_fingerprint TEXT)`).Error; err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.MTLS.IdentityConflict = mode
	return &Service{db: db, cfg: cfg, logger: zap.NewNop(), connections: map[string]*Connection{}}
}

func TestIdentityFirstSeenAndReconnect(t *testing.T) {
	s := identityService(t, "reject")
	if d := s.checkIdentity("a1", "fp-A", "host-a"); d != "" {
		t.Fatalf("从未见过的 AgentID 不应冲突: %s", d)
	}
	s.db.Exec(`INSERT INTO hosts (host_id) VALUES ('a1')`)
	s.recordFingerprint(&Connection{AgentID: "a1", Fingerprint: "fp-A"})

	if d := s.checkIdentity("a1", "fp-A", "host-a-renamed"); d != "" {
		t.Fatalf("同一台机器（指纹相同）重连不应冲突，即使改了主机名: %s", d)
	}
}

func TestIdentityFingerprintMismatch(t *testing.T) {
	s := identityService(t, "reject")
	s.db.Exec(`INSERT INTO hosts (host_id, machine_fingerprint) VALUES ('a1', 'fp-A')`)
	if d := s.checkIdentity("a1", "fp-B", "clone"); d == "" {
		t.Fatal("指纹与首次接入时不同应判冲突")
	}
	// 旧版 agent 不报指纹：没有依据，不凭指纹判。
	if d := s.checkIdentity("a1", "", "host-a"); d != "" {
		t.Fatalf("未上报指纹时不应凭指纹判冲突: %s", d)
	}
}

func TestIdentityConcurrentUseFromAnotherHost(t *testing.T) {
	s := identityService(t, "reject")
	s.connections["a1"] = &Connection{AgentID: "a1", Hostname: "host-a"}
	if d := s.checkIdentity("a1", "", "host-b"); d == "" {
		t.Fatal("同一 AgentID 正被另一台主机使用应判冲突（旧版 agent 无指纹时比主机名）")
	}
	if d := s.checkIdentity("a1", "", "host-a"); d != "" {
		t.Fatalf("同一主机重连不应冲突: %s", d)
	}

	s.connections["a1"] = &Connection{AgentID: "a1", Hostname: "x", Fingerprint: "fp-A"}
	if d := s.checkIdentity("a1", "fp-A", "y"); d != "" {
		t.Fatalf("两侧指纹相同即同一台机器，主机名不同也不冲突: %s", d)
	}
	if d := s.checkIdentity("a1", "fp-B", "x"); d == "" {
		t.Fatal("两侧指纹不同应判冲突，即使主机名相同")
	}
}

// 已有基线不被覆盖：冲突放行（alert 模式）时，克隆机器不能把基线改成自己的。
func TestRecordFingerprintKeepsBaseline(t *testing.T) {
	s := identityService(t, "alert")
	s.db.Exec(`INSERT INTO hosts (host_id, machine_fingerprint) VALUES ('a1', 'fp-A')`)
	s.recordFingerprint(&Connection{AgentID: "a1", Fingerprint: "fp-B"})
	var got string
	s.db.Raw(`SELECT machine_fingerprint FROM hosts WHERE host_id='a1'`).Scan(&got)
	if got != "fp-A" {
		t.Fatalf("基线被覆盖为 %q", got)
	}
}

func TestConflictActionByMode(t *testing.T) {
	if err := identityService(t, "alert").handleIdentityConflict("a1", "h", "d"); err != nil {
		t.Fatalf("alert 模式应放行: %v", err)
	}
	err := identityService(t, "reject").handleIdentityConflict("a1", "h", "d")
	if !agentident.IsConflict(err) {
		t.Fatalf("reject 模式应返回 agent 可识别的冲突错误: %v", err)
	}
}
