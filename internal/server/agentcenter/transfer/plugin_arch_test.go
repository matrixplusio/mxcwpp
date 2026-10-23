package transfer

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	grpcProto "github.com/matrixplusio/mxcwpp/api/proto/grpc"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// seedArchPackages 建最小的主机与组件表：fim 1.0.1 有 amd64 / arm64 两个包，1.0.2（灰度）只有 arm64。
func seedArchPackages(t *testing.T, s *Service, armSig string) {
	t.Helper()
	for _, q := range []string{
		"INSERT INTO hosts (host_id, arch) VALUES ('agent-x86', 'x86_64'), ('agent-arm', 'aarch64')",
		"INSERT INTO components (id, name, category) VALUES (1, 'fim', 'plugin')",
		"INSERT INTO component_versions (id, component_id, version) VALUES (10, 1, '1.0.1'), (11, 1, '1.0.2')",
	} {
		if err := s.db.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	pkgs := []struct {
		vid           int
		arch, sha, sg string
	}{
		{10, "amd64", "sha-old", "sig-old"},
		{10, "arm64", "sha-arm", armSig},
		{11, "arm64", "sha-canary-arm", "sig-canary-arm"},
	}
	for _, p := range pkgs {
		if err := s.db.Exec("INSERT INTO component_packages (version_id, arch, pkg_type, sha256, signature, enabled) VALUES (?, ?, 'binary', ?, ?, 1)",
			p.vid, p.arch, p.sha, p.sg).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func fimConfig(t *testing.T, s *Service, plugins []model.PluginConfig, canaries map[string]model.PluginCanary, agentID string) (sha, sig string) {
	t.Helper()
	return fimConfigArch(t, s, plugins, canaries, agentID, "")
}

func fimConfigArch(t *testing.T, s *Service, plugins []model.PluginConfig, canaries map[string]model.PluginCanary, agentID, arch string) (sha, sig string) {
	t.Helper()
	for _, c := range mustBuild(t, s, plugins, canaries, agentID, arch) {
		if c.Name == "fim" {
			return c.Sha256, c.Signature
		}
	}
	t.Fatalf("%s 没有拿到 fim 配置", agentID)
	return "", ""
}

// TestBuildPluginConfigs_PerArchPackage 按主机架构下发对应包的哈希与签名。
func TestBuildPluginConfigs_PerArchPackage(t *testing.T) {
	s := newPluginTestService(t)
	seedArchPackages(t, s, "sig-arm")

	for _, c := range []struct{ agent, sha, sig string }{
		{"agent-x86", "sha-old", "sig-old"},     // amd64：与改造前一致
		{"agent-arm", "sha-arm", "sig-arm"},     // arm64：换成自己架构的包
		{"agent-unknown", "sha-old", "sig-old"}, // 查不到主机：保持默认
	} {
		sha, sig := fimConfig(t, s, globalPlugins(), nil, c.agent)
		if sha != c.sha || sig != c.sig {
			t.Errorf("%s 拿到 sha=%s sig=%s，期望 sha=%s sig=%s", c.agent, sha, sig, c.sha, c.sig)
		}
	}
}

// TestBuildPluginConfigs_UnsignedArchPackageKeepsDefault 平台启用了签名而该架构的包没签名时保持原值，
// 不能把 amd64 的签名配上 arm64 的哈希。
func TestBuildPluginConfigs_UnsignedArchPackageKeepsDefault(t *testing.T) {
	s := newPluginTestService(t)
	seedArchPackages(t, s, "")
	if sha, sig := fimConfig(t, s, globalPlugins(), nil, "agent-arm"); sha != "sha-old" || sig != "sig-old" {
		t.Errorf("拿到 sha=%s sig=%s，期望保持 sha-old / sig-old", sha, sig)
	}
}

// TestBuildPluginConfigs_UnsignedPlatformUsesArchSHA 平台没启用签名时，只换哈希。
func TestBuildPluginConfigs_UnsignedPlatformUsesArchSHA(t *testing.T) {
	s := newPluginTestService(t)
	seedArchPackages(t, s, "")
	plugins := globalPlugins()
	plugins[0].Signature = ""
	if sha, sig := fimConfig(t, s, plugins, nil, "agent-arm"); sha != "sha-arm" || sig != "" {
		t.Errorf("拿到 sha=%s sig=%s，期望 sha-arm 且无签名", sha, sig)
	}
}

// TestBuildPluginConfigs_CanaryPerArch 灰度版本同样按架构取包。
func TestBuildPluginConfigs_CanaryPerArch(t *testing.T) {
	s := newPluginTestService(t)
	seedArchPackages(t, s, "sig-arm")
	canaries := map[string]model.PluginCanary{"fim": {PluginName: "fim", Version: "1.0.2", SHA256: "sha-canary-amd", Signature: "sig-canary-amd",
		HostIDs: model.StringArray{"agent-arm"}}}
	if sha, sig := fimConfig(t, s, globalPlugins(), canaries, "agent-arm"); sha != "sha-canary-arm" || sig != "sig-canary-arm" {
		t.Errorf("拿到 sha=%s sig=%s，期望灰度 arm64 包 sha-canary-arm / sig-canary-arm", sha, sig)
	}
}

func TestNormalizeArch(t *testing.T) {
	for in, want := range map[string]string{"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64", "arm64": "arm64", " riscv64 ": "riscv64", "": ""} {
		if got := normalizeArch(in); got != want {
			t.Errorf("normalizeArch(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestBuildPluginConfigs_FirstConnectUsesHeartbeatArch 新主机首次连接时主机记录还没写入，
// 用首包心跳里的架构取包，否则 arm64 主机第一次必然拿到 amd64 的哈希。
func TestBuildPluginConfigs_FirstConnectUsesHeartbeatArch(t *testing.T) {
	s := newPluginTestService(t)
	seedArchPackages(t, s, "sig-arm")
	if sha, sig := fimConfigArch(t, s, globalPlugins(), nil, "agent-new", "aarch64"); sha != "sha-arm" || sig != "sig-arm" {
		t.Errorf("拿到 sha=%s sig=%s，期望 sha-arm / sig-arm", sha, sig)
	}
}

// TestBuildPluginConfigs_DBErrorAbortsDelivery 查询出错时整体不下发，不能退回 amd64 的哈希：
// agent 看到哈希变了会停掉运行中的插件去重装，而重装必然失败。
func TestBuildPluginConfigs_DBErrorAbortsDelivery(t *testing.T) {
	s := newPluginTestService(t)
	seedArchPackages(t, s, "sig-arm")
	if err := s.db.Exec("DROP TABLE component_packages").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.buildPluginConfigs(globalPlugins(), nil, "agent-arm", model.RuntimeTypeVM, ""); err == nil {
		t.Error("查询出错时应返回错误，而不是退回默认内容")
	}
	if err := s.db.Exec("DROP TABLE hosts").Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.buildPluginConfigs(globalPlugins(), nil, "agent-arm", model.RuntimeTypeVM, ""); err == nil {
		t.Error("查主机架构出错时应返回错误")
	}
}

// TestBuildPluginConfigs_ExternalURLKeepsDefault 外部下载地址只有一份文件，不分架构，不替换哈希。
func TestBuildPluginConfigs_ExternalURLKeepsDefault(t *testing.T) {
	s := newPluginTestService(t)
	seedArchPackages(t, s, "sig-arm")
	plugins := globalPlugins()
	plugins[0].DownloadURLs = model.StringArray{"https://bucket.example/fim"}
	if sha, _ := fimConfig(t, s, plugins, nil, "agent-arm"); sha != "sha-old" {
		t.Errorf("外部地址拿到 sha=%s，期望保持 sha-old", sha)
	}
}

// TestBuildPluginConfigs_CanaryAmd64Unchanged 灰度名单里的 amd64 主机拿到的是灰度版本本身的哈希。
func TestBuildPluginConfigs_CanaryAmd64Unchanged(t *testing.T) {
	s := newPluginTestService(t)
	seedArchPackages(t, s, "sig-arm")
	canaries := map[string]model.PluginCanary{"fim": {PluginName: "fim", Version: "1.0.2", SHA256: "sha-canary-amd", Signature: "sig-canary-amd",
		HostIDs: model.StringArray{"agent-x86"}}}
	if sha, sig := fimConfig(t, s, globalPlugins(), canaries, "agent-x86"); sha != "sha-canary-amd" || sig != "sig-canary-amd" {
		t.Errorf("拿到 sha=%s sig=%s，期望灰度本身的 sha-canary-amd / sig-canary-amd", sha, sig)
	}
}

func TestHeartbeatArch(t *testing.T) {
	rec, err := proto.Marshal(&bridge.Record{Data: &bridge.Payload{Fields: map[string]string{"arch": "aarch64"}}})
	if err != nil {
		t.Fatal(err)
	}
	data := &grpcProto.PackagedData{Records: []*grpcProto.EncodedRecord{{DataType: 2001, Data: []byte("x")}, {DataType: 1000, Data: rec}}}
	if got := heartbeatArch(data); got != "aarch64" {
		t.Errorf("heartbeatArch = %q，期望 aarch64", got)
	}
	if got := heartbeatArch(&grpcProto.PackagedData{}); got != "" {
		t.Errorf("没有心跳时应返回空串，得到 %q", got)
	}
	if got := heartbeatArch(nil); got != "" {
		t.Errorf("nil 时应返回空串，得到 %q", got)
	}
}

// TestConnectionUpdateArch 心跳里的架构第一次出现或变化时才要求重发。
func TestConnectionUpdateArch(t *testing.T) {
	c := &Connection{}
	if c.updateArch("") {
		t.Error("空值不应触发重发")
	}
	if !c.updateArch("aarch64") || c.GetArch() != "arm64" {
		t.Errorf("首次出现应触发重发并归一化，得到 %q", c.GetArch())
	}
	if c.updateArch("arm64") {
		t.Error("架构没变不应再触发重发")
	}
	if !c.updateArch("x86_64") || c.GetArch() != "amd64" {
		t.Errorf("架构变化应触发重发，得到 %q", c.GetArch())
	}
}

// TestConnectionArchConcurrent 广播在别的 goroutine 读架构，心跳处理同时写：用 -race 检测数据竞争。
func TestConnectionArchConcurrent(t *testing.T) {
	c := &Connection{arch: "amd64"}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			c.updateArch([]string{"aarch64", "x86_64"}[i%2])
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		_ = c.GetArch()
	}
	<-done
}

// TestConnectionArchChangeCap 被攻陷的主机来回改架构，每个连接最多响应 maxArchChanges 次。
func TestConnectionArchChangeCap(t *testing.T) {
	c := &Connection{}
	c.updateArch("x86_64") // 首次出现不计入变化次数
	triggered := 0
	for i := 0; i < 10; i++ {
		if c.updateArch([]string{"aarch64", "x86_64"}[i%2]) {
			triggered++
		}
	}
	if triggered != maxArchChanges {
		t.Errorf("架构变化触发了 %d 次重发，期望上限 %d", triggered, maxArchChanges)
	}
}

// TestConnectionRememberArch 首次下发用主机记录里的架构时记进连接，之后同样的心跳架构不再触发重发。
func TestConnectionRememberArch(t *testing.T) {
	c := &Connection{}
	c.rememberArch("arm64")
	if c.updateArch("aarch64") {
		t.Error("与已下发的架构相同，不应再触发重发")
	}
	c2 := &Connection{arch: "amd64"}
	c2.rememberArch("arm64")
	if c2.GetArch() != "amd64" {
		t.Error("已知架构不应被主机记录覆盖")
	}
}
