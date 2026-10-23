package connection

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/config"
)

// TestFirstConnectTLSConfig_FailClosed 本地无 CA 文件时：
//   - 无 / 非法 CA 指纹 → 连接前失败（绝不回退无 pin 的 InsecureSkipVerify）；
//   - 合法 64-hex 指纹 → 返回带 VerifyConnection 的 pin 配置。
func TestFirstConnectTLSConfig_FailClosed(t *testing.T) {
	newMgr := func(fp string) *Manager {
		cfg := &config.Config{}
		// 指向不存在的 CA 文件，强制进入指纹分支。
		cfg.Local.TLS.CAFile = filepath.Join(t.TempDir(), "nope-ca.crt")
		cfg.Local.TLS.CAFingerprint = fp
		return NewManager(cfg, zap.NewNop())
	}

	// 无指纹 → 失败
	if _, err := newMgr("").firstConnectTLSConfig("ac.local", "no ca", "path"); err == nil {
		t.Fatal("无 CA 指纹应连接前失败（不回退不安全模式）")
	}
	// 非法指纹 → 失败
	for _, bad := range []string{"deadbeef", "__PLACEHOLDER__", "zz"} {
		if _, err := newMgr(bad).firstConnectTLSConfig("ac.local", "bad fp", "path"); err == nil {
			t.Fatalf("非法指纹 %q 应失败", bad)
		}
	}
	// 合法指纹 → pin 配置
	validFP := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	cfg, err := newMgr(validFP).firstConnectTLSConfig("ac.local", "ok", "path")
	if err != nil {
		t.Fatalf("合法指纹应成功: %v", err)
	}
	if !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil {
		t.Fatal("pin 配置应为 InsecureSkipVerify=true + 自定义 VerifyConnection")
	}
	if cfg.ServerName != "ac.local" {
		t.Fatalf("ServerName=%q, 期望 ac.local", cfg.ServerName)
	}
}
