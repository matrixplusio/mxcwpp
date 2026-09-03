package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestClientCertFingerprint_DetectsReplacement 证书被换掉必须能被识别出来。
//
// 回归点：原判据是 os.Stat(client.crt) 是否存在——只有"本机从没有过证书"才算变更。
// 共享证书换成单机证书时旧文件是在的，于是落了盘却不重连：磁盘上已是新证书、
// 当前连接仍在用旧的。服务端一旦开启 CN 强制绑定，这批 agent 会被整批拒绝，
// 而平台侧看到的是"证书已下发"，完全看不出问题。
func TestClientCertFingerprint_DetectsReplacement(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")

	// 共享证书阶段
	if err := os.WriteFile(certPath, []byte("shared-cert-CN=mxsec-agent"), 0o644); err != nil {
		t.Fatal(err)
	}
	shared := clientCertFingerprint(dir)
	if shared == "" {
		t.Fatal("已有证书时指纹不应为空")
	}

	// 服务端换发单机证书
	if err := os.WriteFile(certPath, []byte("per-agent-cert-CN=<agent-id>"), 0o644); err != nil {
		t.Fatal(err)
	}
	perAgent := clientCertFingerprint(dir)

	if perAgent == shared {
		t.Error("证书内容已替换，指纹必须变化，否则不会触发重连")
	}

	// 旧判据（文件是否存在）在这一步恒为 false，正是缺陷所在
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatal("前置条件错误：此场景下证书文件本就存在")
	}
}

// TestClientCertFingerprint_MissingIsEmpty 没有证书与读不出证书都返回空串。
//
// 两种情况都应触发重连：前者是首次签发要启用新身份，后者说明当前证书本就不可用，
// 重连会走首连流程重新取。返回空串而不是报错，是为了让调用方只需比较前后值。
func TestClientCertFingerprint_MissingIsEmpty(t *testing.T) {
	dir := t.TempDir()

	if got := clientCertFingerprint(dir); got != "" {
		t.Errorf("证书不存在时应返回空串，得到 %q", got)
	}

	// 磁盘写满等情况会留下 0 字节文件——这在部署环境中出现过，
	// 它同样必须被当作"没有可用证书"。
	if err := os.WriteFile(filepath.Join(dir, "client.crt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := clientCertFingerprint(dir); got != "" {
		t.Errorf("证书为空文件时应返回空串，得到 %q", got)
	}
}

// TestClientCertFingerprint_StableForSameContent 内容没变就不该触发重连。
//
// 服务端每次重连都会重下证书包，若指纹不稳定会导致 agent 反复自杀重连。
func TestClientCertFingerprint_StableForSameContent(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	if err := os.WriteFile(certPath, []byte("same-cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	first := clientCertFingerprint(dir)
	// 重新下发同一张证书
	if err := os.WriteFile(certPath, []byte("same-cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if second := clientCertFingerprint(dir); second != first {
		t.Errorf("同一张证书的指纹必须稳定，%q != %q", second, first)
	}
}
