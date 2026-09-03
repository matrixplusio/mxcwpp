package cluster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteNginxConf_TLS 静态验收渲染的 nginx.conf：443 承载 TLS + UI/API，
// 80 仅健康探测 + 301 跳转（不代理 API/UI），HSTS 只在 443 块。
func TestWriteNginxConf_TLS(t *testing.T) {
	cfg := &Config{}
	cfg.App.ManagerHTTPPort = 8080
	cfg.App.HTTPPort = 80
	cfg.App.HTTPSPort = 443

	dst := filepath.Join(t.TempDir(), "nginx.conf")
	if err := writeNginxConf(dst, cfg); err != nil {
		t.Fatalf("writeNginxConf: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	conf := string(data)

	assertNginxTLS(t, conf)
}

// TestCommittedNginxConf_TLS 对仓库内 deploy/config/nginx.conf 做同样的静态验收，
// 保证 docker-compose 部署入口与集群 render 结果一致。
func TestCommittedNginxConf_TLS(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Skipf("定位仓库根失败: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "deploy", "config", "nginx.conf"))
	if err != nil {
		t.Fatalf("read committed nginx.conf: %v", err)
	}
	assertNginxTLS(t, string(data))
}

func assertNginxTLS(t *testing.T, conf string) {
	t.Helper()

	for _, must := range []string{
		"listen 443 ssl",
		"ssl_certificate     /etc/nginx/ssl/server.crt",
		"ssl_certificate_key /etc/nginx/ssl/server.key",
		"ssl_protocols       TLSv1.2 TLSv1.3",
		"return 301 https://",
	} {
		if !strings.Contains(conf, must) {
			t.Errorf("nginx.conf 缺少 %q", must)
		}
	}

	// 分割 80 / 443 块：以 "listen 443" 为界。
	idx := strings.Index(conf, "listen 443")
	if idx < 0 {
		t.Fatal("未找到 443 server 块")
	}
	httpBlock := conf[:idx]
	httpsBlock := conf[idx:]

	// 80 块只允许一个后端代理例外：agent 插件包下载（无凭据，内容有 SHA256 + 签名校验）。
	// 其余任何 location / proxy_pass 都是明文承载业务面，属于回退。
	const pluginsLoc = "location /api/v1/plugins/download"
	if !strings.Contains(httpBlock, pluginsLoc) {
		t.Error("HTTP(80) 块应保留 agent 插件下载代理，否则全量 agent 下载会被 301 到私有 CA HTTPS 而失败")
	}
	if n := strings.Count(httpBlock, "proxy_pass"); n != 1 {
		t.Errorf("HTTP(80) 块只允许插件下载一个 proxy_pass，实际 %d 个", n)
	}
	if n := strings.Count(httpBlock, "location /api"); n != 1 {
		t.Errorf("HTTP(80) 块只允许 %s 一条 /api 路由，实际 %d 条", pluginsLoc, n)
	}
	if strings.Contains(httpBlock, "Strict-Transport-Security") {
		t.Error("HSTS 不应出现在明文 HTTP(80) 块")
	}
	// HSTS 必须在 443 块。
	if !strings.Contains(httpsBlock, "Strict-Transport-Security") {
		t.Error("HTTPS(443) 块应包含 HSTS")
	}
	// 443 块应代理后端并承载 UI。
	if !strings.Contains(httpsBlock, "proxy_pass http://mxcwpp-manager") {
		t.Error("HTTPS(443) 块应代理 manager 后端")
	}
}

// TestNginxTLSMountIsolation nginx 容器只能挂 certs/ssl 子目录。
// 挂整个 certs 会把 CA 私钥（可签发任意 agent 证书）、client.key 与 enroll_token.secret
// 暴露给一个直面公网的容器，等于把整条信任链交出去。
func TestNginxTLSMountIsolation(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Skipf("定位仓库根失败: %v", err)
	}
	for _, rel := range []string{
		filepath.Join("deploy", "docker-compose.yml"),
		filepath.Join("deploy", "prod", "templates", "docker-compose.control.yml.tmpl"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, ":/etc/nginx/ssl") {
				continue
			}
			src := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(strings.TrimSpace(line), "- "), ":", 2)[0])
			if !strings.HasSuffix(src, "/certs/ssl") {
				t.Errorf("%s: nginx TLS 挂载源应为 .../certs/ssl，实际 %q", rel, src)
			}
		}
	}
}

// TestWriteControlCerts_SSLSubdir 渲染的节点包必须产出 certs/ssl/server.{crt,key}，
// 且该子目录不含 CA 私钥等敏感材料——它是 nginx 唯一可见的证书目录。
func TestWriteControlCerts_SSLSubdir(t *testing.T) {
	bundleDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bundleDir, "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	certs := &CertificateBundle{
		CACert: []byte("ca-cert"), CAKey: []byte("ca-key"),
		ServerCert: []byte("srv-cert"), ServerKey: []byte("srv-key"),
		AgentCert: []byte("agent-cert"), AgentKey: []byte("agent-key"),
		ClientCert: []byte("client-cert"), ClientKey: []byte("client-key"),
	}
	if err := writeControlCerts(bundleDir, certs); err != nil {
		t.Fatalf("writeControlCerts: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(bundleDir, "certs", "ssl"))
	if err != nil {
		t.Fatalf("read ssl dir: %v", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	if len(got) != 2 || !got["server.crt"] || !got["server.key"] {
		t.Errorf("certs/ssl 只应含 server.crt/server.key，实际 %v", got)
	}
	info, err := os.Stat(filepath.Join(bundleDir, "certs", "ssl", "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("certs/ssl/server.key 权限应为 0600，实际 %o", info.Mode().Perm())
	}
}
