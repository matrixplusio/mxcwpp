package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// deployScriptPath 返回真实 deploy.sh 的绝对路径，不存在则跳过。
func deployScriptPath(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash 不可用，跳过")
	}
	abs, err := filepath.Abs(filepath.Join("..", "..", "deploy", "deploy.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Skipf("deploy.sh 不存在: %v", err)
	}
	return abs
}

// ensureTwiceBody 抽取 deploy.sh 真实的 is_strong_secret/persist/ensure 三函数并 eval，
// 执行两次（第二次模拟全新 shell 从 .env 重载），断言：达标、不轮换、唯一一行、权限 0600、
// EXPECT 非空时值被保留。不打印任何密钥值，失败仅输出非敏感原因。
const ensureTwiceBody = `set -euo pipefail
eval "$(sed -n '/^is_strong_secret() {/,/^}/p; /^persist_env_kv() {/,/^}/p; /^ensure_internal_secret() {/,/^}/p' "$SCRIPT")"
log_warn(){ :; }; log_info(){ :; }
INTERNAL_SECRET=""
set +u; . "$ENV_FILE" || true; set -u
ensure_internal_secret
v1="${INTERNAL_SECRET:-}"
unset INTERNAL_SECRET
. "$ENV_FILE"
ensure_internal_secret
v2="${INTERNAL_SECRET:-}"
is_strong_secret "$v1" || { echo "FAIL:not-strong"; exit 1; }
[ "$v1" = "$v2" ] || { echo "FAIL:rotated"; exit 1; }
n="$(grep -c '^INTERNAL_SECRET=' "$ENV_FILE" || true)"
[ "$n" = "1" ] || { echo "FAIL:lines=$n"; exit 1; }
perm="$(stat -f '%Lp' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE")"
[ "$perm" = "600" ] || { echo "FAIL:perm=$perm"; exit 1; }
if [ -n "${EXPECT:-}" ]; then [ "$v1" = "$EXPECT" ] || { echo "FAIL:not-preserved"; exit 1; }; fi
echo "OK"`

// TestDeployEnsureInternalSecret 覆盖 .env 无键/空键/弱值/过短/重复键/强值多场景，
// 每种执行两次，断言 ensure_internal_secret 幂等（不轮换、唯一一行、0600），
// 强值被保留、其它行不被破坏。
func TestDeployEnsureInternalSecret(t *testing.T) {
	script := deployScriptPath(t)
	const strong = "0123456789abcdef0123456789abcdef" // 32 hex

	cases := []struct {
		name       string
		initial    string
		expect     string // 非空 → 断言 secret 被保留为该值
		otherLines bool
	}{
		{"no-key", "", "", false},
		{"empty-key", "INTERNAL_SECRET=\n", "", false},
		{"weak-value", "INTERNAL_SECRET=changeme\n", "", false},
		{"short-value", "INTERNAL_SECRET=abc\n", "", false},
		{"duplicate-weak", "INTERNAL_SECRET=\nINTERNAL_SECRET=alsoweak\n", "", false},
		{"strong-preserved", "INTERNAL_SECRET=" + strong + "\n", strong, false},
		{"strong-with-other-lines", "FOO=bar\nINTERNAL_SECRET=" + strong + "\nBAZ=qux\n", strong, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			envFile := filepath.Join(t.TempDir(), ".env")
			if err := os.WriteFile(envFile, []byte(c.initial), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", ensureTwiceBody)
			cmd.Env = append(os.Environ(), "ENV_FILE="+envFile, "SCRIPT="+script)
			if c.expect != "" {
				cmd.Env = append(cmd.Env, "EXPECT="+c.expect)
			}
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "OK") {
				t.Fatalf("非幂等/校验失败: %v\n%s", err, out)
			}
			if c.otherLines {
				data, _ := os.ReadFile(envFile)
				if !strings.Contains(string(data), "FOO=bar") || !strings.Contains(string(data), "BAZ=qux") {
					t.Errorf("persist 破坏了非 INTERNAL_SECRET 行")
				}
			}
		})
	}
}

// certBody 抽取 deploy.sh 的证书函数并在临时目录里真实签发一次，随后打印待断言的事实：
// server.crt 的 EKU / SAN、certs/ssl 目录内容、以及 server_cert_ok 对旧式（无 SAN/EKU）
// 证书的判定。不依赖仓库现有证书，全部在 TMPDIR 内生成。
const certBody = `set -euo pipefail
eval "$(sed -n '/^cert_san_config() {/,/^}/p; /^issue_server_cert() {/,/^}/p; /^server_cert_ok() {/,/^}/p; /^sync_nginx_ssl() {/,/^}/p' "$SCRIPT")"
log_warn(){ :; }; log_info(){ :; }; log_error(){ :; }
mkdir -p "$SCRIPT_DIR/certs"
cd "$SCRIPT_DIR/certs"
openssl genrsa -out ca.key 2048 >/dev/null 2>&1
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=Test CA" >/dev/null 2>&1

# 1) 旧式无 SAN/EKU 的 server.crt 必须被判定为不合格。
openssl genrsa -out server.key 2048 >/dev/null 2>&1
openssl req -new -key server.key -out old.csr -subj "/CN=mxcwpp-server" >/dev/null 2>&1
openssl x509 -req -days 365 -in old.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt >/dev/null 2>&1
rm -f old.csr
if server_cert_ok; then echo "FAIL:legacy-cert-accepted"; exit 1; fi

# 2) 重签后必须合格，且带 serverAuth EKU 与包含 SERVER_IP 的 SAN。
issue_server_cert >/dev/null 2>&1
server_cert_ok || { echo "FAIL:reissued-cert-rejected"; exit 1; }
text="$(openssl x509 -in server.crt -noout -text)"
echo "$text" | grep -q "TLS Web Server Authentication" || { echo "FAIL:no-eku"; exit 1; }
echo "$text" | grep -q "IP Address:$SERVER_IP" || { echo "FAIL:no-san-ip"; exit 1; }

# 3) sync_nginx_ssl 只导出服务端证书对，绝不外泄 CA 私钥 / client 私钥 / enroll 令牌。
: > enroll_token.secret
sync_nginx_ssl
ls ssl | sort | tr '\n' ' ' | grep -qx "server.crt server.key " || { echo "FAIL:ssl-extra-files:$(ls ssl | tr '\n' ' ')"; exit 1; }
perm="$(stat -f '%Lp' ssl/server.key 2>/dev/null || stat -c '%a' ssl/server.key)"
[ "$perm" = "600" ] || { echo "FAIL:ssl-key-perm=$perm"; exit 1; }
echo "OK"`

// TestDeployServerCertTrust 验证 deploy.sh 产出的服务端证书满足新的信任链要求：
//   - 旧式（无 SAN/EKU）证书被识别为不合格，升级时会触发重签而不是静默放行；
//   - 重签结果带 serverAuth EKU 且 SAN 覆盖 SERVER_IP（否则 AgentCenter fail-closed
//     拒绝启动、agent 首连 pin 校验 SAN 不匹配）；
//   - nginx 只读挂载目录 certs/ssl 只含 server.crt/server.key，不含 CA 私钥与 enroll 令牌。
func TestDeployServerCertTrust(t *testing.T) {
	script := deployScriptPath(t)
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl 不可用，跳过")
	}

	cmd := exec.Command("bash", "-c", certBody)
	cmd.Env = append(os.Environ(),
		"SCRIPT="+script,
		"SCRIPT_DIR="+t.TempDir(),
		"SERVER_IP=10.1.2.3",
	)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "OK") {
		t.Fatalf("证书信任链断言失败: %v\n%s", err, out)
	}
}

// TestAgentEnrollTokenDelivery 锁住 enroll 令牌的交付链。
//
// 服务端已 fail-closed：无有效 enroll 令牌的 agent 拿不到单机证书。若安装侧不落地令牌，
// 结果是全量新装 agent 静默无法上线——这条链缺一环就等于 agent 接入功能失效，
// 故用静态断言把四个环节钉死：
//  1. systemd unit 经 EnvironmentFile 读取令牌（不写进 unit / 进程参数）；
//  2. install.sh 定义并在启动前调用 configure_agent_trust；
//  3. 令牌文件 0600；
//  4. 令牌绝不通过 -ldflags 编进二进制（strings 可读、无法轮换）。
func TestAgentEnrollTokenDelivery(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	read := func(rel string) string {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(data)
	}

	unit := read(filepath.Join("deploy", "systemd", "mxcwpp-agent.service"))
	if !strings.Contains(unit, "EnvironmentFile=-/etc/mxcwpp-agent/agent.env") {
		t.Error("mxcwpp-agent.service 缺少 EnvironmentFile=-/etc/mxcwpp-agent/agent.env，agent 拿不到 enroll 令牌")
	}
	if strings.Contains(unit, "MXCWPP_ENROLL_TOKEN=") {
		t.Error("enroll 令牌不得以 Environment= 形式写进 unit 文件（systemctl show 可读）")
	}

	install := read(filepath.Join("scripts", "install.sh"))
	for _, must := range []string{
		"configure_agent_trust() {",
		"\n    configure_agent_trust\n",
		"MXCWPP_ENROLL_TOKEN=${MXCWPP_ENROLL_TOKEN}",
		`chmod 600 "$env_file"`,
	} {
		if !strings.Contains(install, must) {
			t.Errorf("install.sh 缺少 %q", must)
		}
	}

	build := read(filepath.Join("scripts", "build.sh"))
	if strings.Contains(build, "main.enrollToken=") {
		t.Error("enroll 令牌不得经 -ldflags 编入 agent 二进制（strings 可读且无法轮换）")
	}
}
