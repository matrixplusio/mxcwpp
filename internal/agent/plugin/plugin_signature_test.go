package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/agent/config"
	"github.com/matrixplusio/mxcwpp/internal/common/signing"
)

// verifySignature 决定一个下发的插件二进制会不会被执行。
// 它放行的每一种情形都必须是有意为之，因为它的下游就是 exec。

func signerFor(t *testing.T) (pub string, sign func(string) string) {
	t.Helper()
	pubKey, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	s, err := signing.NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pubKey, func(digest string) string {
		sig, err := s.SignSHA256(digest)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
}

func managerWithKey(pub string) *Manager {
	return &Manager{
		cfg:    &config.Config{SignPublicKey: pub},
		logger: zap.NewNop(),
	}
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestVerifySignatureAcceptsValidSignature(t *testing.T) {
	pub, sign := signerFor(t)
	d := digestOf("collector-binary")

	if err := managerWithKey(pub).verifySignature(d, sign(d)); err != nil {
		t.Fatalf("合法签名被拒绝: %v", err)
	}
}

// TestVerifySignatureRejectsEmptySignature 公钥已配置时，
// 空签名必须被拒绝——否则只要把签名字段留空就能绕过整道校验。
func TestVerifySignatureRejectsEmptySignature(t *testing.T) {
	pub, _ := signerFor(t)
	if err := managerWithKey(pub).verifySignature(digestOf("x"), ""); err == nil {
		t.Fatal("空签名被放行——省掉签名字段即可绕过校验")
	}
}

// TestVerifySignatureRejectsTamperedBinary 二进制被换掉后，原签名不再匹配。
func TestVerifySignatureRejectsTamperedBinary(t *testing.T) {
	pub, sign := signerFor(t)
	sig := sign(digestOf("collector-binary"))

	if err := managerWithKey(pub).verifySignature(digestOf("collector-binary-tampered"), sig); err == nil {
		t.Fatal("被篡改的二进制通过了校验")
	}
}

// TestVerifySignatureRejectsForeignKey 攻击者自签的插件不能被接受。
func TestVerifySignatureRejectsForeignKey(t *testing.T) {
	pub, _ := signerFor(t)
	_, attackerSign := signerFor(t)
	d := digestOf("collector-binary")

	if err := managerWithKey(pub).verifySignature(d, attackerSign(d)); err == nil {
		t.Fatal("攻击者自签的插件通过了校验")
	}
}

// TestVerifySignatureSkipsWhenNoKeyConfigured 固定"未配置公钥即跳过"这一行为。
//
// 这是一条 fail-open 分支，只有开发构建才应该走到：公钥由 -ldflags 注入，
// scripts/build.sh 的生产构建缺少 SIGN_PUBLIC_KEY 时会直接失败
// （见 TestProductionBuildRequiresSigningKey）。这里把两件事一起钉住——
// 行为本身，以及它所依赖的那道构建期闸门。
func TestVerifySignatureSkipsWhenNoKeyConfigured(t *testing.T) {
	if err := managerWithKey("").verifySignature(digestOf("x"), ""); err != nil {
		t.Fatalf("未配置公钥的开发构建无法加载插件: %v", err)
	}
}
