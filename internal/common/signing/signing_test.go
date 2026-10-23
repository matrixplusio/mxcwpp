package signing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这个包是插件供应链的唯一关卡：agent 在执行下发的插件二进制之前，
// 用它校验服务端签名。放行一个伪造签名等于在每台受管主机上执行任意代码，
// 所以这里的用例都以"必须拒绝"为主。

func hashOf(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func TestSignThenVerify(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	digest := hashOf("plugin-binary")
	sig, err := s.SignSHA256(digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySHA256(pub, digest, sig); err != nil {
		t.Fatalf("自己签的名验不过: %v", err)
	}
}

// TestVerifyRejectsTamperedArtifact 二进制被替换后，原签名必须失效。
//
// 这是本包存在的理由：签名对应的是内容哈希，换了内容就对不上。
func TestVerifyRejectsTamperedArtifact(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	s, _ := NewSigner(priv)

	sig, _ := s.SignSHA256(hashOf("plugin-binary"))
	if err := VerifySHA256(pub, hashOf("plugin-binary-with-backdoor"), sig); err == nil {
		t.Fatal("内容被替换后签名仍然通过——供应链校验形同虚设")
	}
}

// TestVerifyRejectsForeignKey 别的私钥签出来的名，不能用本方公钥验过。
func TestVerifyRejectsForeignKey(t *testing.T) {
	pub, _, _ := GenerateKeyPair()
	_, attackerPriv, _ := GenerateKeyPair()
	attacker, _ := NewSigner(attackerPriv)

	digest := hashOf("plugin-binary")
	sig, _ := attacker.SignSHA256(digest)
	if err := VerifySHA256(pub, digest, sig); err == nil {
		t.Fatal("攻击者用自己的密钥签名通过了校验")
	}
}

// TestVerifyRejectsMalformedInputs 畸形输入一律报错，不得当作通过。
//
// 每一项都对应一种"看起来像没签名"的情况；只要有一项返回 nil，
// 攻击者就有了一条不需要私钥的绕过路径。
func TestVerifyRejectsMalformedInputs(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	s, _ := NewSigner(priv)
	digest := hashOf("plugin-binary")
	sig, _ := s.SignSHA256(digest)

	cases := []struct {
		name           string
		pub, hex, sign string
	}{
		{"空签名", pub, digest, ""},
		{"空公钥", "", digest, sig},
		{"公钥非 base64", "!!!not-base64!!!", digest, sig},
		{"签名非 base64", pub, digest, "!!!not-base64!!!"},
		{"公钥长度不对", base64.StdEncoding.EncodeToString([]byte("short")), digest, sig},
		{"哈希非 hex", pub, "zzzz", sig},
		{"签名全零", pub, digest, base64.StdEncoding.EncodeToString(make([]byte, 64))},
		{"三项全空", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := VerifySHA256(c.pub, c.hex, c.sign); err == nil {
				t.Errorf("%s 被判为验签通过", c.name)
			}
		})
	}
}

// TestSignRejectsBadDigest 签名侧同样不接受畸形哈希，
// 否则会签出一个长度不对的载荷，让验签端的语义变得不确定。
func TestSignRejectsBadDigest(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	s, _ := NewSigner(priv)

	for _, bad := range []string{"", "zz", hex.EncodeToString(make([]byte, 16))} {
		if _, err := s.SignSHA256(bad); err == nil {
			t.Errorf("对畸形哈希 %q 签名成功了", bad)
		}
	}
}

func TestNewSignerRejectsBadKey(t *testing.T) {
	for _, bad := range []string{"", "!!!", base64.StdEncoding.EncodeToString([]byte("too-short"))} {
		if _, err := NewSigner(bad); err == nil {
			t.Errorf("接受了非法私钥 %q", bad)
		}
	}
}

// TestNewSignerFromFileTrimsWhitespace 密钥文件常带结尾换行，
// 若不裁剪就会以"私钥长度不对"失败，运维会误判成密钥损坏。
func TestNewSignerFromFileTrimsWhitespace(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	path := filepath.Join(t.TempDir(), "sign.key")
	if err := os.WriteFile(path, []byte("\n"+priv+"\n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignerFromFile(path); err != nil {
		t.Fatalf("带空白的密钥文件加载失败: %v", err)
	}
}

func TestNewSignerFromFileReportsMissingFile(t *testing.T) {
	_, err := NewSignerFromFile(filepath.Join(t.TempDir(), "absent.key"))
	if err == nil {
		t.Fatal("密钥文件不存在却没有报错")
	}
	if !strings.Contains(err.Error(), "read key file") {
		t.Errorf("错误信息没指出是读文件失败: %v", err)
	}
}

// TestGenerateKeyPairIsUnique 每次生成的密钥对必须不同。
func TestGenerateKeyPairIsUnique(t *testing.T) {
	a, _, _ := GenerateKeyPair()
	b, _, _ := GenerateKeyPair()
	if a == b {
		t.Fatal("两次生成得到同一个公钥")
	}
}
