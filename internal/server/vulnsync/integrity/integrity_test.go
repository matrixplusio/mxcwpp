package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestValidateChecksumFormat(t *testing.T) {
	good := sha256Hex([]byte("x"))
	if err := ValidateChecksumFormat("sha256", good); err != nil {
		t.Fatalf("合法 sha256 应通过: %v", err)
	}
	if err := ValidateChecksumFormat("SHA-256", good); err != nil {
		t.Fatalf("归一化算法名应通过: %v", err)
	}
	bad := []struct {
		typ, val string
	}{
		{"md5", good},               // 不支持算法
		{"sha256", "abc"},           // 长度不对
		{"sha256", good[:63] + "g"}, // 非十六进制
	}
	for _, b := range bad {
		if err := ValidateChecksumFormat(b.typ, b.val); err == nil {
			t.Errorf("应拒绝 %+v", b)
		}
	}
}

func TestVerifyDigest(t *testing.T) {
	data := []byte("hello vuln feed")
	if err := VerifyDigest(data, "sha256", sha256Hex(data)); err != nil {
		t.Fatalf("匹配摘要应通过: %v", err)
	}
	if err := VerifyDigest(data, "sha256", sha256Hex([]byte("tampered"))); err == nil {
		t.Fatal("不匹配摘要应失败（篡改信号）")
	}
}

func TestVerifyDetachedGPG_BadInput(t *testing.T) {
	// 非法公钥/签名应返回错误，绝不静默通过。
	if err := VerifyDetachedGPG([]byte("data"), []byte("not-a-sig"), []byte("not-a-key")); err == nil {
		t.Fatal("非法公钥应返回错误")
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
