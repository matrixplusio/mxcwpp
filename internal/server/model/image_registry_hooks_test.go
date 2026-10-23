package model

import (
	"strings"
	"testing"
)

// fakeKMS 只做可逆的前缀包装，验证钩子的接线，不验证密码学。
type fakeKMS struct{}

func (fakeKMS) EncryptString(s string) (string, error) { return "kms:v1:" + s, nil }
func (fakeKMS) DecryptString(s string) (string, error) { return strings.TrimPrefix(s, "kms:v1:"), nil }

func withFakeKMS(t *testing.T) {
	t.Helper()
	prev := globalKMS
	globalKMS = fakeKMS{}
	t.Cleanup(func() { globalKMS = prev })
}

func TestImageRegistryPasswordSealedAtRest(t *testing.T) {
	withFakeKMS(t)

	r := ImageRegistry{Password: "p@ss"}
	if err := r.BeforeSave(nil); err != nil {
		t.Fatal(err)
	}
	if !isEncrypted(r.Password) {
		t.Fatalf("写库前应加密，实际 %q", r.Password)
	}
	// 已加密的值再次保存不能套两层。
	again := r.Password
	if err := r.BeforeSave(nil); err != nil || r.Password != again {
		t.Fatalf("重复保存不应二次加密: %q", r.Password)
	}
	if err := r.AfterFind(nil); err != nil || r.Password != "p@ss" {
		t.Fatalf("读库后应还原明文，实际 %q", r.Password)
	}

	legacy := ImageRegistry{Password: "old-plain"}
	if err := legacy.AfterFind(nil); err != nil || legacy.Password != "old-plain" {
		t.Fatalf("加密上线前的明文历史数据应照常可用，实际 %q", legacy.Password)
	}
}

// 走 Updates(map) 的写法不经钩子，必须先 SealSecret。
func TestSealSecret(t *testing.T) {
	if got, _ := SealSecret("x"); got != "x" {
		t.Fatalf("未启用 KMS 时应原样返回，实际 %q", got)
	}
	withFakeKMS(t)
	if got, _ := SealSecret("x"); got != "kms:v1:x" {
		t.Fatalf("启用 KMS 时应加密，实际 %q", got)
	}
	if got, _ := SealSecret(""); got != "" {
		t.Fatalf("空值不加密，实际 %q", got)
	}
}
