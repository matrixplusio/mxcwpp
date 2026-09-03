package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifySignatureRoundtrip(t *testing.T) {
	// 生成临时密钥对
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	updatePublicKeyBase64 = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { updatePublicKeyBase64 = "" })

	// 写一个临时包文件
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "agent.rpm")
	if err := os.WriteFile(pkgPath, []byte("fake agent binary content"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("fake agent binary content"))
	sig := ed25519.Sign(priv, hash[:])
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if err := VerifySignature(pkgPath, sigB64); err != nil {
		t.Fatalf("expected verify pass, got %v", err)
	}
}

func TestVerifySignatureMismatch(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	updatePublicKeyBase64 = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { updatePublicKeyBase64 = "" })

	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "x")
	_ = os.WriteFile(pkgPath, []byte("payload"), 0o644)
	hash := sha256.Sum256([]byte("payload"))
	wrongSig := ed25519.Sign(otherPriv, hash[:])
	if err := VerifySignature(pkgPath, base64.StdEncoding.EncodeToString(wrongSig)); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestVerifySignatureMissingWhenKeyEmbedded(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	updatePublicKeyBase64 = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { updatePublicKeyBase64 = "" })

	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "x")
	_ = os.WriteFile(pkgPath, []byte("x"), 0o644)
	if err := VerifySignature(pkgPath, ""); err != ErrSignatureRequired {
		t.Fatalf("expected ErrSignatureRequired, got %v", err)
	}
}
