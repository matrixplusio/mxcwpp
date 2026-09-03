// Package signing 提供 Ed25519 签名和验证功能
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Signer 使用 Ed25519 私钥对数据进行签名
type Signer struct {
	privateKey ed25519.PrivateKey
}

// NewSigner 从 base64 编码的私钥字符串创建 Signer
func NewSigner(privKeyBase64 string) (*Signer, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(privKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d (expected %d)", len(keyBytes), ed25519.PrivateKeySize)
	}
	return &Signer{privateKey: ed25519.PrivateKey(keyBytes)}, nil
}

// NewSignerFromFile 从文件加载 base64 编码的私钥
func NewSignerFromFile(keyPath string) (*Signer, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	return NewSigner(strings.TrimSpace(string(data)))
}

// SignSHA256 对 SHA256 hex 字符串签名，返回 base64 编码的签名
func (s *Signer) SignSHA256(sha256Hex string) (string, error) {
	hashBytes, err := hex.DecodeString(sha256Hex)
	if err != nil {
		return "", fmt.Errorf("invalid sha256 hex: %w", err)
	}
	if len(hashBytes) != 32 {
		return "", fmt.Errorf("invalid sha256 hash length: %d", len(hashBytes))
	}

	signature := ed25519.Sign(s.privateKey, hashBytes)
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifySHA256 验证 SHA256 hex 字符串的签名
func VerifySHA256(pubKeyBase64, sha256Hex, signatureBase64 string) error {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d (expected %d)", len(pubKeyBytes), ed25519.PublicKeySize)
	}

	hashBytes, err := hex.DecodeString(sha256Hex)
	if err != nil {
		return fmt.Errorf("invalid sha256 hex: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)
	if !ed25519.Verify(pubKey, hashBytes, sigBytes) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// GenerateKeyPair 生成 Ed25519 密钥对，返回 base64 编码的公钥和私钥
func GenerateKeyPair() (pubBase64, privBase64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %w", err)
	}
	pubBase64 = base64.StdEncoding.EncodeToString(pub)
	privBase64 = base64.StdEncoding.EncodeToString(priv)
	return pubBase64, privBase64, nil
}
