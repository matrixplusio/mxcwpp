// signature.go — Agent 自更新 ed25519 签名验证 (P0-8 安全修复).
//
// 原来仅 SHA256 校验 (Server 给的 SHA256 与下载文件 hash 比对). 缺陷:
//   - SHA256 可被攻击者篡改 (中间人 / DNS 劫持 / S3 bucket 被盗)
//   - SHA256 仅完整性, 不是真实性 (anyone can compute)
//
// 修复: ed25519 公钥嵌入二进制 (build-time -ldflags), Server 给签名 + SHA256, Agent 双校验.
// 流程:
//  1. 下载包文件
//  2. 计算 SHA256 (完整性)
//  3. 用嵌入公钥验签名 (真实性) - signature = ed25519.Sign(privKey, sha256_bytes)
//  4. 双通过才安装
package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// updatePublicKeyBase64 build-time 嵌入 -ldflags "-X ...updatePublicKeyBase64=<base64-ed25519-pub>"
// 默认空 → 跳过签名校验 (兼容 dev / 老部署), 但 production build 必须设置.
var updatePublicKeyBase64 string

// VerifySignature ed25519 校验下载包.
//
// signature: base64 编码的 ed25519 签名 (Server 提供)
// pkgPath: 本地下载文件路径
//
// 返回:
//   - nil: 验证通过
//   - ErrSignatureRequired: 公钥未嵌入 (dev build) 但 server 也没给签名, 拒绝安装
//   - 其它 error: 签名格式错 / 验证失败
func VerifySignature(pkgPath, signatureB64 string) error {
	if updatePublicKeyBase64 == "" && signatureB64 == "" {
		// dev build + 老 server: 允许跳过, 但日志层调用方应警告
		return nil
	}
	if updatePublicKeyBase64 == "" {
		return errors.New("updater: public key not embedded (build with -ldflags -X)")
	}
	if signatureB64 == "" {
		return ErrSignatureRequired
	}
	pubBytes, err := base64.StdEncoding.DecodeString(updatePublicKeyBase64)
	if err != nil {
		return fmt.Errorf("updater: decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("updater: invalid public key size %d (expect %d)", len(pubBytes), ed25519.PublicKeySize)
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("updater: decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("updater: invalid signature size %d (expect %d)", len(sig), ed25519.SignatureSize)
	}
	hashBytes, err := sha256File(pkgPath)
	if err != nil {
		return fmt.Errorf("updater: hash file: %w", err)
	}
	if !ed25519.Verify(pubBytes, hashBytes, sig) {
		return ErrSignatureMismatch
	}
	return nil
}

// HasEmbeddedKey 是否在 build 时嵌入了公钥.
//
// 调用方根据返回值决定:
//   - true: prod build, 严格 require signature
//   - false: dev build, 仅 SHA256 校验 (会写 warn 日志)
func HasEmbeddedKey() bool { return updatePublicKeyBase64 != "" }

// EmbeddedPublicKeyFingerprint 返回嵌入公钥的 hex 前 16 字节, 用于日志展示验证 Agent 与 Server 配对.
func EmbeddedPublicKeyFingerprint() string {
	if updatePublicKeyBase64 == "" {
		return "<none>"
	}
	pubBytes, err := base64.StdEncoding.DecodeString(updatePublicKeyBase64)
	if err != nil || len(pubBytes) == 0 {
		return "<invalid>"
	}
	h := sha256.Sum256(pubBytes)
	return hex.EncodeToString(h[:8])
}

// sha256File 计算文件 SHA256.
func sha256File(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// 错误集.
var (
	ErrSignatureRequired = errors.New("updater: signature required by embedded public key, but server provided none")
	ErrSignatureMismatch = errors.New("updater: ed25519 signature mismatch")
)
