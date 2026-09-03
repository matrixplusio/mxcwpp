// Package integrity 提供漏洞情报数据源的完整性校验，防供应链投毒（批4）。
//
// 两种校验手段：
//   - 摘要校验：源给出内容摘要（sha256/sha512/sha1）时，比对实际下载内容；
//   - GPG 验签：源提供 detached OpenPGP 签名 + 公钥时，校验内容未被篡改。
//
// 不改变现有抓取行为：仅在源配置/响应提供校验材料时生效，是纵深防御的一层。
package integrity

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // 仅用于比对上游声明的 sha1 摘要，非安全用途自身散列
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/openpgp" //nolint:staticcheck // openpgp 已冻结但仍是标准 detached 验签实现
)

// digestLen 是各算法十六进制摘要的期望长度。
var digestLen = map[string]int{
	"sha1":   40,
	"sha256": 64,
	"sha512": 128,
}

// NormalizeChecksumType 归一化摘要算法名（去前缀/连字符/大小写）。
func NormalizeChecksumType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	t = strings.ReplaceAll(t, "-", "")
	return t
}

// ValidateChecksumFormat 校验摘要字段格式：算法已知且为对应长度的十六进制。
// 用于校验上游"已解析的 checksum 字段"是否完好（畸形摘要是数据被篡改/损坏的信号）。
func ValidateChecksumFormat(checksumType, value string) error {
	algo := NormalizeChecksumType(checksumType)
	want, ok := digestLen[algo]
	if !ok {
		return fmt.Errorf("integrity: 不支持的摘要算法 %q", checksumType)
	}
	value = strings.TrimSpace(value)
	if len(value) != want {
		return fmt.Errorf("integrity: %s 摘要长度应为 %d，实际 %d", algo, want, len(value))
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("integrity: 摘要非合法十六进制: %w", err)
	}
	return nil
}

// VerifyDigest 比对 data 的实际摘要与上游声明的十六进制摘要。
func VerifyDigest(data []byte, checksumType, expectedHex string) error {
	algo := NormalizeChecksumType(checksumType)
	var got string
	switch algo {
	case "sha1":
		sum := sha1.Sum(data) //nolint:gosec // 比对上游声明摘要
		got = hex.EncodeToString(sum[:])
	case "sha256":
		sum := sha256.Sum256(data)
		got = hex.EncodeToString(sum[:])
	case "sha512":
		sum := sha512.Sum512(data)
		got = hex.EncodeToString(sum[:])
	default:
		return fmt.Errorf("integrity: 不支持的摘要算法 %q", checksumType)
	}
	if !strings.EqualFold(got, strings.TrimSpace(expectedHex)) {
		return fmt.Errorf("integrity: 摘要不匹配，期望 %s 实际 %s", expectedHex, got)
	}
	return nil
}

// VerifyDetachedGPG 用 armored 公钥校验 data 的 detached OpenPGP 签名。
// 签名/公钥任一不合法或验签失败均返回错误，防被篡改的源数据进入库。
func VerifyDetachedGPG(data, armoredSignature, armoredPublicKey []byte) error {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armoredPublicKey))
	if err != nil {
		return fmt.Errorf("integrity: 读取公钥失败: %w", err)
	}
	_, err = openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(data), bytes.NewReader(armoredSignature))
	if err != nil {
		return fmt.Errorf("integrity: GPG 验签失败: %w", err)
	}
	return nil
}
