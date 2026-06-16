package certissue

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// FingerprintDER 返回证书 DER 字节的 SHA256 十六进制小写指纹（无分隔符）。
func FingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// NormalizeFingerprint 去除指纹中的冒号/空格并转小写，便于比对不同书写格式。
func NormalizeFingerprint(fp string) string {
	r := strings.NewReplacer(":", "", " ", "")
	return strings.ToLower(r.Replace(strings.TrimSpace(fp)))
}

// VerifyChainPinnedCA 校验 TLS 握手得到的证书链中是否存在 SHA256 指纹等于 want 的证书。
//
// 用于 agent 首次连接（本地尚无 CA 文件）时 pin 住 AC 的 CA，防止中间人冒充 AC。
// rawCerts 为 tls.ConnectionState.PeerCertificates 的 Raw DER（或 VerifyConnection 回调入参）。
func VerifyChainPinnedCA(rawCerts [][]byte, want string) error {
	want = NormalizeFingerprint(want)
	if want == "" {
		return fmt.Errorf("未配置 CA 指纹")
	}
	for _, raw := range rawCerts {
		if FingerprintDER(raw) == want {
			return nil
		}
		// 同时尝试比对该证书的签发者（链中可能只带叶子证书，需校验其 CA）
		if cert, err := x509.ParseCertificate(raw); err == nil {
			if cert.IsCA && FingerprintDER(cert.Raw) == want {
				return nil
			}
		}
	}
	return fmt.Errorf("服务端证书链未匹配 pin 的 CA 指纹")
}
