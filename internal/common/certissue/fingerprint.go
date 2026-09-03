package certissue

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"regexp"
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

// hex64Re 匹配归一化后的 64 位小写十六进制 SHA-256 指纹。
var hex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidateFingerprint 校验 CA 指纹格式：归一化（去冒号/空格、转小写）后必须是 64 位十六进制。
// 用于 agent 首连前置校验与配置校验，杜绝空/截断/占位符指纹被当作有效 pin。
func ValidateFingerprint(fp string) error {
	norm := NormalizeFingerprint(fp)
	if norm == "" {
		return fmt.Errorf("CA 指纹为空")
	}
	if !hex64Re.MatchString(norm) {
		return fmt.Errorf("CA 指纹格式非法（需 64 位十六进制 SHA-256，可含冒号）：%q", fp)
	}
	return nil
}

// agentIDRe 约束 AgentID 字符集：字母数字与 . _ : -，长度 1..128。
// 防止任意文本进入单机证书 CN，或被用于路径/注入。
var agentIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// ValidAgentID 校验 AgentID 的长度与字符集。签发单机证书（CN=AgentID）与 Transfer
// 身份绑定前都必须通过，避免未校验文本进入证书主体。
func ValidAgentID(id string) error {
	if id == "" {
		return fmt.Errorf("AgentID 为空")
	}
	if !agentIDRe.MatchString(id) {
		return fmt.Errorf("AgentID 非法（仅允许字母数字及 . _ : - ，长度 1..128）：%q", id)
	}
	return nil
}

// VerifyChainPinnedCA 对服务端在 TLS 握手中出示的证书链做完整的 pinned-root 校验，
// 用于 agent 首次连接（本地尚无 CA 文件）时锁定 AC 的 CA，杜绝中间人冒充 AC。
//
// 与“仅检查链中是否出现指纹匹配证书”的弱校验不同，本函数要求同时满足：
//  1. wantFP 是合法的 64 位十六进制 SHA-256 指纹；
//  2. 链中存在指纹等于 wantFP 且 IsCA 的证书，将其作为**唯一**信任根（pinned root）；
//  3. 叶子证书（rawCerts[0]）经该 pinned root 完整验签成功（含有效期、中间证书链）；
//  4. serverName 命中叶子的 SAN（DNS/IP）；
//  5. 叶子用途包含 ServerAuth。
//
// 因此攻击者即便把公开的 pin CA 证书塞进一条伪造链，叶子仍无法由该 CA 验签，会被拒绝。
// rawCerts 为 tls.ConnectionState.PeerCertificates 的 Raw DER（或 VerifyConnection 回调入参）。
func VerifyChainPinnedCA(rawCerts [][]byte, wantFP, serverName string) error {
	want := NormalizeFingerprint(wantFP)
	if err := ValidateFingerprint(want); err != nil {
		return err
	}
	if len(rawCerts) == 0 {
		return fmt.Errorf("服务端未出示任何证书")
	}

	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("解析服务端证书失败: %w", err)
		}
		certs = append(certs, c)
	}

	// 找出 pin 指纹锁定的 CA：必须指纹匹配且确为 CA 证书。
	var pinned *x509.Certificate
	for _, c := range certs {
		if FingerprintDER(c.Raw) != want {
			continue
		}
		if !c.IsCA {
			return fmt.Errorf("pin 指纹命中的证书不是 CA（拒绝以叶子证书冒充信任根）")
		}
		pinned = c
		break
	}
	if pinned == nil {
		return fmt.Errorf("服务端证书链未包含 pin 指纹锁定的 CA")
	}

	// 以 pinned CA 作为唯一信任根验证叶子；其余非根证书作为中间证书。
	roots := x509.NewCertPool()
	roots.AddCert(pinned)
	intermediates := x509.NewCertPool()
	leaf := certs[0]
	for _, c := range certs[1:] {
		if c.Equal(pinned) {
			continue
		}
		intermediates.AddCert(c)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("叶子证书未由 pin 的 CA 签发，或 SAN/有效期/用途不符: %w", err)
	}
	return nil
}
