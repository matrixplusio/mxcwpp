// Package redact 提供发往外部 LLM 前的数据脱敏与本地端点判定（批4 合规）。
//
// 安全运营数据含主机名 / 内网 IP 等敏感信息，外发第三方模型存在数据出境与泄露风险。
// 外发前用 Desensitizer 抹去 IP 与内网主机名；本地模型（ollama/vLLM）不脱敏。
package redact

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

const (
	// ipPlaceholder / hostPlaceholder 是脱敏后的占位符，保留语义可读性。
	ipPlaceholder   = "[REDACTED_IP]"
	hostPlaceholder = "[REDACTED_HOST]"
)

// ipv4Re 匹配点分十进制 IPv4。ipv6Re 匹配带冒号的 IPv6（含压缩写法）。
var (
	ipv4Re = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6Re = regexp.MustCompile(`\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b`)
)

// defaultSensitiveSuffixes 是默认视为内网主机的域名后缀。
var defaultSensitiveSuffixes = []string{".internal", ".local", ".cluster.local", ".svc", ".lan", ".corp"}

// Desensitizer 按配置抹去文本中的 IP 与内网主机名。零值不可用，请用 New 构造。
type Desensitizer struct {
	hostRe *regexp.Regexp
}

// New 构造脱敏器。extraSuffixes 追加到默认敏感后缀（如自建集群域名）。
func New(extraSuffixes []string) *Desensitizer {
	suffixes := append([]string{}, defaultSensitiveSuffixes...)
	for _, s := range extraSuffixes {
		if s = strings.TrimSpace(s); s != "" {
			if !strings.HasPrefix(s, ".") {
				s = "." + s
			}
			suffixes = append(suffixes, s)
		}
	}
	// 匹配 host.label 形式：一串标签 + 敏感后缀。用 quoteMeta 防后缀里的点被当通配。
	quoted := make([]string, len(suffixes))
	for i, s := range suffixes {
		quoted[i] = regexp.QuoteMeta(s)
	}
	hostRe := regexp.MustCompile(`\b[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]+)*(?:` + strings.Join(quoted, "|") + `)\b`)
	return &Desensitizer{hostRe: hostRe}
}

// Redact 返回抹去 IP 与内网主机名后的文本。
func (d *Desensitizer) Redact(s string) string {
	if s == "" {
		return s
	}
	s = d.hostRe.ReplaceAllString(s, hostPlaceholder)
	s = ipv6Re.ReplaceAllString(s, ipPlaceholder)
	s = ipv4Re.ReplaceAllString(s, ipPlaceholder)
	return s
}

// IsLocalURL 判断目标端点是否为本地/内网模型（无需脱敏、不算数据出境）。
// 覆盖 localhost / 回环 / 私有网段 / 内网域名后缀。
// 注意：链路本地段（169.254.0.0/16，含云元数据 169.254.169.254）不视为合法本地模型，
// 避免被当作"本地"而放行对元数据端点的 SSRF。
func IsLocalURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	for _, suf := range defaultSensitiveSuffixes {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	return false
}
