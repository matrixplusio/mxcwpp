// Package ssrf 提供防 SSRF 的 URL 校验与安全 HTTP 客户端。
//
// 用于一切"服务端按用户/管理员提供的 URL 发起请求"的场景（通知 webhook、漏洞数据源等），
// 防止打内网、回环、链路本地（含云元数据 169.254.169.254）等地址。
//
// 防护分两层：
//  1. 预校验 ValidateURL：解析 scheme + 解析域名所有 IP，命中内网段即拒。
//  2. 安全客户端 NewSafeClient：在真正建连时（Dialer.Control）按实际连接 IP 复查，
//     抵御 DNS rebinding（解析时通过、建连时换内网 IP）；并对每一跳重定向做协议校验。
package ssrf

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// ValidateURL 预校验：仅允许 http/https，且域名解析出的所有 IP 都不在受限网段。
func ValidateURL(raw string) error {
	u, err := parseAndCheckScheme(raw)
	if err != nil {
		return err
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL 缺少主机名")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("解析主机失败: %w", err)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("目标地址指向受限网段（内网/回环/元数据），已拒绝: %s", ip.String())
		}
	}
	return nil
}

// NewSafeClient 返回带 SSRF 防护的 HTTP 客户端：建连时按实际 IP 复查 + 重定向逐跳校验协议。
func NewSafeClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("无法解析连接 IP: %s", host)
			}
			if isBlockedIP(ip) {
				return fmt.Errorf("拒绝连接受限网段: %s", ip.String())
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: timeout,
			Proxy:                 nil, // 不走环境代理，避免绕过 IP 校验
		},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("重定向到非 http(s) 协议，已拒绝: %s", req.URL.Scheme)
			}
			return nil
		},
	}
}

func parseAndCheckScheme(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("URL 解析失败: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("仅允许 http/https，拒绝协议: %q", u.Scheme)
	}
	return u, nil
}

// isBlockedIP 判断 IP 是否落在受限网段：回环 / 私网 / 链路本地（含 169.254.169.254）/ 未指定 / 组播。
func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}
