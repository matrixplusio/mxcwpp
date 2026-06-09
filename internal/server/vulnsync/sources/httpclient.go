// Package sources — 共享 http.Client 池 (P1-7 性能修复).
//
// 12 个漏洞源 (nvd / cnnvd / redhat / debian / ubuntu / suse / alpine / cisa_kev /
// epss / exploitdb / osv / xc) 原本各自 http.NewRequestWithContext 默认走
// http.DefaultClient → 无连接池, 每次 TLS handshake 慢, 同步耗时 2-3x.
//
// 本文件给所有 sources 注入共享 Transport:
//   - MaxIdleConns 100 / MaxIdleConnsPerHost 10 (每外部域名最多 10 长连接)
//   - IdleConnTimeout 90s
//   - TLSHandshakeTimeout 10s
//   - DisableCompression false (NVD / Redhat 等 JSON 大 payload 可压)
package sources

import (
	"net/http"
	"sync"
	"time"
)

var (
	sharedClientOnce sync.Once
	sharedClient     *http.Client
)

// SharedHTTPClient 给所有 source 调用, 复用同一 Transport.
func SharedHTTPClient() *http.Client {
	sharedClientOnce.Do(func() {
		sharedClient = &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				MaxConnsPerHost:       20,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				DisableCompression:    false,
				ForceAttemptHTTP2:     true,
			},
		}
	})
	return sharedClient
}
