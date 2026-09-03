package advisory

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"
)

// UserAgent 上游请求统一 UA，便于上游侧识别 + 限流统计
const UserAgent = "mxcwpp-vuln-sync/2.6 (+https://github.com/matrixplusio/mxcwpp)"

// DoWithBackoff 把请求加上 retry/退避，保护上游不被打挂、保护本端不因瞬时 429 整轮 sync 失败。
//
// 重试策略：
//   - 429 / 403 / 5xx → 退避后重试（共最多 maxRetries 次）
//   - 网络错误（连接重置/超时）→ 重试
//   - 4xx 其他（如 404）→ 直接返回不重试
//
// 退避时间：5s, 15s, 45s（指数 + 抖动 ±30%），避免与其他客户端 thundering herd。
//
// 上限：maxRetries 默认 3。每次 attempt 用同 ctx；调用方控总 timeout 即可中断。
func DoWithBackoff(ctx context.Context, client *http.Client, req *http.Request, maxRetries int) (*http.Response, error) {
	if maxRetries <= 0 {
		maxRetries = 3
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}

	backoffs := []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second}
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// 注意：第一次 attempt=0 不等待
		if attempt > 0 {
			wait := backoffs[(attempt-1)%len(backoffs)]
			jitter := time.Duration(rand.Int63n(int64(wait) * 6 / 10)) // ±30%
			wait += jitter - (wait * 3 / 10)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if shouldRetryStatus(resp.StatusCode) {
			// 排掉 body 释放连接
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("upstream HTTP %d (attempt %d/%d)", resp.StatusCode, attempt+1, maxRetries+1)
			continue
		}

		// 2xx / 4xx 非限流类直接返
		return resp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("max retries exhausted (%d)", maxRetries)
	}
	return nil, lastErr
}

// shouldRetryStatus 哪些 HTTP 状态码值得退避重试
func shouldRetryStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429
		http.StatusForbidden,           // 403（部分 CDN 限流走 403）
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	}
	return false
}
