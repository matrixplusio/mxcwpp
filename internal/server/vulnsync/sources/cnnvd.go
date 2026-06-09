package sources

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// CNNVDDriver 占位实现 (CNNVD 无公开 API)。
//
// 实际生产建议:
//   - 商业合作接 CNNVD 数据合作方 API (奇安信 CERT / 漏洞盒子 API)
//   - 或本地维护一份 CVE->CNNVD 映射表 (从公告手动同步)
//   - 或对接 https://www.cnnvd.org.cn 站点爬虫 (注意 Cloudflare 拦截)
//
// 本 driver 仅做空 Fetch + HealthCheck 占位,
// 不阻塞 vulnsync 启动。
type CNNVDDriver struct {
	APIEndpoint string // 商业合作 API 端点; 留空时仅占位
	APIKey      string
	Client      *http.Client
}

// NewCNNVDDriver 构造 CNNVD driver (占位)。
func NewCNNVDDriver(apiEndpoint, apiKey string, timeout time.Duration) *CNNVDDriver {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &CNNVDDriver{
		APIEndpoint: apiEndpoint,
		APIKey:      apiKey,
		Client:      SharedHTTPClient(),
	}
}

func (d *CNNVDDriver) Name() string { return "cnnvd" }

func (d *CNNVDDriver) Fetch(_ context.Context, _ time.Time) (*FetchResult, error) {
	if d.APIEndpoint == "" {
		return &FetchResult{Source: "cnnvd", FetchedAt: time.Now()}, nil
	}
	// 留 PR: 真实 API 调用实现
	return &FetchResult{Source: "cnnvd", FetchedAt: time.Now()},
		fmt.Errorf("cnnvd: 真实 API 调用待实现, 当前为占位")
}

func (d *CNNVDDriver) HealthCheck(_ context.Context) error {
	if d.APIEndpoint == "" {
		return nil
	}
	return nil
}

var _ Driver = (*CNNVDDriver)(nil)
