package biz

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// SyncCNVDStub 国家信息安全漏洞共享平台（CNVD）同步 stub。
//
// CNVD https://www.cnvd.org.cn 无公开 API，需要第三方授权数据源。
// stub 仅判断 base_url 可达性，提示用户配置授权数据源。
func (v *VulnScanner) SyncCNVDStub() error {
	return checkChinaOfficialAvailable(context.Background(), "https://www.cnvd.org.cn/", "CNVD")
}

// checkChinaOfficialAvailable 探测国内官方漏洞库可达性。
// 不实际拉数据，仅判断网络层 OK，供用户在 UI 看到上游可达性反馈。
func checkChinaOfficialAvailable(ctx context.Context, url, name string) error {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 mxcwpp/1.0")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s 上游不可达：%w（国内部署可正常拉取）", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 {
		return fmt.Errorf("%s 返回 403（反爬虫），国外服务器常见，请在国内部署或配置镜像源", name)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s HTTP %d", name, resp.StatusCode)
	}
	// 可达但未实现 fetcher — 写 success 标识"上游连通"
	zap.L().Info("国内官方漏洞库可达但未实现数据拉取",
		zap.String("source", name),
		zap.Int("http_status", resp.StatusCode),
	)
	return fmt.Errorf("%s 上游可达但 fetcher 暂未实现（需第三方授权数据源 / API 配置）", name)
}
