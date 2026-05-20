package biz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	// CNNVD 官方漏洞列表 API（POST，无需认证）
	cnnvdVulListAPI = "https://www.cnnvd.org.cn/web/homePage/cnnvdVulList"
	cnnvdPageSize   = 50  // 官方 API 单页上限
	cnnvdMaxPages   = 200 // 最大翻页数，避免无限循环
)

// cnnvdListRequest CNNVD 漏洞列表请求
type cnnvdListRequest struct {
	PageIndex   int    `json:"pageIndex"`
	PageSize    int    `json:"pageSize"`
	Keyword     string `json:"keyword"`
	HazardLevel string `json:"hazardLevel"`
	VulType     string `json:"vulType"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	DateType    string `json:"dateType"`
}

// cnnvdListResponse CNNVD 漏洞列表响应
type cnnvdListResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total   int          `json:"total"`
		Records []cnnvdEntry `json:"records"`
	} `json:"data"`
}

// cnnvdEntry CNNVD 漏洞条目
type cnnvdEntry struct {
	ID          string `json:"id"`
	VulName     string `json:"vulName"`
	CnnvdCode   string `json:"cnnvdCode"`   // CNNVD-YYYYMM-NNNN
	CveCode     string `json:"cveCode"`     // CVE-YYYY-NNNN
	HazardLevel int    `json:"hazardLevel"` // 1=低危 2=中危 3=高危 0=超危
	PublishTime string `json:"publishTime"`
}

// SyncCNNVD 通过 CNNVD 官方 API 补齐漏洞的 CNNVD 编号
// 查询本地缺少 CNNVD 编号的 CVE，批量从 CNNVD API 按关键词匹配
func (v *VulnScanner) SyncCNNVD() error {
	v.logger.Info("开始 CNNVD 编号补齐")

	// 从系统配置读取自定义 API 地址
	apiURL := cnnvdVulListAPI
	var configURL string
	if err := v.db.Table("system_configs").
		Select("value").
		Where("`key` = ?", "cnnvd_api_url").
		Scan(&configURL).Error; err == nil && configURL != "" {
		apiURL = configURL
	}

	// 查询需要补齐 CNNVD 编号的 CVE ID
	var cveIDs []string
	v.db.Table("vulnerabilities").
		Select("cve_id").
		Where("cve_id != '' AND (cnnvd_id IS NULL OR cnnvd_id = '')").
		Limit(5000). // 单次同步上限，避免过大请求量
		Pluck("cve_id", &cveIDs)

	if len(cveIDs) == 0 {
		v.logger.Info("无需补齐 CNNVD 编号")
		return nil
	}

	v.logger.Info("待补齐 CNNVD 编号的漏洞数", zap.Int("count", len(cveIDs)))

	// 构建 CVE → 待更新 的查找集合
	pendingCVEs := make(map[string]struct{}, len(cveIDs))
	for _, id := range cveIDs {
		pendingCVEs[id] = struct{}{}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	totalUpdated := 0
	consecutiveErrors := 0

	// 分页拉取 CNNVD 最新漏洞，匹配 CVE 编号
	for page := 1; page <= cnnvdMaxPages; page++ {
		reqBody := cnnvdListRequest{
			PageIndex: page,
			PageSize:  cnnvdPageSize,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, err := http.NewRequest("POST", apiURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("构建 CNNVD 请求失败: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
		req.Header.Set("Referer", "https://www.cnnvd.org.cn/home/childHome")
		req.Header.Set("Origin", "https://www.cnnvd.org.cn")
		req.Header.Set("Accept", "application/json, text/plain, */*")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("CNNVD API 请求失败: %w", err)
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("读取 CNNVD 响应失败: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			consecutiveErrors++
			v.logger.Warn("CNNVD API 非 200 响应，等待后重试",
				zap.Int("status", resp.StatusCode),
				zap.Int("page", page),
				zap.Int("consecutiveErrors", consecutiveErrors),
			)
			if consecutiveErrors >= 3 {
				return fmt.Errorf("CNNVD API 连续 %d 次非 200 响应（最近: %d），停止同步", consecutiveErrors, resp.StatusCode)
			}
			time.Sleep(time.Duration(consecutiveErrors*5) * time.Second)
			page-- // 重试当前页
			continue
		}
		consecutiveErrors = 0

		var apiResp cnnvdListResponse
		if err := json.Unmarshal(respBody, &apiResp); err != nil {
			return fmt.Errorf("解析 CNNVD 响应失败: %w", err)
		}

		if apiResp.Code != 200 || len(apiResp.Data.Records) == 0 {
			break
		}

		for _, entry := range apiResp.Data.Records {
			cveCode := strings.TrimSpace(entry.CveCode)
			cnnvdCode := strings.TrimSpace(entry.CnnvdCode)
			if cveCode == "" || cnnvdCode == "" {
				continue
			}
			if _, ok := pendingCVEs[cveCode]; !ok {
				continue
			}

			result := v.db.Table("vulnerabilities").
				Where("cve_id = ? AND (cnnvd_id IS NULL OR cnnvd_id = '')", cveCode).
				Update("cnnvd_id", cnnvdCode)
			if result.RowsAffected > 0 {
				totalUpdated++
				delete(pendingCVEs, cveCode)
			}
		}

		// 所有待补齐的都找到了，提前退出
		if len(pendingCVEs) == 0 {
			break
		}

		// 已经遍历到最后一页
		if len(apiResp.Data.Records) < cnnvdPageSize {
			break
		}

		// 限速：避免对官方 API 造成压力
		time.Sleep(500 * time.Millisecond)
	}

	v.logger.Info("CNNVD 编号补齐完成", zap.Int("updated", totalUpdated), zap.Int("remaining", len(pendingCVEs)))
	return nil
}
