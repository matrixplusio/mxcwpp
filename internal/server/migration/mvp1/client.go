package mvp1

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client MVP1 HTTP API 客户端
type Client struct {
	baseURL  string
	username string
	password string
	token    string
	http     *http.Client
}

// NewClient 创建客户端并登录
// baseURL: http://mvp1.example.com (不带 /api/v1 后缀)
func NewClient(baseURL, username, password string) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("地址必须以 http:// 或 https:// 开头")
	}

	// SSRF 防护：禁止访问内网地址和云元数据端点
	if err := validateExternalURL(baseURL); err != nil {
		return nil, err
	}

	c := &Client{
		baseURL:  baseURL,
		username: username,
		password: password,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					//nolint:gosec // MVP1 可能使用自签名证书，前端已提示
					InsecureSkipVerify: true,
				},
			},
		},
	}

	if err := c.login(); err != nil {
		return nil, fmt.Errorf("登录失败: %w", err)
	}

	return c, nil
}

// login 使用管理员账号登录获取 token
func (c *Client) login() error {
	body, _ := json.Marshal(map[string]string{
		"username": c.username,
		"password": c.password,
	})

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/v1/auth/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("请求登录接口失败: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("登录返回 %d: %s", resp.StatusCode, string(data))
	}

	var out struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("解析登录响应失败: %w", err)
	}
	if out.Code != 0 || out.Data.Token == "" {
		return fmt.Errorf("登录失败: %s", out.Message)
	}

	c.token = out.Data.Token
	return nil
}

// BaseURL 返回基础 URL
func (c *Client) BaseURL() string {
	return c.baseURL
}

// Get 发起带鉴权的 GET 请求，自动处理 401 重登录
func (c *Client) Get(path string, params map[string]string, out interface{}) error {
	return c.doWithRetry(http.MethodGet, path, params, out)
}

// Version 获取 MVP1 版本信息
func (c *Client) Version() (string, error) {
	var raw json.RawMessage
	if err := c.Get("/api/v1/health", nil, &raw); err != nil {
		return "unknown", err
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &v); err == nil && v.Version != "" {
		return v.Version, nil
	}
	return "unknown", nil
}

// doWithRetry 执行 HTTP 请求，遇 401 自动重登录一次
func (c *Client) doWithRetry(method, path string, params map[string]string, out interface{}) error {
	status, body, err := c.doOnce(method, path, params)
	if err != nil {
		return err
	}

	if status == http.StatusUnauthorized {
		if err := c.login(); err != nil {
			return fmt.Errorf("token 过期，重新登录失败: %w", err)
		}
		status, body, err = c.doOnce(method, path, params)
		if err != nil {
			return err
		}
	}

	if status != http.StatusOK {
		return fmt.Errorf("请求 %s 返回 %d: %s", path, status, truncate(string(body), 200))
	}

	var wrap struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}
	if wrap.Code != 0 {
		return fmt.Errorf("API 返回错误 %d: %s", wrap.Code, wrap.Message)
	}

	if out != nil && len(wrap.Data) > 0 {
		if err := json.Unmarshal(wrap.Data, out); err != nil {
			return fmt.Errorf("解析 data 字段失败: %w", err)
		}
	}
	return nil
}

// doOnce 单次 HTTP 请求
func (c *Client) doOnce(method, path string, params map[string]string) (int, []byte, error) {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return 0, nil, err
	}
	if len(params) > 0 {
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

// ListAll 分页拉取所有数据，返回原始 JSON 数组
// MVP1 API 分页格式：data.items 是数组，data.total 是总数
func (c *Client) ListAll(path string, pageSize int) ([]json.RawMessage, error) {
	if pageSize <= 0 {
		pageSize = 100
	}

	var all []json.RawMessage
	page := 1
	for {
		var pageData struct {
			Total int64             `json:"total"`
			Items []json.RawMessage `json:"items"`
		}
		params := map[string]string{
			"page":      strconv.Itoa(page),
			"page_size": strconv.Itoa(pageSize),
		}
		if err := c.Get(path, params, &pageData); err != nil {
			return nil, err
		}

		all = append(all, pageData.Items...)

		// 没有更多数据
		if len(pageData.Items) < pageSize || int64(len(all)) >= pageData.Total {
			break
		}
		page++
		// 防止异常死循环
		if page > 10000 {
			break
		}
	}
	return all, nil
}

// CountTable 获取指定路径的记录总数（只拉取第一页）
func (c *Client) CountTable(path string) (int64, error) {
	var pageData struct {
		Total int64             `json:"total"`
		Items []json.RawMessage `json:"items"`
	}
	params := map[string]string{"page": "1", "page_size": "1"}
	if err := c.Get(path, params, &pageData); err != nil {
		return 0, err
	}
	return pageData.Total, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// privateIPBlocks 定义需要阻止的内网和特殊地址段
var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local / cloud metadata
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 ULA
		"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// validateExternalURL 验证 URL 不指向内网地址或云元数据端点
func validateExternalURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("无效的 URL")
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL 缺少主机名")
	}

	// 解析为 IP
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("无法解析主机名: %s", host)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, block := range privateIPBlocks {
			if block.Contains(ip) {
				return fmt.Errorf("不允许访问内网地址")
			}
		}
	}
	return nil
}
