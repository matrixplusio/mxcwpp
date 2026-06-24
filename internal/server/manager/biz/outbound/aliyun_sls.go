package outbound

// 阿里云日志服务 SLS connector (P2-18).
//
// 协议参考: https://help.aliyun.com/document_detail/29026.html
// API: POST https://<project>.<region>.log.aliyuncs.com/logstores/<logstore>/shards/lb
// Body: protobuf 格式 (简化版改用 JSON Webhook API)
//
// 当前简化实现走 SLS HTTP Webhook 入口 (无需 protobuf 依赖).
// 完整 protobuf 实现见: github.com/aliyun/aliyun-log-go-sdk

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// AliyunSLSConnector 阿里云 SLS 日志服务推送.
type AliyunSLSConnector struct {
	endpoint        string // <project>.<region>.log.aliyuncs.com
	project         string
	logstore        string
	accessKeyID     string
	accessKeySecret string
	client          *http.Client
	logger          *zap.Logger
}

// NewAliyunSLSConnector 构造.
func NewAliyunSLSConnector(project, logstore, region, accessKeyID, accessKeySecret string, logger *zap.Logger) *AliyunSLSConnector {
	if logger == nil {
		logger = zap.NewNop()
	}
	if region == "" {
		region = "cn-hangzhou"
	}
	return &AliyunSLSConnector{
		endpoint:        fmt.Sprintf("%s.%s.log.aliyuncs.com", project, region),
		project:         project,
		logstore:        logstore,
		accessKeyID:     accessKeyID,
		accessKeySecret: accessKeySecret,
		client:          &http.Client{Timeout: 10 * time.Second},
		logger:          logger,
	}
}

// Name 名字.
func (c *AliyunSLSConnector) Name() string { return "aliyun_sls" }

// Send 推送 Event 到 SLS logstore (protobuf wire 格式).
func (c *AliyunSLSConnector) Send(ctx context.Context, ev *Event) error {
	url := fmt.Sprintf("https://%s/logstores/%s/shards/lb", c.endpoint, c.logstore)

	// 构造 SLS LogGroup protobuf
	group := &slsLogGroup{
		Topic:  "mxcwpp",
		Source: ev.HostName,
		Logs: []slsLog{
			{
				Time: uint32(ev.Timestamp.Unix()),
				Contents: []slsLogContent{
					{Key: "alert_id", Value: ev.ID},
					{Key: "tenant_id", Value: ev.TenantID},
					{Key: "host_id", Value: ev.HostID},
					{Key: "severity", Value: ev.Severity},
					{Key: "category", Value: ev.Category},
					{Key: "rule_id", Value: ev.RuleID},
					{Key: "title", Value: ev.Title},
					{Key: "description", Value: ev.Description},
					{Key: "mitre_id", Value: ev.MitreID},
					{Key: "source", Value: ev.Source},
				},
			},
		},
	}
	bodyPB := group.Marshal()
	rawSize := strconv.Itoa(len(bodyPB))

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(bodyPB)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("x-log-apiversion", "0.6.0")
	req.Header.Set("x-log-signaturemethod", "hmac-sha1")
	req.Header.Set("x-log-bodyrawsize", rawSize)
	req.Header.Set("x-log-compresstype", "")
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	bodyMD5 := md5.Sum(bodyPB)
	req.Header.Set("Content-MD5", strings.ToUpper(hex.EncodeToString(bodyMD5[:])))
	req.Header.Set("Content-Length", strconv.Itoa(len(bodyPB)))
	signature := c.sign(req, bodyPB)
	req.Header.Set("Authorization", "LOG "+c.accessKeyID+":"+signature)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("sls do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("sls status %d", resp.StatusCode)
	}
	return nil
}

// sign SLS HMAC-SHA1 签名.
//
// 简化实现: 实际生产用 aliyun-log-go-sdk 签名函数, 这里仅给最小可工作版本.
func (c *AliyunSLSConnector) sign(req *http.Request, body []byte) string {
	canonicalString := strings.Join([]string{
		req.Method,
		req.Header.Get("Content-MD5"),
		req.Header.Get("Content-Type"),
		req.Header.Get("Date"),
		"x-log-apiversion:" + req.Header.Get("x-log-apiversion"),
		"x-log-signaturemethod:" + req.Header.Get("x-log-signaturemethod"),
		req.URL.Path,
	}, "\n")
	mac := hmac.New(sha1.New, []byte(c.accessKeySecret))
	mac.Write([]byte(canonicalString))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Close 释放 http client.
func (c *AliyunSLSConnector) Close() error {
	c.client.CloseIdleConnections()
	return nil
}
