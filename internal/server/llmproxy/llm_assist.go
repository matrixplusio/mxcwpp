// Package biz - C2: LLM 告警辅助分析
package llmproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// LLMAssist LLM 告警辅助分析服务
type LLMAssist struct {
	db     *gorm.DB
	logger *zap.Logger
	apiURL string
	apiKey string
	model  string
}

// NewLLMAssist 创建 LLM 辅助分析服务
func NewLLMAssist(db *gorm.DB, logger *zap.Logger, apiURL, apiKey, modelName string) *LLMAssist {
	return &LLMAssist{
		db:     db,
		logger: logger,
		apiURL: apiURL,
		apiKey: apiKey,
		model:  modelName,
	}
}

// AnalysisResult LLM 分析结果
type AnalysisResult struct {
	Summary         string   `json:"summary"`
	RiskLevel       string   `json:"riskLevel"`
	AttackVector    string   `json:"attackVector"`
	Recommendations []string `json:"recommendations"`
	MitreMapping    []string `json:"mitreMapping"`
}

// AnalyzeAlert 分析单个告警
func (l *LLMAssist) AnalyzeAlert(alertID uint) (*AnalysisResult, error) {
	var alert model.Alert
	if err := l.db.First(&alert, alertID).Error; err != nil {
		return nil, fmt.Errorf("查询告警失败: %w", err)
	}

	prompt := fmt.Sprintf(`你是一位安全分析师。请分析以下安全告警并给出评估：

告警信息：
- 分类：%s
- 严重级别：%s
- 主机：%s
- 详情：%s
- 规则：%s

请用 JSON 格式返回分析结果，包含以下字段：
- summary: 简要分析摘要（中文，2-3句话）
- riskLevel: 风险评估（critical/high/medium/low）
- attackVector: 可能的攻击手法
- recommendations: 建议的处置措施（数组）
- mitreMapping: 关联的 MITRE ATT&CK 技术（数组）`,
		alert.Category, alert.Severity, alert.HostID, alert.Actual, alert.Title)

	result, err := l.callLLM(prompt)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// callLLM 调用 LLM API
func (l *LLMAssist) callLLM(prompt string) (*AnalysisResult, error) {
	if l.apiURL == "" || l.apiKey == "" {
		return nil, fmt.Errorf("LLM API 未配置")
	}

	reqBody := map[string]interface{}{
		"model": l.model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens": 1024,
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", l.apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", l.apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用 LLM API 失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LLM API 返回 %d: %s", resp.StatusCode, string(respBody))
	}

	// 解析响应（适配 Claude/OpenAI 格式）
	var apiResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("解析 LLM 响应失败: %w", err)
	}

	// 提取文本内容
	var text string
	if len(apiResp.Content) > 0 {
		text = apiResp.Content[0].Text
	} else if len(apiResp.Choices) > 0 {
		text = apiResp.Choices[0].Message.Content
	}

	if text == "" {
		return nil, fmt.Errorf("LLM 返回空内容")
	}

	var result AnalysisResult
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		// 如果 JSON 解析失败，将整个文本作为摘要
		result.Summary = text
		result.RiskLevel = "unknown"
	}

	return &result, nil
}
