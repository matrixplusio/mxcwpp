// Package api — CEL 规则沙箱测试 endpoint (B5).
//
// 给规则编辑器用: 用户输入 expression + sample event, 立即返编译错误 / 是否命中,
// 不污染 detection_rules 表, 也不进 Pipeline.
package api

import (
	"encoding/json"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/internal/server/engine/celengine"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// RuleSandboxHandler 沙箱测试.
type RuleSandboxHandler struct {
	logger *zap.Logger
}

// NewRuleSandboxHandler 构造.
func NewRuleSandboxHandler(logger *zap.Logger) *RuleSandboxHandler {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &RuleSandboxHandler{logger: logger}
}

// sandboxRequest 输入.
type sandboxRequest struct {
	Expression string            `json:"expression" binding:"required"`
	DataType   int32             `json:"data_type"`
	Fields     map[string]string `json:"fields" binding:"required"`
	Sample     json.RawMessage   `json:"sample_payload"` // 可选: 用 payload 推导 fields
}

// sandboxResponse 应答.
type sandboxResponse struct {
	Compiled   bool     `json:"compiled"`
	CompileErr string   `json:"compile_error,omitempty"`
	Matched    bool     `json:"matched"`
	EvalErr    string   `json:"eval_error,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// Test POST /api/v2/rules/test.
//
// 不存表, 仅瞬时编译评估返回结果.
func (h *RuleSandboxHandler) Test(c *gin.Context) {
	var req sandboxRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}
	if req.DataType == 0 {
		req.DataType = 3000 // 默认 ProcessEvent
	}
	resp := sandboxResponse{}

	// 临时 Engine: NewInMemory 用单条规则
	rule := model.DetectionRule{
		ID:         9999999,
		Name:       "sandbox-test",
		Expression: req.Expression,
		Enabled:    true,
		DataTypes:  model.StringArray{strconv.Itoa(int(req.DataType))},
	}
	eng, err := celengine.NewInMemory(h.logger, []model.DetectionRule{rule})
	if err != nil {
		resp.CompiledErr(err.Error())
		Success(c, resp)
		return
	}
	resp.Compiled = true
	// 评估
	hits := eng.Evaluate(req.DataType, req.Fields)
	resp.Matched = len(hits) > 0
	// 提示常见用法
	if len(req.Fields) == 0 {
		resp.Warnings = append(resp.Warnings, "fields 为空, 表达式中字段引用会返默认零值")
	}
	Success(c, resp)
}

func (r *sandboxResponse) CompiledErr(msg string) {
	r.Compiled = false
	r.CompileErr = msg
}
