// Package api 提供 HTTP API 处理器
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// APIResponse 统一 API 响应结构
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// PaginatedData 分页数据结构
type PaginatedData struct {
	Total int64       `json:"total"`
	Items interface{} `json:"items"`
}

// Success 成功响应（带数据）
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": data,
	})
}

// SuccessWithMessage 成功响应（带消息和数据）
func SuccessWithMessage(c *gin.Context, message string, data interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": message,
		"data":    data,
	})
}

// SuccessMessage 成功响应（仅消息）
func SuccessMessage(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": message,
	})
}

// SuccessPaginated 成功响应（分页数据）
func SuccessPaginated(c *gin.Context, total int64, items interface{}) {
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"total": total,
			"items": items,
		},
	})
}

// Created 创建成功响应
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, gin.H{
		"code": 0,
		"data": data,
	})
}

// 业务错误统一返回 HTTP 200 + body code（探针/panic/webhook 除外）。
// code 取自 respcode.go 的业务码库；message 为空时回退该 code 的默认文案。

// BadRequest 请求参数错误
func BadRequest(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{
		"code":    CodeInvalidParam,
		"message": msgOr(message, CodeInvalidParam),
	})
}

// BadRequestWithData 请求参数错误（附带 data，如 need_captcha 等前端需要的标志）
func BadRequestWithData(c *gin.Context, message string, data interface{}) {
	body := gin.H{
		"code":    CodeInvalidParam,
		"message": msgOr(message, CodeInvalidParam),
	}
	if data != nil {
		body["data"] = data
	}
	c.JSON(http.StatusOK, body)
}

// NotFound 资源不存在
func NotFound(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{
		"code":    CodeNotFound,
		"message": msgOr(message, CodeNotFound),
	})
}

// Conflict 资源冲突
func Conflict(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{
		"code":    CodeConflict,
		"message": msgOr(message, CodeConflict),
	})
}

// InternalError 服务器内部错误
func InternalError(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{
		"code":    CodeInternalError,
		"message": msgOr(message, CodeInternalError),
	})
}

// Unauthorized 未授权 / 认证失败（如用户名或密码错误）。不触发前端跳转登录。
func Unauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{
		"code":    CodeUnauthorized,
		"message": msgOr(message, CodeUnauthorized),
	})
}

// UnauthorizedExpired 登录已过期 / Token 无效。前端据 code=40101 跳转登录页。
func UnauthorizedExpired(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{
		"code":    CodeTokenExpired,
		"message": msgOr(message, CodeTokenExpired),
	})
}

// Forbidden 禁止访问
func Forbidden(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{
		"code":    CodeForbidden,
		"message": msgOr(message, CodeForbidden),
	})
}

// TooManyRequests 限流响应
func TooManyRequests(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{
		"code":    CodeRateLimited,
		"message": msgOr(message, CodeRateLimited),
	})
}

// ServiceUnavailable 服务不可用（用于 /health degraded 等）
//
// 可附带 data（健康检查报告）。data 传 nil 时只返 code+message。
// 例外：保留真实 HTTP 503，供 LB / k8s 探针据状态码摘除降级实例。
func ServiceUnavailable(c *gin.Context, message string, data interface{}) {
	body := gin.H{
		"code":    CodeUnavailable,
		"message": msgOr(message, CodeUnavailable),
	}
	if data != nil {
		body["data"] = data
	}
	c.JSON(http.StatusServiceUnavailable, body)
}
