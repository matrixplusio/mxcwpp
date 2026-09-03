// Package httptrans — AC 管理接口内部响应封装 (A6 审计修复).
//
// AC 管理接口 (/health /conn/* /command /dependency/install) 是 Manager → AC
// 内部协议, 客户端硬编码解析特定字段名 (action / status / error 等), 不能改成
// 通用 {code,message,data} 信封 (会破 prod Manager-AC 心跳/调度链路).
//
// 但裸 c.JSON + gin.H 散落各 handler 风格不统一. 这里集中 2 个辅助:
//
//	ackErr(c, http.StatusBadRequest, err)        → {"error": err.Error()}
//	ackStatus(c, http.StatusOK, "sent")          → {"status": "sent"}
//
// 内部协议字段保持不变 (向后兼容), 仅消除散乱 c.JSON 调用.
package httptrans

import (
	"github.com/gin-gonic/gin"
)

// ackErr 内部协议错误响应.
func ackErr(c *gin.Context, status int, err error) {
	if err == nil {
		c.JSON(status, gin.H{"error": "unknown error"})
		return
	}
	c.JSON(status, gin.H{"error": err.Error()})
}

// ackStatus 内部协议状态响应.
func ackStatus(c *gin.Context, status int, label string) {
	c.JSON(status, gin.H{"status": label})
}
