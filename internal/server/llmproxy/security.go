package llmproxy

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
)

// InternalAuth 校验内部共享密钥 X-Internal-Secret，保护 llmproxy 内部接口（/complete /embed）。
//
// 复用 v1 内部通信约定（manager middleware.InternalAuth）。常量时间比较防时序侧信道。
// secret 为空时调用方不应挂此中间件（启动时告警），避免空密钥放行任意请求。
func InternalAuth(secret string) gin.HandlerFunc {
	want := []byte(secret)
	return func(c *gin.Context) {
		provided := []byte(c.GetHeader("X-Internal-Secret"))
		if subtle.ConstantTimeCompare(provided, want) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "unauthorized",
			})
			return
		}
		c.Next()
	}
}
