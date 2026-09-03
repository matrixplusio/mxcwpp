// Package internalauth 提供内部服务间通信的共享认证中间件。
//
// 放在中立 common 包，供 Manager 与 AgentCenter 同时使用，避免 AgentCenter
// 反向 import manager。二者以同一 server.internal_secret 构成对称认证。
package internalauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
)

// HeaderName 是内部认证头名称。
const HeaderName = "X-Internal-Secret"

// Middleware 校验请求头 X-Internal-Secret 是否与共享密钥匹配。
//
// 安全约束：
//   - secret 为空时不得退化为放行——空配置下所有请求一律 401（fail-closed）。
//   - 先对提供值与密钥各做 SHA-256 归一为定长摘要，再 subtle.ConstantTimeCompare，
//     避免 subtle.ConstantTimeCompare 在长度不同时提前返回而泄漏长度侧信道。
//   - 不记录 secret 值。
func Middleware(secret string) gin.HandlerFunc {
	secretDigest := sha256.Sum256([]byte(secret))
	// 空 secret = 未正确配置，拒绝一切请求，杜绝 fail-open。
	failClosed := len(secret) == 0
	return func(c *gin.Context) {
		providedDigest := sha256.Sum256([]byte(c.GetHeader(HeaderName)))
		if failClosed || subtle.ConstantTimeCompare(providedDigest[:], secretDigest[:]) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "unauthorized",
			})
			return
		}
		c.Next()
	}
}
