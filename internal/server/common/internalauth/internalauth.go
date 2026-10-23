// Package internalauth 提供内部服务间通信的共享认证中间件。
//
// 放在中立 common 包，供 Manager 与 AgentCenter 同时使用，避免 AgentCenter
// 反向 import manager。二者以同一 server.internal_secret 构成对称认证。
//
// 一把密钥只管一类调用方：internal_secret 是 Manager↔AC；告警接收、AC 管理动作各用各的
// （见 config 的 alert_ingest_secret / ac_admin_secret）。混用的后果是权限最低的那个
// 持有者（比如只需要推告警的监控组件）拿到了权限最高的能力。
package internalauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strings"

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
	return MiddlewareAny(secret)
}

// MiddlewareAny 接受多把密钥中的任意一把，空串忽略；一把有效的都没有时拒绝一切请求。
//
// 用于轮换：接收方同时认新旧两把，发送方只带新的，各服务可以逐个重启而不出现
// 「一边已换、一边没换」的鉴权断档。旧密钥在全部切完后从配置里删掉。
func MiddlewareAny(secrets ...string) gin.HandlerFunc {
	digests := make([][sha256.Size]byte, 0, len(secrets))
	for _, s := range secrets {
		if s != "" {
			digests = append(digests, sha256.Sum256([]byte(s)))
		}
	}
	return func(c *gin.Context) {
		provided := sha256.Sum256([]byte(providedSecret(c)))
		// 每一把都比完再下结论，不因为先命中而提前返回。
		ok := 0
		for i := range digests {
			ok |= subtle.ConstantTimeCompare(provided[:], digests[i][:])
		}
		if ok != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"code":    http.StatusUnauthorized,
				"message": "unauthorized",
			})
			return
		}
		c.Next()
	}
}

// AllowCIDRs 只放行来源地址落在给定网段内的请求；cidrs 为空时不限制。
//
// 取的是 TCP 对端地址而不是 X-Forwarded-For：内部管理端口前面没有可信代理，
// 请求头里的地址是调用方自己填的，拿它做判断等于没有判断。
// 是密钥之外的第二道：密钥泄露后，从别的机器发来的请求仍然进不来。
func AllowCIDRs(cidrs []string) (gin.HandlerFunc, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			// 写了白名单却全是空项，按「不限制」处理就是静默放行
			return nil, fmt.Errorf("来源网段列表里有空项")
		}
		if !strings.Contains(raw, "/") {
			if ip := net.ParseIP(raw); ip != nil && ip.To4() != nil {
				raw += "/32"
			} else {
				raw += "/128"
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("无效的来源网段 %q: %w", raw, err)
		}
		nets = append(nets, n)
	}
	return func(c *gin.Context) {
		if len(nets) == 0 {
			c.Next()
			return
		}
		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			host = c.Request.RemoteAddr
		}
		ip := net.ParseIP(host)
		for _, n := range nets {
			if ip != nil && n.Contains(ip) {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": http.StatusForbidden, "message": "forbidden"})
	}, nil
}

// providedSecret 取调用方提供的密钥：优先 X-Internal-Secret，其次 Authorization: Bearer。
// alertmanager 的 webhook 只能带标准 Authorization 头，不认 Bearer 时它的投递全部 401。
func providedSecret(c *gin.Context) string {
	if v := c.GetHeader(HeaderName); v != "" {
		return v
	}
	if v, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer "); ok {
		return v
	}
	return ""
}
