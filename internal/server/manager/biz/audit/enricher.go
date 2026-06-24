// Package audit 实现 AuditLog 多维 enrichment (P4-5).
//
// 给 AuditLog 写入前补充上下文:
//   - 用户 IP / User-Agent / 地理位置 (GeoIP)
//   - 操作目标的 RBAC 角色 / 租户
//   - 历史风险评分 (该用户最近 30 天异常操作数)
//   - ATT&CK Tactic/Technique 关联 (如果是 mode 切换或敏感操作)
package audit

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Enricher AuditLog 富化器.
type Enricher struct {
	db        *gorm.DB
	logger    *zap.Logger
	geoip     GeoIPLookup
	riskCache sync.Map // user_id → cachedRisk
}

// GeoIPLookup 抽象 IP → 地理位置.
type GeoIPLookup interface {
	Lookup(ip string) (country, city string, found bool)
}

// NewEnricher 构造.
func NewEnricher(db *gorm.DB, logger *zap.Logger, geo GeoIPLookup) *Enricher {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Enricher{db: db, logger: logger, geoip: geo}
}

// EnrichEntry 给 AuditLog 行追加上下文.
//
// 失败仅 warn, 不阻塞 audit 写入主流程.
func (e *Enricher) EnrichEntry(ctx context.Context, log *model.AuditLog) {
	if log == nil {
		return
	}
	// 1. IP → 地理 (从 UserAgent 字段提取, 实际部署 IP 来自 middleware)
	if log.IP != "" && e.geoip != nil {
		ip := normalizeIP(log.IP)
		if country, city, ok := e.geoip.Lookup(ip); ok {
			meta := log.Detail
			if meta == "" {
				meta = "{}"
			}
			meta = appendJSONField(meta, "geo_country", country)
			meta = appendJSONField(meta, "geo_city", city)
			log.Detail = meta
		}
	}

	// 2. 用户风险评分 (近 30 天异常操作数)
	if log.Username != "" {
		risk := e.computeUserRisk(ctx, log.Username)
		if risk > 0 {
			log.Detail = appendJSONField(log.Detail, "user_risk_score", risk)
		}
	}

	// 3. ATT&CK 关联 (敏感操作映射)
	if tactic, technique := e.mapATTCK(log.Action); tactic != "" {
		log.Detail = appendJSONField(log.Detail, "attck_tactic", tactic)
		log.Detail = appendJSONField(log.Detail, "attck_technique", technique)
	}
}

// cachedRisk 缓存值 + 过期时间.
type cachedRisk struct {
	score    int
	expireAt time.Time
}

// computeUserRisk 近 30 天该用户的失败/敏感操作计数 (有缓存).
func (e *Enricher) computeUserRisk(ctx context.Context, userID string) int {
	if v, ok := e.riskCache.Load(userID); ok {
		c := v.(cachedRisk)
		if time.Now().Before(c.expireAt) {
			return c.score
		}
	}
	since := time.Now().Add(-30 * 24 * time.Hour)
	var count int64
	if err := e.db.WithContext(ctx).
		Table("audit_logs").
		Where("username = ? AND created_at >= ? AND (status_code >= 400 OR action LIKE 'mode.%' OR action LIKE 'config_change.%')",
			userID, since).
		Count(&count).Error; err != nil {
		return 0
	}
	score := int(count)
	e.riskCache.Store(userID, cachedRisk{score: score, expireAt: time.Now().Add(5 * time.Minute)})
	return score
}

// mapATTCK 把 action 映射到 ATT&CK Tactic + Technique.
func (e *Enricher) mapATTCK(action string) (tactic, technique string) {
	switch {
	case strings.HasPrefix(action, "mode."):
		return "TA0004", "T1548" // Privilege Escalation
	case strings.HasPrefix(action, "config_change."):
		return "TA0003", "T1098" // Persistence (Account Manipulation)
	case strings.HasPrefix(action, "host_isolation."):
		return "TA0040", "T1486" // Impact
	case strings.HasPrefix(action, "auth.login.failed"):
		return "TA0006", "T1110" // Brute Force
	case strings.HasPrefix(action, "user."):
		return "TA0003", "T1136" // Persistence (Create Account)
	}
	return "", ""
}

// appendJSONField 极简 JSON 字段追加 (Metadata 是简单 JSON 对象).
func appendJSONField(existing string, key string, value any) string {
	if existing == "" || existing == "{}" {
		return "{\"" + key + "\":\"" + stringifyValue(value) + "\"}"
	}
	// 去末尾 }, 加 ", "key":"val" }
	trimmed := strings.TrimSpace(existing)
	if !strings.HasSuffix(trimmed, "}") {
		return existing
	}
	body := trimmed[:len(trimmed)-1]
	sep := ","
	if strings.TrimSpace(body[1:]) == "" {
		sep = ""
	}
	return body + sep + "\"" + key + "\":\"" + stringifyValue(value) + "\"}"
}

func stringifyValue(v any) string {
	switch t := v.(type) {
	case string:
		return strings.ReplaceAll(t, "\"", "\\\"")
	case int:
		return intToStr(t)
	}
	return "?"
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// normalizeIP 处理 X-Forwarded-For 多 IP / IPv6.
func normalizeIP(s string) string {
	if idx := strings.Index(s, ","); idx > 0 {
		s = s[:idx]
	}
	s = strings.TrimSpace(s)
	// 校验
	if parsed := net.ParseIP(s); parsed != nil {
		return parsed.String()
	}
	return s
}
