package advisory

// CacheStrategy OSVSource 详情缓存策略。
//
// OSV detail API 数据巨量 + 上游有偶发限流，缓存层能大幅降低 sync 时延。
// 缓存内容是 osv.dev /v1/vulns/{id} 原始 JSON，TTL 由实现层决定。
type CacheStrategy int

const (
	// CacheStrategyNone 不用缓存，每次 sync 全走在线 API。
	CacheStrategyNone CacheStrategy = iota
	// CacheStrategyPreferOnline 优先在线 API；API 失败回退过期 cache（"Hybrid" 模式）。
	CacheStrategyPreferOnline
	// CacheStrategyOfflineOnly 仅用 cache，不调上游 API（用于离线部署）。
	CacheStrategyOfflineOnly
)

// DetailCache OSVSource 漏洞详情 JSON 缓存接口。
//
// advisory 包不直接依赖 VulnCacheManager；调用方（biz 包）实现该接口注入。
// 当注入 nil 时 OSVSource 按 CacheStrategyNone 行为。
type DetailCache interface {
	// Get 取已缓存且未过期的 JSON 原文；命中返 ([]byte, true)，未命中或过期返 (nil, false)。
	Get(id string) ([]byte, bool)
	// GetIncludeExpired 取已缓存的 JSON（含过期）；上游 API 失败时兜底用。
	GetIncludeExpired(id string) ([]byte, bool)
	// Put 写入缓存原文。
	Put(id string, raw []byte)
}
