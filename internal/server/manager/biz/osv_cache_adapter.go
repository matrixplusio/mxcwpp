package biz

import (
	"github.com/imkerbos/mxsec-platform/internal/server/vulnsync/advisory"
)

// osvDetailCacheAdapter 把 VulnCacheManager 适配成 advisory.DetailCache。
// advisory 子包不能直接依赖 biz 包（循环），用接口注入解耦。
type osvDetailCacheAdapter struct {
	inner *VulnCacheManager
}

// newOSVDetailCacheAdapter 构造适配器；inner=nil 时返回 nil（advisory.OSVSource 会按无缓存行为）。
func newOSVDetailCacheAdapter(inner *VulnCacheManager) advisory.DetailCache {
	if inner == nil {
		return nil
	}
	return &osvDetailCacheAdapter{inner: inner}
}

// Get 实现 advisory.DetailCache。
func (a *osvDetailCacheAdapter) Get(id string) ([]byte, bool) {
	raw, err := a.inner.GetCachedVuln(id)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	return raw, true
}

// GetIncludeExpired 实现 advisory.DetailCache。
func (a *osvDetailCacheAdapter) GetIncludeExpired(id string) ([]byte, bool) {
	raw, err := a.inner.GetCachedVulnIncludeExpired(id)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	return raw, true
}

// Put 实现 advisory.DetailCache。
func (a *osvDetailCacheAdapter) Put(id string, raw []byte) {
	_ = a.inner.PutCache(id, raw)
}

// osvCacheStrategy 把 VulnCacheMode 映射成 advisory.CacheStrategy。
func osvCacheStrategy(mode VulnCacheMode) advisory.CacheStrategy {
	switch mode {
	case CacheModeOffline:
		return advisory.CacheStrategyOfflineOnly
	case CacheModeHybrid:
		return advisory.CacheStrategyPreferOnline
	default:
		return advisory.CacheStrategyNone
	}
}
