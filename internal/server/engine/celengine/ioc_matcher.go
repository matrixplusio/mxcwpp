package celengine

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// iocSnapshotData 与 manager 端 exportSnapshot 的 iocData 结构一致
type iocSnapshotData struct {
	IP   []string `json:"ip"`
	Hash []string `json:"hash"`
	URL  []string `json:"url"`
}

// IOCMatcher 服务端 IOC 匹配器:从 ioc_snapshots 表加载全量 IOC 到内存集,供 engine 匹配。
// 服务端匹配(事件本就全量到 engine),不依赖给 agent 下发 IOC。
type IOCMatcher struct {
	db      *gorm.DB
	logger  *zap.Logger
	mu      sync.RWMutex
	ip      map[string]struct{}
	hash    map[string]struct{}
	url     map[string]struct{}
	version string
	// confirmedIP 自有情报库里的 IP：我们自己研判确认过的攻击源，与外部 feed 分开存。
	// 外部 feed 的入站命中是背景噪声、被抑制；这一份的入站命中是已知的人又回来了，必须告警。
	confirmedIP map[string]struct{}
}

// NewIOCMatcher 创建匹配器
func NewIOCMatcher(db *gorm.DB, logger *zap.Logger) *IOCMatcher {
	return &IOCMatcher{
		db: db, logger: logger,
		ip: map[string]struct{}{}, hash: map[string]struct{}{}, url: map[string]struct{}{},
		confirmedIP: map[string]struct{}{},
	}
}

// Reload 从最新快照加载 IOC 集(版本未变则跳过)
func (m *IOCMatcher) Reload() error {
	if m.db == nil {
		return nil
	}
	m.reloadConfirmed()
	var snap model.IOCSnapshot
	if err := m.db.Order("id DESC").First(&snap).Error; err != nil {
		return nil // 无快照
	}
	m.mu.RLock()
	same := snap.Version == m.version
	m.mu.RUnlock()
	if same {
		return nil
	}
	var data iocSnapshotData
	if err := json.Unmarshal([]byte(snap.Data), &data); err != nil {
		return err
	}
	toSet := func(vals []string) map[string]struct{} {
		s := make(map[string]struct{}, len(vals))
		for _, v := range vals {
			if v != "" {
				s[v] = struct{}{}
			}
		}
		return s
	}
	m.mu.Lock()
	m.ip = toSet(data.IP)
	m.hash = toSet(data.Hash)
	m.url = toSet(data.URL)
	m.version = snap.Version
	m.mu.Unlock()
	m.logger.Info("IOC 匹配集已加载",
		zap.Int("ip", len(data.IP)), zap.Int("hash", len(data.Hash)), zap.Int("url", len(data.URL)),
		zap.String("version", snap.Version))
	return nil
}

// reloadConfirmed 从自有情报库加载已启用的 IP。量小（人工录入与研判提取），每轮直接全量读，
// 不走快照版本判断：新录入的攻击源要在下一轮就生效。读失败保留上一份，不清空。
func (m *IOCMatcher) reloadConfirmed() {
	var vals []string
	if err := m.db.Model(&model.LocalIOC{}).
		Where("ioc_type = ? AND enabled = ?", "ip", true).Pluck("value", &vals).Error; err != nil {
		m.logger.Warn("加载已确认攻击源失败，沿用上一份", zap.Error(err))
		return
	}
	set := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		if v != "" {
			set[v] = struct{}{}
		}
	}
	m.mu.Lock()
	m.confirmedIP = set
	m.mu.Unlock()
}

// CheckConfirmedIP 判断是否为自有情报库里的已确认攻击源。
func (m *IOCMatcher) CheckConfirmedIP(v string) bool {
	return m.check(func() map[string]struct{} { return m.confirmedIP }, v)
}

// StartReload 周期重载,使新增 IOC(含自有情报研判提取)无需重启即生效
func (m *IOCMatcher) StartReload(ctx context.Context) {
	if m.db == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := m.Reload(); err != nil {
					m.logger.Warn("IOC 匹配集重载失败", zap.Error(err))
				}
			}
		}
	}()
}

// CheckIP / CheckHash / CheckURL 判断是否命中 IOC 集
func (m *IOCMatcher) CheckIP(v string) bool   { return m.check(m.ipSet, v) }
func (m *IOCMatcher) CheckHash(v string) bool { return m.check(m.hashSet, v) }
func (m *IOCMatcher) CheckURL(v string) bool  { return m.check(m.urlSet, v) }

func (m *IOCMatcher) ipSet() map[string]struct{}   { return m.ip }
func (m *IOCMatcher) hashSet() map[string]struct{} { return m.hash }
func (m *IOCMatcher) urlSet() map[string]struct{}  { return m.url }

func (m *IOCMatcher) check(getSet func() map[string]struct{}, v string) bool {
	if v == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := getSet()[v]
	return ok
}

// Count 返回各类 IOC 数(用于日志/统计)
func (m *IOCMatcher) Count() (ip, hash, url int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.ip), len(m.hash), len(m.url)
}
