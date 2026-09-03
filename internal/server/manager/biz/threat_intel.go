// Package biz - C3: 威胁情报（内置 Feed 直拉）
package biz

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const (
	iocRedisKeyPrefix = "mxcwpp:ioc:"
	iocTTL            = 24 * time.Hour
)

// feedSource 内置 Feed 数据源定义
type feedSource struct {
	Name    string // 来源名称
	URL     string // Feed URL
	IOCType string // IOC 类型：ip / url / hash
}

// 内置免费公开 Feed 列表（abuse.ch + OTX + blocklist.de + emergingthreats）
var builtinFeeds = []feedSource{
	// abuse.ch
	{Name: "abuse.ch Feodo IP", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", IOCType: "ip"},
	{Name: "abuse.ch URLhaus", URL: "https://urlhaus.abuse.ch/downloads/text/", IOCType: "url"},
	{Name: "abuse.ch MalwareBazaar MD5", URL: "https://bazaar.abuse.ch/export/txt/md5/recent/", IOCType: "hash"},
	// blocklist.de (brute-force / SSH / attack IPs)
	{Name: "blocklist.de All", URL: "https://lists.blocklist.de/lists/all.txt", IOCType: "ip"},
	// Emerging Threats (compromised IPs)
	{Name: "ET Compromised IPs", URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", IOCType: "ip"},
	// cinsscore.com (CI Army threat list)
	{Name: "CI Army Bad IPs", URL: "https://cinsscore.com/list/ci-badguys.txt", IOCType: "ip"},
}

// ThreatIntel 威胁情报服务
type ThreatIntel struct {
	db          *gorm.DB
	redisClient *redis.Client
	logger      *zap.Logger
	httpClient  *http.Client
	customFeeds []feedSource // user-configured external feeds
	otxAPIKey   string       // AlienVault OTX API key (optional)
	mispURL     string       // MISP instance URL (optional)
	mispAPIKey  string       // MISP API key (optional)
}

// NewThreatIntel 创建威胁情报服务
func NewThreatIntel(db *gorm.DB, redisClient *redis.Client, logger *zap.Logger) *ThreatIntel {
	return &ThreatIntel{
		db:          db,
		redisClient: redisClient,
		logger:      logger,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// SetOTXKey configures AlienVault OTX integration (optional).
func (t *ThreatIntel) SetOTXKey(apiKey string) {
	t.otxAPIKey = apiKey
	t.logger.Info("OTX threat intel integration configured")
}

// SetMISP configures MISP instance integration (optional).
func (t *ThreatIntel) SetMISP(url, apiKey string) {
	t.mispURL = strings.TrimSuffix(url, "/")
	t.mispAPIKey = apiKey
	t.logger.Info("MISP threat intel integration configured",
		zap.String("url", t.mispURL))
}

// AddCustomFeed registers an additional text-line IOC feed.
func (t *ThreatIntel) AddCustomFeed(name, url, iocType string) {
	t.customFeeds = append(t.customFeeds, feedSource{
		Name:    name,
		URL:     url,
		IOCType: iocType,
	})
}

// IOC 威胁指标
type IOC struct {
	Type  string   `json:"type"` // ip, domain, hash, url
	Value string   `json:"value"`
	Tags  []string `json:"tags,omitempty"`
}

// SyncIOCs 拉取内置 Feed 最新 IOC 并写入 Redis Set
func (t *ThreatIntel) SyncIOCs(ctx context.Context) error {
	startedAt := time.Now()

	// 插入 running 记录
	record := model.SecurityDBSyncRecord{
		DBType:    "threat-intel",
		Status:    "running",
		StartedAt: startedAt,
	}
	t.db.Create(&record)

	err := t.doSyncIOCs(ctx)

	duration := int(time.Since(startedAt).Seconds())
	updates := map[string]interface{}{
		"duration": duration,
	}

	if err != nil {
		updates["status"] = "failed"
		updates["error_msg"] = err.Error()
	} else {
		updates["status"] = "success"
		updates["version"] = time.Now().Format("20060102.150405")

		// 统计各类型 IOC 数量
		if t.redisClient != nil {
			var totalIOC int64
			for _, iocType := range []string{"ip", "hash", "domain", "url"} {
				if n, e := t.redisClient.SCard(ctx, iocRedisKeyPrefix+iocType).Result(); e == nil {
					totalIOC += n
				}
			}
			updates["file_size"] = totalIOC // 复用 file_size 存储 IOC 总数
		}
	}

	if dbErr := t.db.Model(&record).Updates(updates).Error; dbErr != nil {
		t.logger.Error("更新同步记录失败", zap.Error(dbErr))
	}

	return err
}

// doSyncIOCs 遍历内置 + 自定义 Feed 列表，逐个拉取并持久化到 ioc_entries(DB 为真源;Redis 可选缓存)
func (t *ThreatIntel) doSyncIOCs(ctx context.Context) error {
	// Merge built-in + custom feeds.
	allFeeds := make([]feedSource, 0, len(builtinFeeds)+len(t.customFeeds))
	allFeeds = append(allFeeds, builtinFeeds...)
	allFeeds = append(allFeeds, t.customFeeds...)

	t.logger.Info("开始同步威胁情报",
		zap.Int("builtin_feeds", len(builtinFeeds)),
		zap.Int("custom_feeds", len(t.customFeeds)),
		zap.Bool("otx_enabled", t.otxAPIKey != ""),
		zap.Bool("misp_enabled", t.mispURL != ""))

	var totalCount int
	var lastErr error

	for _, feed := range allFeeds {
		count, err := t.fetchFeed(ctx, feed)
		if err != nil {
			t.logger.Warn("拉取 Feed 失败",
				zap.String("name", feed.Name),
				zap.Error(err))
			lastErr = err
			continue
		}
		totalCount += count
		t.logger.Info("Feed 拉取完成",
			zap.String("name", feed.Name),
			zap.Int("count", count))
	}

	// OTX integration (optional).
	if t.otxAPIKey != "" {
		count, err := t.fetchOTX(ctx)
		if err != nil {
			t.logger.Warn("OTX 拉取失败", zap.Error(err))
			lastErr = err
		} else {
			totalCount += count
		}
	}

	// MISP integration (optional).
	if t.mispURL != "" && t.mispAPIKey != "" {
		count, err := t.fetchMISP(ctx)
		if err != nil {
			t.logger.Warn("MISP 拉取失败", zap.Error(err))
			lastErr = err
		} else {
			totalCount += count
		}
	}

	t.logger.Info("威胁情报同步完成", zap.Int("total", totalCount))

	// 关键(持久化韧性):即使本轮 feed 全失败,也要清理过期 + 从 DB 存量重建快照/Redis,
	// 保证外部源断供时仍用最后已知集继续检测,不因一次拉取失败让匹配集变空。
	t.cleanupExpiredIOCs(ctx)
	if err := t.exportSnapshot(ctx); err != nil {
		t.logger.Warn("IOC 快照导出失败", zap.Error(err))
	}

	// feed 全失败仍回报错误(供 UI 显示同步状态),但快照已用 DB 存量重建。
	if totalCount == 0 && lastErr != nil {
		return fmt.Errorf("所有 Feed 拉取失败(已用 DB 存量重建快照)，最后错误: %w", lastErr)
	}

	return nil
}

// fetchOTX pulls IOCs from AlienVault OTX subscribed pulses.
func (t *ThreatIntel) fetchOTX(ctx context.Context) (int, error) {
	// OTX API: GET /api/v1/indicators/export (subscribed IOCs as text lines)
	url := "https://otx.alienvault.com/api/v1/indicators/export"
	var totalCount int

	for _, iocType := range []string{"IPv4", "URL", "FileHash-MD5"} {
		reqURL := fmt.Sprintf("%s?type=%s", url, iocType)
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("X-OTX-API-KEY", t.otxAPIKey)

		resp, err := t.httpClient.Do(req)
		if err != nil {
			return totalCount, fmt.Errorf("OTX %s 请求失败: %w", iocType, err)
		}

		// Map OTX types to our IOC types.
		var iocT string
		switch iocType {
		case "IPv4":
			iocT = "ip"
		case "URL":
			iocT = "url"
		case "FileHash-MD5":
			iocT = "hash"
		}

		values := make([]string, 0, 4096)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			values = append(values, line)
		}
		resp.Body.Close()

		count, err := t.upsertIOCEntries(ctx, iocT, "AlienVault OTX", values)
		if err != nil {
			return totalCount, err
		}
		totalCount += count
		t.logger.Info("OTX Feed 拉取完成",
			zap.String("type", iocType),
			zap.Int("count", count))
	}

	return totalCount, nil
}

// fetchMISP pulls IOCs from a MISP instance via REST API.
func (t *ThreatIntel) fetchMISP(ctx context.Context) (int, error) {
	// MISP API: POST /attributes/restSearch with published=true, last=1d
	url := t.mispURL + "/attributes/restSearch"

	body := `{"returnFormat":"text","type":["ip-dst","ip-src","md5","url"],"last":"1d","published":true}`
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", t.mispAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/plain")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("MISP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("MISP HTTP %d", resp.StatusCode)
	}

	// MISP text output: one IOC per line;按类型分桶后批量 upsert。
	byType := map[string][]string{"ip": nil, "hash": nil, "url": nil}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var iocT string
		switch {
		case strings.Contains(line, "://"):
			iocT = "url"
		case len(line) == 32 && !strings.Contains(line, "."):
			iocT = "hash"
		default:
			iocT = "ip"
		}
		byType[iocT] = append(byType[iocT], line)
	}

	count := 0
	for iocT, values := range byType {
		n, err := t.upsertIOCEntries(ctx, iocT, "MISP", values)
		if err != nil {
			return count, err
		}
		count += n
	}

	t.logger.Info("MISP Feed 拉取完成", zap.Int("count", count))
	return count, nil
}

// fetchFeed 拉取单个 Feed 并 upsert 持久化到 ioc_entries(DB 为真源;Redis/snapshot 事后从 DB 派生)。
func (t *ThreatIntel) fetchFeed(ctx context.Context, feed feedSource) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		return 0, fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	values := make([]string, 0, 4096)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		values = append(values, line)
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("读取 Feed 响应失败: %w", err)
	}

	return t.upsertIOCEntries(ctx, feed.IOCType, feed.Name, values)
}

// upsertIOCEntries 批量 upsert 外部 IOC 到 ioc_entries。命中已存在则刷新 last_seen/expires_at/enabled(aging),
// 新条目设 first_seen。分批 500 条避免超大 SQL。
func (t *ThreatIntel) upsertIOCEntries(ctx context.Context, iocType, source string, values []string) (int, error) {
	if len(values) == 0 {
		return 0, nil
	}
	now := time.Now()
	exp := now.Add(model.IOCTypeTTL(iocType))
	const chunk = 500

	total := 0
	seen := make(map[string]struct{}, len(values))
	batch := make([]model.IOCEntry, 0, chunk)

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := t.db.WithContext(ctx).Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "ioc_type"}, {Name: "value"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"last_seen":  now,
				"expires_at": exp,
				"enabled":    true,
				"source":     source,
				"updated_at": now,
			}),
		}).Create(&batch).Error
		if err != nil {
			return err
		}
		total += len(batch)
		batch = batch[:0]
		return nil
	}

	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 512 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		batch = append(batch, model.IOCEntry{
			IOCType: iocType, Value: v, Source: source, Severity: "high",
			FirstSeen: now, LastSeen: now, ExpiresAt: &exp, Enabled: true,
		})
		if len(batch) >= chunk {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := flush(); err != nil {
		return total, err
	}
	return total, nil
}

// GetLatestSyncStatus 查询最近一条同步记录
func (t *ThreatIntel) GetLatestSyncStatus() (*model.SecurityDBSyncRecord, error) {
	var record model.SecurityDBSyncRecord
	err := t.db.Where("db_type = ?", "threat-intel").Order("id DESC").First(&record).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &record, nil
}

// GetSyncHistory 分页查询同步历史记录
func (t *ThreatIntel) GetSyncHistory(page, pageSize int) ([]model.SecurityDBSyncRecord, int64, error) {
	var total int64
	query := t.db.Model(&model.SecurityDBSyncRecord{}).Where("db_type = ?", "threat-intel")
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var records []model.SecurityDBSyncRecord
	offset := (page - 1) * pageSize
	err := query.Offset(offset).Limit(pageSize).Order("id DESC").Find(&records).Error
	return records, total, err
}

// CheckIOC 检查值是否在 IOC 集合中
func (t *ThreatIntel) CheckIOC(ctx context.Context, iocType, value string) bool {
	if t.redisClient == nil {
		return false
	}
	key := iocRedisKeyPrefix + iocType
	result, err := t.redisClient.SIsMember(ctx, key, value).Result()
	if err != nil {
		return false
	}
	return result
}

// ── IOC Snapshot Export ─────────────────────────────────────

// iocData is the JSON structure for IOC snapshots.
type iocData struct {
	IP   []string `json:"ip"`
	Hash []string `json:"hash"`
	URL  []string `json:"url"`
}

// exportSnapshot reads all IOC data from Redis, computes diff against previous
// snapshot, and writes a new IOCSnapshot record for AgentCenter to distribute.
func (t *ThreatIntel) exportSnapshot(ctx context.Context) error {
	// 1. 从 DB 读全量有效 IOC:外部持久化(ioc_entries,未过期)∪ 自有情报(local_iocs)。
	//    DB 为真源 → feed 断供也不丢;Redis 仅作派生缓存。
	current, err := t.buildIOCDataFromDB(ctx)
	if err != nil {
		return err
	}

	// 用 DB 有效集重建 Redis 缓存(CheckIOC / 兼容用;DB 才是真源)。
	t.rebuildRedisFromDB(ctx, current)

	// 2. Serialize full data.
	fullJSON, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("序列化 IOC 数据失败: %w", err)
	}

	version := fmt.Sprintf("%x", sha256.Sum256(fullJSON))[:16]
	totalCount := len(current.IP) + len(current.Hash) + len(current.URL)

	// 3. Load previous snapshot for diff.
	var prev model.IOCSnapshot
	prevExists := t.db.Order("id DESC").First(&prev).Error == nil

	var diffAdded, diffRemoved iocData
	prevVersion := ""
	if prevExists {
		prevVersion = prev.Version
		if prevVersion == version {
			t.logger.Info("IOC 快照无变化，跳过导出", zap.String("version", version))
			return nil
		}

		var prevData iocData
		if err := json.Unmarshal([]byte(prev.Data), &prevData); err == nil {
			diffAdded.IP, diffRemoved.IP = diffSets(prevData.IP, current.IP)
			diffAdded.Hash, diffRemoved.Hash = diffSets(prevData.Hash, current.Hash)
			diffAdded.URL, diffRemoved.URL = diffSets(prevData.URL, current.URL)
		}
	} else {
		// First snapshot: everything is "added".
		diffAdded = current
	}

	addedJSON, _ := json.Marshal(diffAdded)
	removedJSON, _ := json.Marshal(diffRemoved)

	// 4. Write snapshot.
	snapshot := model.IOCSnapshot{
		Version:   version,
		Data:      string(fullJSON),
		DiffAdded: string(addedJSON),
		DiffRemov: string(removedJSON),
		PrevVer:   prevVersion,
		Count:     totalCount,
	}
	if err := t.db.Create(&snapshot).Error; err != nil {
		return fmt.Errorf("写入 IOC 快照失败: %w", err)
	}

	// 5. Clean up old snapshots (keep 5).
	var old []model.IOCSnapshot
	if err := t.db.Order("id DESC").Offset(5).Find(&old).Error; err == nil && len(old) > 0 {
		ids := make([]uint, len(old))
		for i, o := range old {
			ids[i] = o.ID
		}
		t.db.Delete(&model.IOCSnapshot{}, ids)
	}

	t.logger.Info("IOC 快照导出完成",
		zap.String("version", version),
		zap.Int("total", totalCount),
		zap.Int("added", len(diffAdded.IP)+len(diffAdded.Hash)+len(diffAdded.URL)),
		zap.Int("removed", len(diffRemoved.IP)+len(diffRemoved.Hash)+len(diffRemoved.URL)),
	)
	return nil
}

// buildIOCDataFromDB 从 DB 组装有效 IOC 集:外部持久化(ioc_entries,enabled 且未过期)∪ 自有(local_iocs,enabled)。
// 快照/agent 匹配当前支持 ip/hash/url;domain 暂不下发(engine stage_ioc 未匹配域名)。
func (t *ThreatIntel) buildIOCDataFromDB(ctx context.Context) (iocData, error) {
	out := iocData{}
	now := time.Now()
	type row struct {
		IOCType string
		Value   string
	}

	var ext []row
	if err := t.db.WithContext(ctx).Model(&model.IOCEntry{}).
		Select("ioc_type", "value").
		Where("enabled = ? AND (expires_at IS NULL OR expires_at > ?)", true, now).
		Find(&ext).Error; err != nil {
		return out, fmt.Errorf("读取 ioc_entries 失败: %w", err)
	}

	var loc []row
	if err := t.db.WithContext(ctx).Model(&model.LocalIOC{}).
		Select("ioc_type", "value").Where("enabled = ?", true).Find(&loc).Error; err != nil {
		return out, fmt.Errorf("读取 local_iocs 失败: %w", err)
	}

	seen := make(map[string]struct{}, len(ext)+len(loc))
	add := func(iocType, value string) {
		k := iocType + "|" + value
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		switch iocType {
		case "ip":
			out.IP = append(out.IP, value)
		case "hash":
			out.Hash = append(out.Hash, value)
		case "url":
			out.URL = append(out.URL, value)
		}
	}
	for _, r := range ext {
		add(r.IOCType, r.Value)
	}
	for _, r := range loc {
		add(r.IOCType, r.Value)
	}
	sort.Strings(out.IP)
	sort.Strings(out.Hash)
	sort.Strings(out.URL)
	return out, nil
}

// rebuildRedisFromDB 用 DB 有效集重建 Redis IOC set(纯派生缓存;DB 是真源)。
func (t *ThreatIntel) rebuildRedisFromDB(ctx context.Context, data iocData) {
	if t.redisClient == nil {
		return
	}
	for _, e := range []struct {
		typ  string
		vals []string
	}{{"ip", data.IP}, {"hash", data.Hash}, {"url", data.URL}} {
		key := iocRedisKeyPrefix + e.typ
		pipe := t.redisClient.Pipeline()
		pipe.Del(ctx, key)
		for i := 0; i < len(e.vals); i += 1000 {
			end := i + 1000
			if end > len(e.vals) {
				end = len(e.vals)
			}
			args := make([]interface{}, 0, end-i)
			for _, v := range e.vals[i:end] {
				args = append(args, v)
			}
			if len(args) > 0 {
				pipe.SAdd(ctx, key, args...)
			}
		}
		pipe.Expire(ctx, key, iocTTL) // 缓存 TTL;过期后 sync 会重建,DB 不丢
		if _, err := pipe.Exec(ctx); err != nil {
			t.logger.Warn("重建 Redis IOC 缓存失败", zap.String("type", e.typ), zap.Error(err))
		}
	}
}

// cleanupExpiredIOCs 物理删除过期超 30 天的外部 IOC(bound 表大小);未过期/自有情报不动。
func (t *ThreatIntel) cleanupExpiredIOCs(ctx context.Context) {
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	res := t.db.WithContext(ctx).Where("expires_at IS NOT NULL AND expires_at < ?", cutoff).Delete(&model.IOCEntry{})
	if res.Error != nil {
		t.logger.Warn("清理过期 IOC 失败", zap.Error(res.Error))
		return
	}
	if res.RowsAffected > 0 {
		t.logger.Info("清理过期 IOC", zap.Int64("deleted", res.RowsAffected))
	}
}

// diffSets returns (added, removed) between old and new sorted string slices.
func diffSets(old, cur []string) (added, removed []string) {
	oldSet := make(map[string]struct{}, len(old))
	for _, v := range old {
		oldSet[v] = struct{}{}
	}
	curSet := make(map[string]struct{}, len(cur))
	for _, v := range cur {
		curSet[v] = struct{}{}
	}

	for _, v := range cur {
		if _, ok := oldSet[v]; !ok {
			added = append(added, v)
		}
	}
	for _, v := range old {
		if _, ok := curSet[v]; !ok {
			removed = append(removed, v)
		}
	}
	return
}
