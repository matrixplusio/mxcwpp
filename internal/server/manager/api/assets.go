// Package api 提供 HTTP API 处理器
package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// AssetsHandler 是资产数据 API 处理器
type AssetsHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

type assetListParams struct {
	HostID       string
	BusinessLine string
	Search       string
	Page         int
	PageSize     int
}

type AssetStatistics struct {
	Processes         int64 `json:"processes"`
	Ports             int64 `json:"ports"`
	Users             int64 `json:"users"`
	Software          int64 `json:"software"`
	Containers        int64 `json:"containers"`
	Apps              int64 `json:"apps"`
	NetworkInterfaces int64 `json:"network_interfaces"`
	Volumes           int64 `json:"volumes"`
	Kmods             int64 `json:"kmods"`
	Services          int64 `json:"services"`
	Crons             int64 `json:"crons"`
}

type AssetTopItem struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

type AssetCollectorStatus struct {
	Version         string `json:"version,omitempty"`
	ConfigEnabled   bool   `json:"config_enabled"`
	PackageUploaded bool   `json:"package_uploaded"`
	PackagePath     string `json:"package_path,omitempty"`
	HostStatus      string `json:"host_status,omitempty"`
	HostVersion     string `json:"host_version,omitempty"`
}

type AssetCollectionStatus struct {
	HostID          string               `json:"host_id,omitempty"`
	Scope           string               `json:"scope"`
	HasData         bool                 `json:"has_data"`
	LastCollectedAt string               `json:"last_collected_at,omitempty"`
	Level           string               `json:"level,omitempty"`
	Message         string               `json:"message,omitempty"`
	Collector       AssetCollectorStatus `json:"collector"`
}

type AssetOverview struct {
	Scope             string  `json:"scope"`
	TotalHosts        int64   `json:"total_hosts"`
	CoveredHosts      int64   `json:"covered_hosts"`
	UncoveredHosts    int64   `json:"uncovered_hosts"`
	OnlineHosts       int64   `json:"online_hosts"`
	OfflineHosts      int64   `json:"offline_hosts"`
	BusinessLineCount int64   `json:"business_line_count"`
	CoverageRate      float64 `json:"coverage_rate"`
	LastCollectedAt   string  `json:"last_collected_at,omitempty"`
}

type AssetHistoryPoint struct {
	Timestamp  string          `json:"timestamp"`
	Total      int64           `json:"total"`
	DeltaTotal int64           `json:"delta_total"`
	Statistics AssetStatistics `json:"statistics"`
}

type AssetHistoryResult struct {
	Scope             string              `json:"scope"`
	HostID            string              `json:"host_id,omitempty"`
	BusinessLine      string              `json:"business_line,omitempty"`
	TotalSnapshots    int                 `json:"total_snapshots"`
	LatestCollectedAt string              `json:"latest_collected_at,omitempty"`
	Points            []AssetHistoryPoint `json:"points"`
}

type AssetRelationProcess struct {
	PID         string `json:"pid"`
	PPID        string `json:"ppid"`
	Exe         string `json:"exe"`
	Cmdline     string `json:"cmdline"`
	Username    string `json:"username"`
	ContainerID string `json:"container_id,omitempty"`
	CollectedAt string `json:"collected_at,omitempty"`
}

type AssetRelationHost struct {
	HostID        string            `json:"host_id"`
	Hostname      string            `json:"hostname"`
	IPv4          model.StringArray `json:"ipv4,omitempty"`
	BusinessLine  string            `json:"business_line,omitempty"`
	Status        string            `json:"status,omitempty"`
	AgentVersion  string            `json:"agent_version,omitempty"`
	RuntimeType   string            `json:"runtime_type,omitempty"`
	LastHeartbeat string            `json:"last_heartbeat,omitempty"`
}

type AssetRelationPort struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	State    string `json:"state"`
}

type AssetRelationApp struct {
	AppType    string `json:"app_type"`
	AppName    string `json:"app_name"`
	Version    string `json:"version"`
	Port       int    `json:"port"`
	ConfigPath string `json:"config_path"`
}

type AssetRelationSoftware struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	PackageType  string `json:"package_type"`
	Architecture string `json:"architecture"`
}

type AssetRelationContainer struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	Image         string `json:"image"`
	Runtime       string `json:"runtime"`
	Status        string `json:"status"`
}

type AssetRelationService struct {
	ServiceName string `json:"service_name"`
	ServiceType string `json:"service_type"`
	Status      string `json:"status"`
	Enabled     bool   `json:"enabled"`
}

type AssetRelationConfidence struct {
	Level     string   `json:"level"`
	MatchedBy []string `json:"matched_by,omitempty"`
}

type AssetRelationVulnerability struct {
	CVEID          string `json:"cve_id"`
	Severity       string `json:"severity"`
	Component      string `json:"component"`
	Status         string `json:"status"`
	CurrentVersion string `json:"current_version,omitempty"`
	FixedVersion   string `json:"fixed_version,omitempty"`
}

type AssetRelationChange struct {
	EventID    string `json:"event_id"`
	FilePath   string `json:"file_path"`
	ChangeType string `json:"change_type"`
	Severity   string `json:"severity"`
	Category   string `json:"category,omitempty"`
	DetectedAt string `json:"detected_at"`
}

type AssetRelationRiskSummary struct {
	ExposedPortCount   int    `json:"exposed_port_count"`
	VulnerabilityCount int    `json:"vulnerability_count"`
	FIMChangeCount     int    `json:"fim_change_count"`
	LastChangedAt      string `json:"last_changed_at,omitempty"`
}

type AssetRelationItem struct {
	Host            AssetRelationHost            `json:"host"`
	Process         AssetRelationProcess         `json:"process"`
	Ports           []AssetRelationPort          `json:"ports,omitempty"`
	Apps            []AssetRelationApp           `json:"apps,omitempty"`
	Software        []AssetRelationSoftware      `json:"software,omitempty"`
	Services        []AssetRelationService       `json:"services,omitempty"`
	Container       *AssetRelationContainer      `json:"container,omitempty"`
	Confidence      AssetRelationConfidence      `json:"confidence"`
	Risks           AssetRelationRiskSummary     `json:"risks"`
	Vulnerabilities []AssetRelationVulnerability `json:"vulnerabilities,omitempty"`
	RecentChanges   []AssetRelationChange        `json:"recent_changes,omitempty"`
	RelatedKinds    []string                     `json:"related_kinds"`
	RelationScore   int                          `json:"relation_score"`
}

type AssetRelationsResult struct {
	Scope        string              `json:"scope"`
	HostID       string              `json:"host_id,omitempty"`
	BusinessLine string              `json:"business_line,omitempty"`
	Total        int                 `json:"total"`
	Items        []AssetRelationItem `json:"items"`
}

type groupedCountResult struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

type portTopResult struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Value    int64  `json:"value"`
}

// NewAssetsHandler 创建资产处理器
func NewAssetsHandler(db *gorm.DB, logger *zap.Logger) *AssetsHandler {
	return &AssetsHandler{
		db:     db,
		logger: logger,
	}
}

func parsePositiveInt(raw string, defaultValue int) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return defaultValue
	}
	return value
}

func normalizeAssetType(assetType string) string {
	switch strings.ToLower(strings.TrimSpace(assetType)) {
	case "packages":
		return "software"
	case "crontabs":
		return "crons"
	default:
		return strings.ToLower(strings.TrimSpace(assetType))
	}
}

func (h *AssetsHandler) parseAssetListParams(c *gin.Context) assetListParams {
	return assetListParams{
		HostID:       c.Query("host_id"),
		BusinessLine: c.Query("business_line"),
		Search:       strings.TrimSpace(c.Query("search")),
		Page:         parsePositiveInt(c.DefaultQuery("page", "1"), 1),
		PageSize:     parsePositiveInt(c.DefaultQuery("page_size", "20"), 20),
	}
}

func likeQuery(search string) string {
	return "%" + search + "%"
}

func applyLikeSearch(query *gorm.DB, search string, clauses ...string) *gorm.DB {
	if search == "" || len(clauses) == 0 {
		return query
	}

	like := likeQuery(search)
	args := make([]interface{}, 0, len(clauses))
	for range clauses {
		args = append(args, like)
	}

	return query.Where("("+strings.Join(clauses, " OR ")+")", args...)
}

func (h *AssetsHandler) respondAssetList(c *gin.Context, query *gorm.DB, orderBy string, page, pageSize int, dest interface{}) {
	total, err := Paginate(query, page, pageSize, orderBy, dest)
	if err != nil {
		h.logger.Error("failed to query assets", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}
	SuccessPaginated(c, total, dest)
}

func (h *AssetsHandler) collectStatistics(hostID, businessLine string) (AssetStatistics, int64, error) {
	stats := AssetStatistics{}
	counts := []struct {
		model interface{}
		dst   *int64
	}{
		{model: &model.Process{}, dst: &stats.Processes},
		{model: &model.Port{}, dst: &stats.Ports},
		{model: &model.AssetUser{}, dst: &stats.Users},
		{model: &model.Software{}, dst: &stats.Software},
		{model: &model.Container{}, dst: &stats.Containers},
		{model: &model.App{}, dst: &stats.Apps},
		{model: &model.NetInterface{}, dst: &stats.NetworkInterfaces},
		{model: &model.Volume{}, dst: &stats.Volumes},
		{model: &model.Kmod{}, dst: &stats.Kmods},
		{model: &model.Service{}, dst: &stats.Services},
		{model: &model.Cron{}, dst: &stats.Crons},
	}

	// 11 个 COUNT 并发,总延迟从 ~430ms 串行 → ~80ms (max(各 COUNT))
	g := new(errgroup.Group)
	for _, item := range counts {
		it := item // closure capture
		g.Go(func() error {
			return h.buildQuery(it.model, hostID, businessLine).Count(it.dst).Error
		})
	}
	if err := g.Wait(); err != nil {
		return AssetStatistics{}, 0, err
	}
	total := int64(0)
	for _, item := range counts {
		total += *item.dst
	}

	return stats, total, nil
}

func (h *AssetsHandler) latestCollectedAt(hostID, businessLine string) (string, error) {
	models := h.assetModels()

	var latest model.LocalTime
	found := false
	for _, assetModel := range models {
		var row struct {
			CollectedAt model.LocalTime `gorm:"column:collected_at"`
		}

		tx := h.buildQuery(assetModel, hostID, businessLine).
			Select("collected_at").
			Order("collected_at DESC").
			Limit(1).
			Find(&row)
		if tx.Error != nil {
			return "", tx.Error
		}
		if tx.RowsAffected == 0 {
			continue
		}
		if row.CollectedAt.IsZero() {
			continue
		}
		if !found || row.CollectedAt.After(latest) {
			latest = row.CollectedAt
			found = true
		}
	}

	if !found {
		return "", nil
	}
	return latest.String(), nil
}

func (h *AssetsHandler) assetModels() []interface{} {
	return []interface{}{
		&model.Process{},
		&model.Port{},
		&model.AssetUser{},
		&model.Software{},
		&model.Container{},
		&model.App{},
		&model.NetInterface{},
		&model.Volume{},
		&model.Kmod{},
		&model.Service{},
		&model.Cron{},
	}
}

func (h *AssetsHandler) collectCoveredHostIDs(hostID, businessLine string) (map[string]struct{}, error) {
	covered := make(map[string]struct{})
	for _, assetModel := range h.assetModels() {
		var hostIDs []string
		if err := h.buildQuery(assetModel, hostID, businessLine).
			Distinct("host_id").
			Pluck("host_id", &hostIDs).Error; err != nil {
			return nil, err
		}
		for _, id := range hostIDs {
			if id == "" {
				continue
			}
			covered[id] = struct{}{}
		}
	}
	return covered, nil
}

func (h *AssetsHandler) collectOverview(hostID, businessLine string) (AssetOverview, error) {
	overview := AssetOverview{Scope: "global"}
	if hostID != "" {
		overview.Scope = "host"
	}

	hostQuery := func() *gorm.DB {
		q := h.db.Model(&model.Host{})
		if hostID != "" {
			q = q.Where("host_id = ?", hostID)
		}
		if businessLine != "" {
			q = q.Where("business_line = ?", businessLine)
		}
		return q
	}

	if err := hostQuery().Count(&overview.TotalHosts).Error; err != nil {
		return overview, err
	}
	if err := hostQuery().Where("status = ?", model.HostStatusOnline).Count(&overview.OnlineHosts).Error; err != nil {
		return overview, err
	}
	overview.OfflineHosts = overview.TotalHosts - overview.OnlineHosts

	var businessLineRow struct {
		Count int64 `gorm:"column:count"`
	}
	if err := hostQuery().
		Select("COUNT(DISTINCT business_line) AS count").
		Where("business_line <> ''").
		Scan(&businessLineRow).Error; err != nil {
		return overview, err
	}
	overview.BusinessLineCount = businessLineRow.Count

	covered, err := h.collectCoveredHostIDs(hostID, businessLine)
	if err != nil {
		return overview, err
	}
	overview.CoveredHosts = int64(len(covered))
	if overview.CoveredHosts > overview.TotalHosts {
		overview.CoveredHosts = overview.TotalHosts
	}
	overview.UncoveredHosts = overview.TotalHosts - overview.CoveredHosts
	if overview.TotalHosts > 0 {
		overview.CoverageRate = float64(overview.CoveredHosts) / float64(overview.TotalHosts) * 100
	}

	overview.LastCollectedAt, err = h.latestCollectedAt(hostID, businessLine)
	if err != nil {
		return overview, err
	}

	return overview, nil
}

func (h *AssetsHandler) collectHistory(hostID, businessLine string, days, limit int) (AssetHistoryResult, error) {
	result := AssetHistoryResult{
		Scope:        "global",
		HostID:       hostID,
		BusinessLine: businessLine,
	}
	if hostID != "" {
		result.Scope = "host"
	}

	type historyModelDef struct {
		model interface{}
		apply func(*AssetStatistics, int64)
	}

	models := []historyModelDef{
		{model: &model.Process{}, apply: func(stats *AssetStatistics, value int64) { stats.Processes = value }},
		{model: &model.Port{}, apply: func(stats *AssetStatistics, value int64) { stats.Ports = value }},
		{model: &model.AssetUser{}, apply: func(stats *AssetStatistics, value int64) { stats.Users = value }},
		{model: &model.Software{}, apply: func(stats *AssetStatistics, value int64) { stats.Software = value }},
		{model: &model.Container{}, apply: func(stats *AssetStatistics, value int64) { stats.Containers = value }},
		{model: &model.App{}, apply: func(stats *AssetStatistics, value int64) { stats.Apps = value }},
		{model: &model.NetInterface{}, apply: func(stats *AssetStatistics, value int64) { stats.NetworkInterfaces = value }},
		{model: &model.Volume{}, apply: func(stats *AssetStatistics, value int64) { stats.Volumes = value }},
		{model: &model.Kmod{}, apply: func(stats *AssetStatistics, value int64) { stats.Kmods = value }},
		{model: &model.Service{}, apply: func(stats *AssetStatistics, value int64) { stats.Services = value }},
		{model: &model.Cron{}, apply: func(stats *AssetStatistics, value int64) { stats.Crons = value }},
	}

	pointMap := make(map[string]*AssetHistoryPoint)
	var pointMu sync.Mutex
	cutoff := time.Now().AddDate(0, 0, -days)

	// GROUP BY DATE(collected_at) 按日聚合:
	// agent 每秒上报 snapshot → collected_at 含每秒一个 distinct value,
	// 7d 累积 ~60w 个 distinct value,MySQL GROUP BY 完全精度在大表上 1.5s+;
	// DATE 聚合后 7d 仅 7 行 → <50ms。UI 历史 chart 用 daily 趋势,无需秒级精度。
	// 11 个 model 并发,各 query 独立 IO 走 collected_at index range scan。
	g := new(errgroup.Group)
	type dailyRow struct {
		Day   string `gorm:"column:day"`
		Value int64
	}
	for _, modelDef := range models {
		md := modelDef
		g.Go(func() error {
			query := h.buildQuery(md.model, hostID, businessLine)
			if days > 0 {
				query = query.Where("collected_at >= ?", cutoff)
			}
			var rows []dailyRow
			if err := query.
				Select("DATE(collected_at) AS day, COUNT(*) AS value").
				Group("DATE(collected_at)").
				Order("day ASC").
				Scan(&rows).Error; err != nil {
				return err
			}
			pointMu.Lock()
			defer pointMu.Unlock()
			for _, row := range rows {
				if row.Day == "" {
					continue
				}
				point := pointMap[row.Day]
				if point == nil {
					point = &AssetHistoryPoint{Timestamp: row.Day}
					pointMap[row.Day] = point
				}
				md.apply(&point.Statistics, row.Value)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return result, err
	}

	points := make([]AssetHistoryPoint, 0, len(pointMap))
	for _, point := range pointMap {
		point.Total = point.Statistics.Processes +
			point.Statistics.Ports +
			point.Statistics.Users +
			point.Statistics.Software +
			point.Statistics.Containers +
			point.Statistics.Apps +
			point.Statistics.NetworkInterfaces +
			point.Statistics.Volumes +
			point.Statistics.Kmods +
			point.Statistics.Services +
			point.Statistics.Crons
		points = append(points, *point)
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp < points[j].Timestamp
	})

	if limit > 0 && len(points) > limit {
		points = points[len(points)-limit:]
	}

	var previousTotal int64
	for i := range points {
		if i == 0 {
			points[i].DeltaTotal = 0
		} else {
			points[i].DeltaTotal = points[i].Total - previousTotal
		}
		previousTotal = points[i].Total
	}

	result.TotalSnapshots = len(points)
	if len(points) > 0 {
		result.LatestCollectedAt = points[len(points)-1].Timestamp
	}
	result.Points = points
	return result, nil
}

var ignoredRelationTokens = map[string]struct{}{
	"":       {},
	"bin":    {},
	"sbin":   {},
	"usr":    {},
	"local":  {},
	"opt":    {},
	"lib":    {},
	"lib64":  {},
	"run":    {},
	"daemon": {},
	"server": {},
}

func tokenizeRelationValue(value string) []string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return nil
	}

	candidates := []string{normalized, filepath.Base(normalized)}
	unique := make(map[string]struct{})
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		candidate = strings.TrimSuffix(candidate, ".service")
		candidate = strings.TrimSuffix(candidate, ".socket")
		candidate = strings.TrimSuffix(candidate, ".timer")
		candidate = strings.TrimSuffix(candidate, ".target")
		candidate = strings.Split(candidate, ":")[0]

		var builder strings.Builder
		for _, r := range candidate {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				builder.WriteRune(r)
			} else {
				builder.WriteByte(' ')
			}
		}

		for _, token := range strings.Fields(builder.String()) {
			if len(token) < 2 {
				continue
			}
			if _, ignored := ignoredRelationTokens[token]; ignored {
				continue
			}
			unique[token] = struct{}{}
		}
	}

	tokens := make([]string, 0, len(unique))
	for token := range unique {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	return tokens
}

func collectRelationTokens(values ...string) []string {
	unique := make(map[string]struct{})
	for _, value := range values {
		for _, token := range tokenizeRelationValue(value) {
			unique[token] = struct{}{}
		}
	}

	tokens := make([]string, 0, len(unique))
	for token := range unique {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	return tokens
}

func joinRelatedKinds(ports []AssetRelationPort, apps []AssetRelationApp, software []AssetRelationSoftware, services []AssetRelationService, container *AssetRelationContainer) []string {
	kinds := make([]string, 0, 5)
	if len(ports) > 0 {
		kinds = append(kinds, "ports")
	}
	if len(apps) > 0 {
		kinds = append(kinds, "apps")
	}
	if len(software) > 0 {
		kinds = append(kinds, "software")
	}
	if len(services) > 0 {
		kinds = append(kinds, "services")
	}
	if container != nil {
		kinds = append(kinds, "container")
	}
	return kinds
}

func uniqueSortedKeys(values map[string]struct{}) []string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return items
}

func relationConfidenceLevel(exactCount, heuristicCount int) string {
	switch {
	case exactCount > 0 && heuristicCount > 0:
		return "mixed"
	case exactCount > 0:
		return "exact"
	default:
		return "heuristic"
	}
}

func severityWeight(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func buildRelationHost(host model.Host) AssetRelationHost {
	relationHost := AssetRelationHost{
		HostID:       host.HostID,
		Hostname:     host.Hostname,
		IPv4:         host.IPv4,
		BusinessLine: host.BusinessLine,
		Status:       string(host.Status),
		AgentVersion: host.AgentVersion,
		RuntimeType:  string(host.RuntimeType),
	}
	if host.LastHeartbeat != nil && !host.LastHeartbeat.IsZero() {
		relationHost.LastHeartbeat = host.LastHeartbeat.String()
	}
	return relationHost
}

type assetRelationVulnerabilityRecord struct {
	HostID         string
	CVEID          string
	Severity       string
	Component      string
	Status         string
	CurrentVersion string
	FixedVersion   string
}

func filePathMatchesRelation(filePath string, exactPaths []string, tokens []string) (bool, string) {
	normalizedPath := strings.ToLower(strings.TrimSpace(filePath))
	if normalizedPath == "" {
		return false, ""
	}

	for _, exactPath := range exactPaths {
		if exactPath == "" {
			continue
		}
		if strings.EqualFold(normalizedPath, strings.ToLower(strings.TrimSpace(exactPath))) {
			return true, "path->fim"
		}
	}

	pathTokens := tokenizeRelationValue(normalizedPath)
	for _, token := range tokens {
		for _, pathToken := range pathTokens {
			if token == pathToken {
				return true, "token->fim"
			}
		}
	}
	return false, ""
}

func matchRelationKeyword(item AssetRelationItem, keyword string) bool {
	if keyword == "" {
		return true
	}

	targets := []string{
		item.Host.Hostname,
		item.Host.HostID,
		item.Host.BusinessLine,
		item.Process.PID,
		item.Process.Exe,
		item.Process.Cmdline,
		item.Process.Username,
	}
	if item.Container != nil {
		targets = append(targets, item.Container.ContainerID, item.Container.ContainerName, item.Container.Image)
	}
	for _, port := range item.Ports {
		targets = append(targets, fmt.Sprintf("%s/%d", port.Protocol, port.Port), port.State)
	}
	for _, app := range item.Apps {
		targets = append(targets, app.AppType, app.AppName, app.Version, app.ConfigPath)
	}
	for _, pkg := range item.Software {
		targets = append(targets, pkg.Name, pkg.Version, pkg.PackageType)
	}
	for _, svc := range item.Services {
		targets = append(targets, svc.ServiceName, svc.ServiceType, svc.Status)
	}
	for _, vuln := range item.Vulnerabilities {
		targets = append(targets, vuln.CVEID, vuln.Component, vuln.Severity, vuln.Status)
	}
	for _, change := range item.RecentChanges {
		targets = append(targets, change.FilePath, change.ChangeType, change.Severity, change.Category)
	}
	targets = append(targets, item.Confidence.Level)
	targets = append(targets, item.Confidence.MatchedBy...)

	for _, target := range targets {
		if strings.Contains(strings.ToLower(target), keyword) {
			return true
		}
	}
	return false
}

func (h *AssetsHandler) collectRelations(hostID, businessLine, keyword string, limit int) (AssetRelationsResult, error) {
	result := AssetRelationsResult{
		Scope:        "global",
		HostID:       hostID,
		BusinessLine: businessLine,
	}
	if hostID != "" {
		result.Scope = "host"
	}

	hostQuery := h.db.Model(&model.Host{})
	if hostID != "" {
		hostQuery = hostQuery.Where("host_id = ?", hostID)
	}
	if businessLine != "" {
		hostQuery = hostQuery.Where("business_line = ?", businessLine)
	}

	var hosts []model.Host
	if err := hostQuery.Find(&hosts).Error; err != nil {
		return result, err
	}
	if len(hosts) == 0 {
		return result, nil
	}

	hostByID := make(map[string]model.Host, len(hosts))
	hostIDs := make([]string, 0, len(hosts))
	for _, host := range hosts {
		hostByID[host.HostID] = host
		hostIDs = append(hostIDs, host.HostID)
	}

	var processes []model.Process
	if err := h.buildQuery(&model.Process{}, hostID, businessLine).
		Order("collected_at DESC").
		Find(&processes).Error; err != nil {
		return result, err
	}
	if len(processes) == 0 {
		return result, nil
	}

	var ports []model.Port
	if err := h.buildQuery(&model.Port{}, hostID, businessLine).Find(&ports).Error; err != nil {
		return result, err
	}

	var apps []model.App
	if err := h.buildQuery(&model.App{}, hostID, businessLine).Find(&apps).Error; err != nil {
		return result, err
	}

	var software []model.Software
	if err := h.buildQuery(&model.Software{}, hostID, businessLine).Find(&software).Error; err != nil {
		return result, err
	}

	var containers []model.Container
	if err := h.buildQuery(&model.Container{}, hostID, businessLine).Find(&containers).Error; err != nil {
		return result, err
	}

	var services []model.Service
	if err := h.buildQuery(&model.Service{}, hostID, businessLine).Find(&services).Error; err != nil {
		return result, err
	}

	var vulnerabilities []assetRelationVulnerabilityRecord
	if err := h.db.Table("host_vulnerabilities AS hv").
		Select("hv.host_id AS host_id, v.cve_id AS cve_id, v.severity AS severity, v.component AS component, hv.status AS status, hv.current_version AS current_version, v.fixed_version AS fixed_version").
		Joins("JOIN vulnerabilities v ON v.id = hv.vuln_id").
		Where("hv.host_id IN ?", hostIDs).
		Find(&vulnerabilities).Error; err != nil {
		return result, err
	}

	var fimEvents []model.FIMEvent
	if err := h.db.Model(&model.FIMEvent{}).
		Where("host_id IN ?", hostIDs).
		Order("detected_at DESC").
		Limit(1000).
		Find(&fimEvents).Error; err != nil {
		return result, err
	}

	portsByHostPID := make(map[string][]model.Port)
	portsByHostContainerID := make(map[string][]model.Port)
	for _, port := range ports {
		if port.PID != "" {
			key := port.HostID + "::" + port.PID
			portsByHostPID[key] = append(portsByHostPID[key], port)
		}
		if port.ContainerID != "" {
			key := port.HostID + "::" + port.ContainerID
			portsByHostContainerID[key] = append(portsByHostContainerID[key], port)
		}
	}

	appsByHostProcessID := make(map[string][]model.App)
	appsByHostPort := make(map[string][]model.App)
	appTokenMap := make(map[string][]model.App)
	appExactMap := make(map[string][]model.App)
	for _, app := range apps {
		if app.ProcessID != "" {
			key := app.HostID + "::" + app.ProcessID
			appsByHostProcessID[key] = append(appsByHostProcessID[key], app)
		}
		if app.Port > 0 {
			key := fmt.Sprintf("%s::%d", app.HostID, app.Port)
			appsByHostPort[key] = append(appsByHostPort[key], app)
		}
		for _, token := range collectRelationTokens(app.AppType, app.AppName) {
			key := app.HostID + "::" + token
			appTokenMap[key] = append(appTokenMap[key], app)
		}
		for _, exactName := range []string{strings.ToLower(strings.TrimSpace(app.AppType)), strings.ToLower(strings.TrimSpace(app.AppName))} {
			if exactName == "" {
				continue
			}
			key := app.HostID + "::" + exactName
			appExactMap[key] = append(appExactMap[key], app)
		}
	}

	containerByHostContainerID := make(map[string]model.Container)
	for _, container := range containers {
		if container.ContainerID == "" {
			continue
		}
		key := container.HostID + "::" + container.ContainerID
		containerByHostContainerID[key] = container
	}

	serviceTokenMap := make(map[string][]model.Service)
	serviceExactMap := make(map[string][]model.Service)
	for _, service := range services {
		for _, token := range collectRelationTokens(service.ServiceName) {
			key := service.HostID + "::" + token
			serviceTokenMap[key] = append(serviceTokenMap[key], service)
		}
		exactName := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(service.ServiceName, ".service")))
		if exactName != "" {
			key := service.HostID + "::" + exactName
			serviceExactMap[key] = append(serviceExactMap[key], service)
		}
	}

	softwareTokenMap := make(map[string][]model.Software)
	softwareExactMap := make(map[string][]model.Software)
	for _, pkg := range software {
		for _, token := range collectRelationTokens(pkg.Name) {
			key := pkg.HostID + "::" + token
			softwareTokenMap[key] = append(softwareTokenMap[key], pkg)
		}
		exactName := strings.ToLower(strings.TrimSpace(pkg.Name))
		if exactName != "" {
			key := pkg.HostID + "::" + exactName
			softwareExactMap[key] = append(softwareExactMap[key], pkg)
		}
	}

	vulnsByHost := make(map[string][]assetRelationVulnerabilityRecord)
	for _, vuln := range vulnerabilities {
		vulnsByHost[vuln.HostID] = append(vulnsByHost[vuln.HostID], vuln)
	}

	fimEventsByHost := make(map[string][]model.FIMEvent)
	for _, event := range fimEvents {
		fimEventsByHost[event.HostID] = append(fimEventsByHost[event.HostID], event)
	}

	keyword = strings.ToLower(strings.TrimSpace(keyword))
	items := make([]AssetRelationItem, 0, len(processes))
	for _, process := range processes {
		host := hostByID[process.HostID]
		exeBase := strings.ToLower(strings.TrimSpace(filepath.Base(process.Exe)))
		processTokens := collectRelationTokens(process.Exe, process.Cmdline)
		exactMatchReasons := make(map[string]struct{})
		heuristicMatchReasons := make(map[string]struct{})

		portMap := make(map[string]AssetRelationPort)
		for _, port := range portsByHostPID[process.HostID+"::"+process.PID] {
			key := fmt.Sprintf("%s/%d/%s", port.Protocol, port.Port, port.State)
			portMap[key] = AssetRelationPort{Protocol: port.Protocol, Port: port.Port, State: port.State}
			exactMatchReasons["pid->port"] = struct{}{}
		}
		if len(portMap) == 0 && process.ContainerID != "" {
			for _, port := range portsByHostContainerID[process.HostID+"::"+process.ContainerID] {
				key := fmt.Sprintf("%s/%d/%s", port.Protocol, port.Port, port.State)
				portMap[key] = AssetRelationPort{Protocol: port.Protocol, Port: port.Port, State: port.State}
				exactMatchReasons["container_id->port"] = struct{}{}
			}
		}

		appMap := make(map[string]AssetRelationApp)
		for _, app := range appsByHostProcessID[process.HostID+"::"+process.PID] {
			appMap[app.ID] = AssetRelationApp{
				AppType: app.AppType, AppName: app.AppName, Version: app.Version, Port: app.Port, ConfigPath: app.ConfigPath,
			}
			exactMatchReasons["process_id->app"] = struct{}{}
		}
		for _, port := range portMap {
			for _, app := range appsByHostPort[fmt.Sprintf("%s::%d", process.HostID, port.Port)] {
				appMap[app.ID] = AssetRelationApp{
					AppType: app.AppType, AppName: app.AppName, Version: app.Version, Port: app.Port, ConfigPath: app.ConfigPath,
				}
				exactMatchReasons["port->app"] = struct{}{}
			}
		}
		if exeBase != "" {
			for _, app := range appExactMap[process.HostID+"::"+exeBase] {
				appMap[app.ID] = AssetRelationApp{
					AppType: app.AppType, AppName: app.AppName, Version: app.Version, Port: app.Port, ConfigPath: app.ConfigPath,
				}
				exactMatchReasons["exe->app"] = struct{}{}
			}
		}
		for _, token := range processTokens {
			for _, app := range appTokenMap[process.HostID+"::"+token] {
				appMap[app.ID] = AssetRelationApp{
					AppType: app.AppType, AppName: app.AppName, Version: app.Version, Port: app.Port, ConfigPath: app.ConfigPath,
				}
				heuristicMatchReasons["token->app"] = struct{}{}
			}
		}

		var container *AssetRelationContainer
		containerTokens := make([]string, 0, 4)
		if process.ContainerID != "" {
			if matched, ok := containerByHostContainerID[process.HostID+"::"+process.ContainerID]; ok {
				container = &AssetRelationContainer{
					ContainerID: matched.ContainerID, ContainerName: matched.ContainerName, Image: matched.Image, Runtime: matched.Runtime, Status: matched.Status,
				}
				containerTokens = append(containerTokens, collectRelationTokens(matched.ContainerName, matched.Image)...)
				exactMatchReasons["container_id->container"] = struct{}{}
			}
		}

		serviceMap := make(map[string]AssetRelationService)
		if exeBase != "" {
			for _, service := range serviceExactMap[process.HostID+"::"+exeBase] {
				serviceMap[service.ID] = AssetRelationService{
					ServiceName: service.ServiceName, ServiceType: service.ServiceType, Status: service.Status, Enabled: service.Enabled,
				}
				exactMatchReasons["exe->service"] = struct{}{}
			}
		}
		for _, token := range processTokens {
			for _, service := range serviceTokenMap[process.HostID+"::"+token] {
				serviceMap[service.ID] = AssetRelationService{
					ServiceName: service.ServiceName, ServiceType: service.ServiceType, Status: service.Status, Enabled: service.Enabled,
				}
				heuristicMatchReasons["token->service"] = struct{}{}
			}
		}

		softwareMap := make(map[string]AssetRelationSoftware)
		if exeBase != "" {
			for _, pkg := range softwareExactMap[process.HostID+"::"+exeBase] {
				softwareMap[pkg.ID] = AssetRelationSoftware{
					Name: pkg.Name, Version: pkg.Version, PackageType: pkg.PackageType, Architecture: pkg.Architecture,
				}
				exactMatchReasons["exe->software"] = struct{}{}
			}
		}
		softwareTokens := append([]string{}, processTokens...)
		for _, app := range appMap {
			softwareTokens = append(softwareTokens, collectRelationTokens(app.AppType, app.AppName)...)
		}
		for _, service := range serviceMap {
			softwareTokens = append(softwareTokens, collectRelationTokens(service.ServiceName)...)
		}
		softwareTokens = append(softwareTokens, containerTokens...)
		for _, token := range softwareTokens {
			for _, pkg := range softwareTokenMap[process.HostID+"::"+token] {
				softwareMap[pkg.ID] = AssetRelationSoftware{
					Name: pkg.Name, Version: pkg.Version, PackageType: pkg.PackageType, Architecture: pkg.Architecture,
				}
				heuristicMatchReasons["token->software"] = struct{}{}
			}
		}

		portsOut := make([]AssetRelationPort, 0, len(portMap))
		for _, port := range portMap {
			portsOut = append(portsOut, port)
		}
		sort.Slice(portsOut, func(i, j int) bool {
			if portsOut[i].Port == portsOut[j].Port {
				return portsOut[i].Protocol < portsOut[j].Protocol
			}
			return portsOut[i].Port < portsOut[j].Port
		})

		appsOut := make([]AssetRelationApp, 0, len(appMap))
		appExactNames := make(map[string]struct{})
		for _, app := range appMap {
			appsOut = append(appsOut, app)
			for _, exactName := range []string{strings.ToLower(strings.TrimSpace(app.AppType)), strings.ToLower(strings.TrimSpace(app.AppName))} {
				if exactName != "" {
					appExactNames[exactName] = struct{}{}
				}
			}
		}
		sort.Slice(appsOut, func(i, j int) bool {
			left := strings.ToLower(appsOut[i].AppName + appsOut[i].AppType)
			right := strings.ToLower(appsOut[j].AppName + appsOut[j].AppType)
			return left < right
		})

		softwareOut := make([]AssetRelationSoftware, 0, len(softwareMap))
		softwareExactNames := make(map[string]struct{})
		for _, pkg := range softwareMap {
			softwareOut = append(softwareOut, pkg)
			exactName := strings.ToLower(strings.TrimSpace(pkg.Name))
			if exactName != "" {
				softwareExactNames[exactName] = struct{}{}
			}
		}
		sort.Slice(softwareOut, func(i, j int) bool {
			return strings.ToLower(softwareOut[i].Name) < strings.ToLower(softwareOut[j].Name)
		})

		servicesOut := make([]AssetRelationService, 0, len(serviceMap))
		for _, service := range serviceMap {
			servicesOut = append(servicesOut, service)
		}
		sort.Slice(servicesOut, func(i, j int) bool {
			return strings.ToLower(servicesOut[i].ServiceName) < strings.ToLower(servicesOut[j].ServiceName)
		})

		if len(portsOut) == 0 && len(appsOut) == 0 && len(softwareOut) == 0 && len(servicesOut) == 0 && container == nil {
			continue
		}

		softwareTokenSet := make(map[string]struct{})
		for _, token := range softwareTokens {
			if token != "" {
				softwareTokenSet[token] = struct{}{}
			}
		}

		vulnMap := make(map[string]AssetRelationVulnerability)
		for _, vuln := range vulnsByHost[process.HostID] {
			exactComponent := strings.ToLower(strings.TrimSpace(vuln.Component))
			vulnMatched := false
			if exactComponent != "" {
				if _, ok := softwareExactNames[exactComponent]; ok {
					exactMatchReasons["software->vulnerability"] = struct{}{}
					vulnMatched = true
				}
				if _, ok := appExactNames[exactComponent]; ok {
					exactMatchReasons["app->vulnerability"] = struct{}{}
					vulnMatched = true
				}
				if exactComponent == exeBase {
					exactMatchReasons["exe->vulnerability"] = struct{}{}
					vulnMatched = true
				}
			}
			if !vulnMatched {
				for _, token := range collectRelationTokens(vuln.Component) {
					_, vulnMatched = softwareTokenSet[token]
					for _, processToken := range processTokens {
						if token == processToken {
							vulnMatched = true
							break
						}
					}
					if vulnMatched {
						heuristicMatchReasons["token->vulnerability"] = struct{}{}
						break
					}
				}
			}
			if vulnMatched {
				key := vuln.CVEID + "::" + vuln.Component
				vulnMap[key] = AssetRelationVulnerability{
					CVEID: vuln.CVEID, Severity: vuln.Severity, Component: vuln.Component, Status: vuln.Status, CurrentVersion: vuln.CurrentVersion, FixedVersion: vuln.FixedVersion,
				}
			}
		}

		vulnerabilitiesOut := make([]AssetRelationVulnerability, 0, len(vulnMap))
		for _, vuln := range vulnMap {
			vulnerabilitiesOut = append(vulnerabilitiesOut, vuln)
		}
		sort.Slice(vulnerabilitiesOut, func(i, j int) bool {
			left := severityWeight(vulnerabilitiesOut[i].Severity)
			right := severityWeight(vulnerabilitiesOut[j].Severity)
			if left == right {
				return vulnerabilitiesOut[i].CVEID < vulnerabilitiesOut[j].CVEID
			}
			return left > right
		})
		if len(vulnerabilitiesOut) > 3 {
			vulnerabilitiesOut = vulnerabilitiesOut[:3]
		}

		exactPaths := []string{process.Exe}
		for _, app := range appsOut {
			if app.ConfigPath != "" {
				exactPaths = append(exactPaths, app.ConfigPath)
			}
		}
		recentChanges := make([]AssetRelationChange, 0, 3)
		fimChangeCount := 0
		lastChangedAt := ""
		for _, event := range fimEventsByHost[process.HostID] {
			matched, reason := filePathMatchesRelation(event.FilePath, exactPaths, append(processTokens, containerTokens...))
			if !matched {
				continue
			}
			if reason == "path->fim" {
				exactMatchReasons[reason] = struct{}{}
			} else {
				heuristicMatchReasons[reason] = struct{}{}
			}
			fimChangeCount++
			if lastChangedAt == "" {
				lastChangedAt = event.DetectedAt.String()
			}
			if len(recentChanges) < 3 {
				recentChanges = append(recentChanges, AssetRelationChange{
					EventID: event.EventID, FilePath: event.FilePath, ChangeType: event.ChangeType, Severity: event.Severity, Category: event.Category, DetectedAt: event.DetectedAt.String(),
				})
			}
		}

		matchedBy := uniqueSortedKeys(exactMatchReasons)
		matchedBy = append(matchedBy, uniqueSortedKeys(heuristicMatchReasons)...)

		item := AssetRelationItem{
			Host: buildRelationHost(host),
			Process: AssetRelationProcess{
				PID:         process.PID,
				PPID:        process.PPID,
				Exe:         process.Exe,
				Cmdline:     process.Cmdline,
				Username:    process.Username,
				ContainerID: process.ContainerID,
				CollectedAt: process.CollectedAt.String(),
			},
			Ports:           portsOut,
			Apps:            appsOut,
			Software:        softwareOut,
			Services:        servicesOut,
			Container:       container,
			Confidence:      AssetRelationConfidence{Level: relationConfidenceLevel(len(exactMatchReasons), len(heuristicMatchReasons)), MatchedBy: matchedBy},
			Risks:           AssetRelationRiskSummary{ExposedPortCount: len(portsOut), VulnerabilityCount: len(vulnMap), FIMChangeCount: fimChangeCount, LastChangedAt: lastChangedAt},
			Vulnerabilities: vulnerabilitiesOut,
			RecentChanges:   recentChanges,
			RelatedKinds:    joinRelatedKinds(portsOut, appsOut, softwareOut, servicesOut, container),
			RelationScore:   len(portsOut) + len(appsOut) + len(softwareOut) + len(servicesOut),
		}
		if container != nil {
			item.RelationScore++
		}
		item.RelationScore += len(exactMatchReasons) * 2
		item.RelationScore += len(heuristicMatchReasons)
		item.RelationScore += len(vulnMap) * 2
		item.RelationScore += fimChangeCount

		if !matchRelationKeyword(item, keyword) {
			continue
		}
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].RelationScore == items[j].RelationScore {
			if items[i].Host.HostID == items[j].Host.HostID {
				return items[i].Process.PID < items[j].Process.PID
			}
			return items[i].Host.HostID < items[j].Host.HostID
		}
		return items[i].RelationScore > items[j].RelationScore
	})

	result.Total = len(items)
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	result.Items = items
	return result, nil
}

func (h *AssetsHandler) resolveCollectorStatus(hostID string) (AssetCollectorStatus, error) {
	status := AssetCollectorStatus{}

	var pluginConfig model.PluginConfig
	tx := h.db.Where("name = ?", "collector").Limit(1).Find(&pluginConfig)
	if tx.Error != nil {
		return status, tx.Error
	}
	if tx.RowsAffected > 0 {
		status.Version = pluginConfig.Version
		status.ConfigEnabled = pluginConfig.Enabled
	}

	if status.Version == "" {
		var version model.ComponentVersion
		tx = h.db.
			Joins("JOIN components ON components.id = component_versions.component_id").
			Where("components.name = ? AND components.category = ? AND component_versions.is_latest = ?", "collector", model.ComponentCategoryPlugin, true).
			Limit(1).
			Find(&version)
		if tx.Error != nil {
			return status, tx.Error
		}
		if tx.RowsAffected > 0 {
			status.Version = version.Version
		}
	}

	if status.Version != "" {
		var pkg model.ComponentPackage
		tx = h.db.
			Joins("JOIN component_versions ON component_versions.id = component_packages.version_id").
			Joins("JOIN components ON components.id = component_versions.component_id").
			Where("components.name = ? AND components.category = ? AND component_versions.version = ? AND component_packages.pkg_type = ? AND component_packages.enabled = ?",
				"collector", model.ComponentCategoryPlugin, status.Version, model.PackageTypeBinary, true).
			Order("CASE WHEN component_packages.arch = 'amd64' THEN 0 ELSE 1 END").
			Limit(1).
			Find(&pkg)
		if tx.Error != nil {
			return status, tx.Error
		}
		if tx.RowsAffected > 0 {
			status.PackagePath = pkg.FilePath
			if info, statErr := os.Stat(pkg.FilePath); statErr == nil && !info.IsDir() {
				status.PackageUploaded = true
			}
		}
	}

	if hostID == "" {
		return status, nil
	}

	var hostPlugin model.HostPlugin
	tx = h.db.
		Where("host_id = ? AND name = ?", hostID, "collector").
		Order("updated_at DESC").
		Limit(1).
		Find(&hostPlugin)
	if tx.Error != nil {
		return status, tx.Error
	}
	if tx.RowsAffected > 0 {
		status.HostStatus = string(hostPlugin.Status)
		status.HostVersion = hostPlugin.Version
		return status, nil
	}

	switch {
	case !status.PackageUploaded:
		status.HostStatus = "not_uploaded"
	case !status.ConfigEnabled:
		status.HostStatus = "disabled"
	default:
		status.HostStatus = "not_installed"
	}

	return status, nil
}

func buildAssetCollectionMessage(hostID string, status AssetCollectorStatus, hasData bool) (string, string) {
	scopeName := "资产指纹"
	if hostID != "" {
		scopeName = "当前主机资产指纹"
	}

	switch {
	case !status.PackageUploaded:
		return "error", fmt.Sprintf("%s未启用采集，因为 collector 插件包尚未上传。请先在系统组件中上传 collector 插件。", scopeName)
	case !status.ConfigEnabled:
		return "warning", fmt.Sprintf("%s未启用采集，因为 collector 插件配置当前处于禁用状态。", scopeName)
	}

	if hostID == "" {
		if !hasData {
			return "warning", "collector 已启用，但系统尚未收到任何资产指纹数据。请检查 Agent 是否已安装并运行 collector。"
		}
		return "", ""
	}

	switch status.HostStatus {
	case "running":
		if !hasData {
			return "warning", "collector 已运行，但当前主机尚未上报资产指纹数据。请检查 Agent 日志与 Kafka/Consumer 链路。"
		}
	case "error":
		return "error", "collector 插件在当前主机上处于异常状态，请检查 Agent 日志。"
	case "stopped":
		return "warning", "collector 插件在当前主机上已停止，当前不会继续采集资产指纹。"
	case "not_installed":
		return "warning", "当前主机尚未安装或启动 collector 插件，因此没有资产指纹数据。"
	case "disabled":
		return "warning", "collector 插件配置未启用，当前主机不会收到资产采集配置。"
	case "not_uploaded":
		return "error", "collector 插件包尚未上传，当前主机无法采集资产指纹。"
	}

	if !hasData {
		return "warning", "当前主机暂未采集到资产指纹数据。"
	}
	return "", ""
}

// ListProcesses 获取进程列表
// GET /api/v1/assets/processes
func (h *AssetsHandler) ListProcesses(c *gin.Context) {
	params := h.parseAssetListParams(c)
	query := h.buildQuery(&model.Process{}, params.HostID, params.BusinessLine)
	query = applyLikeSearch(query, params.Search,
		"pid LIKE ?",
		"ppid LIKE ?",
		"exe LIKE ?",
		"cmdline LIKE ?",
		"username LIKE ?",
	)
	var processes []model.Process
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &processes)
}

// ListPorts 获取端口列表
// GET /api/v1/assets/ports
func (h *AssetsHandler) ListPorts(c *gin.Context) {
	params := h.parseAssetListParams(c)
	protocol := c.Query("protocol")

	query := h.buildQuery(&model.Port{}, params.HostID, params.BusinessLine)
	if protocol != "" {
		query = query.Where("protocol = ?", protocol)
	}
	if params.Search != "" {
		if port, err := strconv.Atoi(params.Search); err == nil {
			query = query.Where("(port = ? OR process_name LIKE ? OR pid LIKE ?)", port, likeQuery(params.Search), likeQuery(params.Search))
		} else {
			query = applyLikeSearch(query, params.Search,
				"process_name LIKE ?",
				"pid LIKE ?",
				"state LIKE ?",
			)
		}
	}

	var ports []model.Port
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &ports)
}

// ListUsers 获取账户列表
// GET /api/v1/assets/users
func (h *AssetsHandler) ListUsers(c *gin.Context) {
	params := h.parseAssetListParams(c)
	query := h.buildQuery(&model.AssetUser{}, params.HostID, params.BusinessLine)
	query = applyLikeSearch(query, params.Search,
		"username LIKE ?",
		"uid LIKE ?",
		"groupname LIKE ?",
		"home_dir LIKE ?",
		"shell LIKE ?",
	)
	var users []model.AssetUser
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &users)
}

// ListSoftware 获取软件包列表
// GET /api/v1/assets/software
func (h *AssetsHandler) ListSoftware(c *gin.Context) {
	params := h.parseAssetListParams(c)
	packageType := c.Query("package_type")

	query := h.buildQuery(&model.Software{}, params.HostID, params.BusinessLine)
	if packageType != "" {
		query = query.Where("package_type = ?", packageType)
	}
	query = applyLikeSearch(query, params.Search,
		"name LIKE ?",
		"version LIKE ?",
		"package_type LIKE ?",
		"architecture LIKE ?",
		"vendor LIKE ?",
	)
	var software []model.Software
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &software)
}

// ListContainers 获取容器列表
// GET /api/v1/assets/containers
func (h *AssetsHandler) ListContainers(c *gin.Context) {
	params := h.parseAssetListParams(c)
	runtime := c.Query("runtime")
	status := c.Query("status")

	query := h.buildQuery(&model.Container{}, params.HostID, params.BusinessLine)
	if runtime != "" {
		query = query.Where("runtime = ?", runtime)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	query = applyLikeSearch(query, params.Search,
		"container_id LIKE ?",
		"container_name LIKE ?",
		"image LIKE ?",
		"runtime LIKE ?",
		"status LIKE ?",
	)
	var containers []model.Container
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &containers)
}

// ListApps 获取应用列表
// GET /api/v1/assets/apps
func (h *AssetsHandler) ListApps(c *gin.Context) {
	params := h.parseAssetListParams(c)
	appType := c.Query("app_type")

	query := h.buildQuery(&model.App{}, params.HostID, params.BusinessLine)
	if appType != "" {
		query = query.Where("app_type = ?", appType)
	}
	query = applyLikeSearch(query, params.Search,
		"app_type LIKE ?",
		"app_name LIKE ?",
		"version LIKE ?",
		"process_id LIKE ?",
		"config_path LIKE ?",
	)
	var apps []model.App
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &apps)
}

// ListNetInterfaces 获取网络接口列表
// GET /api/v1/assets/network-interfaces
func (h *AssetsHandler) ListNetInterfaces(c *gin.Context) {
	params := h.parseAssetListParams(c)

	query := h.buildQuery(&model.NetInterface{}, params.HostID, params.BusinessLine)
	query = applyLikeSearch(query, params.Search,
		"interface_name LIKE ?",
		"mac_address LIKE ?",
		"state LIKE ?",
	)
	var netInterfaces []model.NetInterface
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &netInterfaces)
}

// ListVolumes 获取磁盘列表
// GET /api/v1/assets/volumes
func (h *AssetsHandler) ListVolumes(c *gin.Context) {
	params := h.parseAssetListParams(c)

	query := h.buildQuery(&model.Volume{}, params.HostID, params.BusinessLine)
	query = applyLikeSearch(query, params.Search,
		"device LIKE ?",
		"mount_point LIKE ?",
		"file_system LIKE ?",
	)
	var volumes []model.Volume
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &volumes)
}

// ListKmods 获取内核模块列表
// GET /api/v1/assets/kmods
func (h *AssetsHandler) ListKmods(c *gin.Context) {
	params := h.parseAssetListParams(c)

	query := h.buildQuery(&model.Kmod{}, params.HostID, params.BusinessLine)
	query = applyLikeSearch(query, params.Search,
		"module_name LIKE ?",
		"state LIKE ?",
	)
	var kmods []model.Kmod
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &kmods)
}

// ListServices 获取系统服务列表
// GET /api/v1/assets/services
func (h *AssetsHandler) ListServices(c *gin.Context) {
	params := h.parseAssetListParams(c)
	serviceType := c.Query("service_type")
	status := c.Query("status")

	query := h.buildQuery(&model.Service{}, params.HostID, params.BusinessLine)
	if serviceType != "" {
		query = query.Where("service_type = ?", serviceType)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	query = applyLikeSearch(query, params.Search,
		"service_name LIKE ?",
		"service_type LIKE ?",
		"status LIKE ?",
		"description LIKE ?",
	)
	var services []model.Service
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &services)
}

// ListCrons 获取定时任务列表
// GET /api/v1/assets/crons
func (h *AssetsHandler) ListCrons(c *gin.Context) {
	params := h.parseAssetListParams(c)
	user := c.Query("user")
	cronType := c.Query("cron_type")

	query := h.buildQuery(&model.Cron{}, params.HostID, params.BusinessLine)
	if user != "" {
		query = query.Where("user = ?", user)
	}
	if cronType != "" {
		query = query.Where("cron_type = ?", cronType)
	}
	query = applyLikeSearch(query, params.Search,
		"user LIKE ?",
		"schedule LIKE ?",
		"command LIKE ?",
		"cron_type LIKE ?",
	)
	var crons []model.Cron
	h.respondAssetList(c, query, "collected_at DESC", params.Page, params.PageSize, &crons)
}

// GetStatistics 获取资产统计信息
// GET /api/v1/assets/statistics?host_id=xxx
func (h *AssetsHandler) GetStatistics(c *gin.Context) {
	hostID := c.Query("host_id")
	businessLine := c.Query("business_line")
	stats, _, err := h.collectStatistics(hostID, businessLine)
	if err != nil {
		h.logger.Error("failed to count asset statistics", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, stats)
}

// GetOverview 获取资产总览信息
// GET /api/v1/assets/overview?host_id=xxx
func (h *AssetsHandler) GetOverview(c *gin.Context) {
	hostID := c.Query("host_id")
	businessLine := c.Query("business_line")

	overview, err := h.collectOverview(hostID, businessLine)
	if err != nil {
		h.logger.Error("failed to query asset overview", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, overview)
}

// GetHistory 获取资产历史快照
// GET /api/v1/assets/history?host_id=xxx&business_line=xxx
func (h *AssetsHandler) GetHistory(c *gin.Context) {
	hostID := strings.TrimSpace(c.Query("host_id"))
	businessLine := strings.TrimSpace(c.Query("business_line"))
	days := parsePositiveInt(c.DefaultQuery("days", "7"), 7)
	if days > 180 {
		days = 180
	}
	limit := parsePositiveInt(c.DefaultQuery("limit", "20"), 20)
	if limit > 100 {
		limit = 100
	}

	result, err := h.collectHistory(hostID, businessLine, days, limit)
	if err != nil {
		h.logger.Error("failed to query asset history", zap.String("host_id", hostID), zap.String("business_line", businessLine), zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, result)
}

// GetRelations 获取资产关系视图
// GET /api/v1/assets/relations?host_id=xxx&business_line=xxx
func (h *AssetsHandler) GetRelations(c *gin.Context) {
	hostID := strings.TrimSpace(c.Query("host_id"))
	businessLine := strings.TrimSpace(c.Query("business_line"))
	if hostID == "" && businessLine == "" {
		var hostCount int64
		if err := h.db.Model(&model.Host{}).Count(&hostCount).Error; err != nil {
			h.logger.Error("failed to count hosts for asset relations", zap.Error(err))
			InternalError(c, "查询失败")
			return
		}
		if hostCount == 0 {
			Success(c, AssetRelationsResult{Scope: "global"})
			return
		}
	}
	if hostID == "" && businessLine == "" && c.Query("all") != "true" {
		BadRequest(c, "请指定 host_id、business_line，或显式传入 all=true")
		return
	}

	keyword := strings.TrimSpace(c.Query("keyword"))
	limit := parsePositiveInt(c.DefaultQuery("limit", "30"), 30)
	if limit > 100 {
		limit = 100
	}

	result, err := h.collectRelations(hostID, businessLine, keyword, limit)
	if err != nil {
		h.logger.Error("failed to query asset relations", zap.String("host_id", hostID), zap.String("business_line", businessLine), zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	Success(c, result)
}

// GetCollectionStatus 获取资产采集状态
// GET /api/v1/assets/status?host_id=xxx
func (h *AssetsHandler) GetCollectionStatus(c *gin.Context) {
	hostID := c.Query("host_id")
	businessLine := c.Query("business_line")

	_, total, err := h.collectStatistics(hostID, businessLine)
	if err != nil {
		h.logger.Error("failed to count asset status statistics", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	lastCollectedAt, err := h.latestCollectedAt(hostID, businessLine)
	if err != nil {
		h.logger.Error("failed to query latest asset timestamp", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	collector, err := h.resolveCollectorStatus(hostID)
	if err != nil {
		h.logger.Error("failed to resolve collector status", zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	level, message := buildAssetCollectionMessage(hostID, collector, total > 0)

	status := AssetCollectionStatus{
		HostID:          hostID,
		Scope:           "global",
		HasData:         total > 0,
		LastCollectedAt: lastCollectedAt,
		Level:           level,
		Message:         message,
		Collector:       collector,
	}
	if hostID != "" {
		status.Scope = "host"
	}

	Success(c, status)
}

// GetTopN 获取资产 TopN 聚合
// GET /api/v1/assets/top?type=processes&limit=5&host_id=xxx
func (h *AssetsHandler) GetTopN(c *gin.Context) {
	assetType := normalizeAssetType(c.Query("type"))
	hostID := c.Query("host_id")
	businessLine := c.Query("business_line")
	limit := parsePositiveInt(c.DefaultQuery("limit", "5"), 5)
	if limit > 50 {
		limit = 50
	}

	items, err := h.queryTopN(assetType, hostID, businessLine, limit)
	if err != nil {
		h.logger.Warn("failed to query asset topn", zap.String("type", assetType), zap.Error(err))
		BadRequest(c, "请求参数错误")
		return
	}

	Success(c, gin.H{
		"items": items,
	})
}

// ExportAssets 导出资产数据
// GET /api/v1/assets/export?type=processes|ports|users|software|containers|apps|network-interfaces|volumes|kmods|services|crons&format=csv|json&host_id=xxx
func (h *AssetsHandler) ExportAssets(c *gin.Context) {
	assetType := normalizeAssetType(c.Query("type"))
	format := c.DefaultQuery("format", "csv")
	hostID := c.Query("host_id")
	businessLine := c.Query("business_line")

	const maxRows = 10000

	filename := fmt.Sprintf("assets_%s_%s.%s", assetType, time.Now().Format("20060102150405"), format)
	c.Header("Content-Disposition", "attachment; filename="+filename)

	switch format {
	case "json":
		h.exportJSON(c, assetType, hostID, businessLine, maxRows)
	case "csv":
		c.Header("Content-Type", "text/csv; charset=utf-8")
		h.exportCSV(c, assetType, hostID, businessLine, maxRows)
	default:
		BadRequest(c, "不支持的导出格式，请使用 csv 或 json")
	}
}

// exportJSON 以 JSON 格式导出资产数据
func (h *AssetsHandler) exportJSON(c *gin.Context, assetType, hostID, businessLine string, limit int) {
	data, err := h.queryAssets(assetType, hostID, businessLine, limit)
	if err != nil {
		h.logger.Error("资产导出查询失败", zap.String("type", assetType), zap.Error(err))
		InternalError(c, "查询失败")
		return
	}

	c.Header("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(c.Writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		h.logger.Warn("资产 JSON 导出写入失败", zap.Error(err))
	}
}

// exportCSV 以 CSV 格式导出资产数据
func (h *AssetsHandler) exportCSV(c *gin.Context, assetType, hostID, businessLine string, limit int) {
	w := csv.NewWriter(c.Writer)
	defer w.Flush()

	switch assetType {
	case "processes":
		var rows []model.Process
		h.buildQuery(&model.Process{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "pid", "ppid", "exe", "cmdline", "uid", "username", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.PID, r.PPID, r.Exe, r.Cmdline, r.UID, r.Username, r.CollectedAt.String()})
		}

	case "ports":
		var rows []model.Port
		h.buildQuery(&model.Port{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "protocol", "port", "state", "pid", "process_name", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.Protocol, fmt.Sprint(r.Port), r.State, r.PID, r.ProcessName, r.CollectedAt.String()})
		}

	case "users":
		var rows []model.AssetUser
		h.buildQuery(&model.AssetUser{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "username", "uid", "gid", "groupname", "home_dir", "shell", "has_password", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.Username, r.UID, r.GID, r.Groupname, r.HomeDir, r.Shell, fmt.Sprint(r.HasPassword), r.CollectedAt.String()})
		}

	case "software":
		var rows []model.Software
		h.buildQuery(&model.Software{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "name", "version", "package_type", "architecture", "vendor", "install_time", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.Name, r.Version, r.PackageType, r.Architecture, r.Vendor, r.InstallTime, r.CollectedAt.String()})
		}

	case "containers":
		var rows []model.Container
		h.buildQuery(&model.Container{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "container_id", "container_name", "image", "runtime", "status", "created_at", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.ContainerID, r.ContainerName, r.Image, r.Runtime, r.Status, r.CreatedAt, r.CollectedAt.String()})
		}

	case "apps":
		var rows []model.App
		h.buildQuery(&model.App{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "app_type", "app_name", "version", "port", "config_path", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.AppType, r.AppName, r.Version, fmt.Sprint(r.Port), r.ConfigPath, r.CollectedAt.String()})
		}

	case "network-interfaces":
		var rows []model.NetInterface
		h.buildQuery(&model.NetInterface{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "interface_name", "mac_address", "mtu", "state", "bytes_recv", "bytes_sent", "packets_drop", "packets_error", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.InterfaceName, r.MACAddress, fmt.Sprint(r.MTU), r.State, fmt.Sprint(r.BytesRecv), fmt.Sprint(r.BytesSent), fmt.Sprint(r.PacketsDrop), fmt.Sprint(r.PacketsError), r.CollectedAt.String()})
		}

	case "volumes":
		var rows []model.Volume
		h.buildQuery(&model.Volume{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "device", "mount_point", "file_system", "total_size", "used_size", "available_size", "usage_percent", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.Device, r.MountPoint, r.FileSystem, fmt.Sprint(r.TotalSize), fmt.Sprint(r.UsedSize), fmt.Sprint(r.AvailableSize), fmt.Sprintf("%.1f", r.UsagePercent), r.CollectedAt.String()})
		}

	case "kmods":
		var rows []model.Kmod
		h.buildQuery(&model.Kmod{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "module_name", "size", "used_by", "state", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.ModuleName, fmt.Sprint(r.Size), fmt.Sprint(r.UsedBy), r.State, r.CollectedAt.String()})
		}

	case "services":
		var rows []model.Service
		h.buildQuery(&model.Service{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "service_name", "service_type", "status", "enabled", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.ServiceName, r.ServiceType, r.Status, fmt.Sprint(r.Enabled), r.CollectedAt.String()})
		}

	case "crons":
		var rows []model.Cron
		h.buildQuery(&model.Cron{}, hostID, businessLine).Limit(limit).Find(&rows)
		_ = w.Write([]string{"host_id", "user", "schedule", "command", "cron_type", "collected_at"})
		for _, r := range rows {
			_ = w.Write([]string{r.HostID, r.User, r.Schedule, r.Command, r.CronType, r.CollectedAt.String()})
		}

	default:
		_ = w.Write([]string{"error"})
		_ = w.Write([]string{"不支持的资产类型: " + assetType})
	}
}

// queryAssets 查询指定类型的资产（用于 JSON 导出）
func (h *AssetsHandler) queryAssets(assetType, hostID, businessLine string, limit int) (interface{}, error) {
	switch assetType {
	case "processes":
		var rows []model.Process
		return rows, h.buildQuery(&model.Process{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	case "ports":
		var rows []model.Port
		return rows, h.buildQuery(&model.Port{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	case "users":
		var rows []model.AssetUser
		return rows, h.buildQuery(&model.AssetUser{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	case "software":
		var rows []model.Software
		return rows, h.buildQuery(&model.Software{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	case "containers":
		var rows []model.Container
		return rows, h.buildQuery(&model.Container{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	case "apps":
		var rows []model.App
		return rows, h.buildQuery(&model.App{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	case "network-interfaces":
		var rows []model.NetInterface
		return rows, h.buildQuery(&model.NetInterface{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	case "volumes":
		var rows []model.Volume
		return rows, h.buildQuery(&model.Volume{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	case "kmods":
		var rows []model.Kmod
		return rows, h.buildQuery(&model.Kmod{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	case "services":
		var rows []model.Service
		return rows, h.buildQuery(&model.Service{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	case "crons":
		var rows []model.Cron
		return rows, h.buildQuery(&model.Cron{}, hostID, businessLine).Limit(limit).Find(&rows).Error
	default:
		return nil, fmt.Errorf("不支持的资产类型: %s", assetType)
	}
}

func (h *AssetsHandler) queryTopN(assetType, hostID, businessLine string, limit int) ([]AssetTopItem, error) {
	switch assetType {
	case "processes":
		return h.queryNamedTopN(&model.Process{}, hostID, businessLine, "COALESCE(NULLIF(exe, ''), 'unknown')", limit)
	case "ports":
		return h.queryPortTopN(hostID, businessLine, limit)
	case "users":
		return h.queryNamedTopN(&model.AssetUser{}, hostID, businessLine, "COALESCE(NULLIF(username, ''), 'unknown')", limit)
	case "software":
		return h.queryNamedTopN(&model.Software{}, hostID, businessLine, "COALESCE(NULLIF(name, ''), 'unknown')", limit)
	case "containers":
		return h.queryNamedTopN(&model.Container{}, hostID, businessLine, "COALESCE(NULLIF(image, ''), 'unknown')", limit)
	case "apps":
		return h.queryNamedTopN(&model.App{}, hostID, businessLine, "COALESCE(NULLIF(app_name, ''), COALESCE(NULLIF(app_type, ''), 'unknown'))", limit)
	case "network-interfaces":
		return h.queryNamedTopN(&model.NetInterface{}, hostID, businessLine, "COALESCE(NULLIF(interface_name, ''), 'unknown')", limit)
	case "volumes":
		return h.queryNamedTopN(&model.Volume{}, hostID, businessLine, "COALESCE(NULLIF(mount_point, ''), COALESCE(NULLIF(device, ''), 'unknown'))", limit)
	case "kmods":
		return h.queryNamedTopN(&model.Kmod{}, hostID, businessLine, "COALESCE(NULLIF(module_name, ''), 'unknown')", limit)
	case "services":
		return h.queryNamedTopN(&model.Service{}, hostID, businessLine, "COALESCE(NULLIF(service_name, ''), 'unknown')", limit)
	case "crons":
		return h.queryNamedTopN(&model.Cron{}, hostID, businessLine, "COALESCE(NULLIF(command, ''), 'unknown')", limit)
	default:
		return nil, fmt.Errorf("不支持的资产类型: %s", assetType)
	}
}

func (h *AssetsHandler) queryNamedTopN(modelDef interface{}, hostID, businessLine, groupExpr string, limit int) ([]AssetTopItem, error) {
	var rows []groupedCountResult
	err := h.buildQuery(modelDef, hostID, businessLine).
		Select(groupExpr + " AS name, COUNT(*) AS value").
		Group(groupExpr).
		Order("value DESC").
		Limit(limit).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	items := make([]AssetTopItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, AssetTopItem(row))
	}
	return items, nil
}

func (h *AssetsHandler) queryPortTopN(hostID, businessLine string, limit int) ([]AssetTopItem, error) {
	var rows []portTopResult
	err := h.buildQuery(&model.Port{}, hostID, businessLine).
		Select("protocol, port, COUNT(*) AS value").
		Group("protocol, port").
		Order("value DESC").
		Limit(limit).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	items := make([]AssetTopItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, AssetTopItem{
			Name:  fmt.Sprintf("%s/%d", row.Protocol, row.Port),
			Value: row.Value,
		})
	}
	return items, nil
}

// buildQuery 构建带可选 host_id / business_line 过滤的查询
func (h *AssetsHandler) buildQuery(modelDef interface{}, hostID, businessLine string) *gorm.DB {
	q := h.db.Model(modelDef)
	if hostID != "" {
		q = q.Where("host_id = ?", hostID)
	}
	if businessLine != "" {
		subQuery := h.db.Model(&model.Host{}).Select("host_id").Where("business_line = ?", businessLine)
		q = q.Where("host_id IN (?)", subQuery)
	}
	return q
}
