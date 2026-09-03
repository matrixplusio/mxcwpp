// Command advisory-replay-verify 验证「VulnSync→Kafka→Manager consumer」新路径与旧
// 「manager syncCoreAdvisories 自拉」路径产出的 host_vuln 集合等价（S2 红线门）。
//
// 不依赖外网 / Kafka：把真实库里现有的 advisory_packages（旧路径产物）重组成富 advisory，
// 喂给与 consumer 完全相同的 Coordinator.IngestAdvisories，写入「隔离 sqlite 内存库」，
// 再与真实库 host_vulnerabilities 的 (host_id, cve_id) 集合对拍。真实库全程只读。
//
// 用法:
//
//	go run ./cmd/tools/advisory-replay-verify -config /etc/mxcwpp/server.yaml
//	go run ./cmd/tools/advisory-replay-verify -mysql-dsn "user:pass@tcp(host:3306)/mxcwpp?parseTime=true&loc=Local"
//
// 判读:
//   - only_old（旧有新无）= 新路径漏报 → 红线违反，禁止进 S3
//   - only_new（新有旧无）= 新路径多报 → 需排查（一般是旧 cleanup 残留 / OSV source 覆盖）
//   - both 占比越高越等价；only_old=0 即满足不漏报红线
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/database"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
	"github.com/matrixplusio/mxcwpp/internal/server/vulnsync/advisory"
)

// osAdvisorySources 是 VulnSync 负责的 OS 厂商 advisory 源（与 S1 buildAdvisorySources 对齐）。
// 等价比对仅针对这些源驱动的 host_vuln；OSV/语言包 + NVD enrich 不在范围。
var osAdvisorySources = map[string]bool{
	"rhsa": true, "rocky-apollo": true, "usn": true,
	"debian-tracker": true, "alpine": true, "centos": true,
}

func main() {
	configPath := flag.String("config", "", "server.yaml 路径（与 -mysql-dsn 二选一）")
	mysqlDSN := flag.String("mysql-dsn", "", "MySQL DSN（覆盖 config）")
	sampleN := flag.Int("sample", 20, "diff 样本打印条数")
	flag.Parse()

	logger, _ := zap.NewProduction()
	defer func() { _ = logger.Sync() }()

	realDB := connectMySQL(*configPath, *mysqlDSN, logger)

	// 1. 真实库读 advisory_packages（OS 源）→ 重组成富 advisory 消息
	msgs := loadAdvisoryMessages(realDB, logger)
	logger.Info("重组 advisory 消息完成", zap.Int("messages", len(msgs)))

	// 2. 真实库读在线主机软件清单
	hosts := loadHosts(realDB, logger)
	logger.Info("加载主机软件清单完成", zap.Int("host_pkg_rows", len(hosts)))

	// 3. 隔离 sqlite 重放 IngestAdvisories（与 consumer 同一写路径）
	shadow := newShadowDB(logger)
	coord := advisory.NewCoordinator(shadow, logger)
	vulnCount, hostVulnCount := coord.IngestAdvisories(msgs, hosts)
	logger.Info("重放完成", zap.Int("vuln_upsert", vulnCount), zap.Int("host_vuln_links", hostVulnCount))

	// 4. 取新旧两个 (host_id, cve_id) 集合
	newSet := queryPairs(shadow, false, logger) // sqlite 全是 OS advisory
	oldSet := queryPairs(realDB, true, logger)  // 真实库：仅 OS advisory 源（按 vuln.source 过滤）

	if len(oldSet) == 0 {
		fmt.Printf("\n⚠️  真实库无 OS-advisory 源(rhsa/rocky-apollo/usn/debian-tracker/alpine/centos)的 host_vuln 基线，\n")
		fmt.Printf("    无法做等价对拍。当前库 host_vuln 全部来自 OSV/GHSA 语言包路径。\n")
		fmt.Printf("    新路径 replay 产出 OS-advisory host_vuln 对: %d（matcher 行为正常）。\n", len(newSet))
		fmt.Printf("    需在「有 OS-advisory host_vuln」的环境跑本工具才能验证等价。\n")
		return
	}

	// 5. 对拍
	report(oldSet, newSet, *sampleN)
}

type pair struct{ host, cve string }

func connectMySQL(configPath, dsn string, logger *zap.Logger) *gorm.DB {
	if dsn != "" {
		db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
			Logger: gormlogger.Default.LogMode(gormlogger.Silent),
		})
		if err != nil {
			logger.Fatal("MySQL 连接失败", zap.Error(err))
		}
		return db
	}
	if configPath == "" {
		logger.Fatal("必须提供 -config 或 -mysql-dsn")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatal("加载配置失败", zap.Error(err))
	}
	db, err := database.Init(cfg.Database, logger, cfg.Log)
	if err != nil {
		logger.Fatal("MySQL 连接失败", zap.Error(err))
	}
	return db
}

// loadAdvisoryMessages 把 advisory_packages（os_family 非空的 OS 源行）按
// (cve, source, os_family, os_major) 分组重组成富 advisory 消息。
func loadAdvisoryMessages(db *gorm.DB, logger *zap.Logger) []advisory.AdvisoryMessage {
	type apRow struct {
		CveID            string
		Source           string
		SourceAdvisoryID string
		OSFamily         string
		OSMajor          string
		PkgName          string
		Arch             string
		FixedVersion     string
		Confidence       string
		Severity         string
	}
	var rows []apRow
	if err := db.Table("advisory_packages").
		Select("cve_id, source, source_advisory_id, os_family, os_major, pkg_name, arch, fixed_version, confidence, severity").
		Where("os_family != '' AND source IN ?", keys(osAdvisorySources)).
		Find(&rows).Error; err != nil {
		logger.Fatal("读取 advisory_packages 失败", zap.Error(err))
	}

	grouped := map[string]*advisory.AdvisoryMessage{}
	for _, r := range rows {
		key := r.CveID + "|" + r.Source + "|" + r.OSFamily + "|" + r.OSMajor
		m, ok := grouped[key]
		if !ok {
			m = &advisory.AdvisoryMessage{
				Source:     r.Source,
				Confidence: advisory.Confidence(orDefault(r.Confidence, "high")),
				Advisory: &advisory.Advisory{
					AdvisoryID: r.SourceAdvisoryID,
					CVEIDs:     []string{r.CveID},
					Severity:   advisory.Severity(r.Severity),
					OSFamily:   r.OSFamily,
					OSMajorVer: r.OSMajor,
				},
			}
			grouped[key] = m
		}
		m.Advisory.AffectedPkgs = append(m.Advisory.AffectedPkgs, advisory.PkgFix{
			Name: r.PkgName, Arch: r.Arch, FixedVersion: r.FixedVersion,
		})
	}
	out := make([]advisory.AdvisoryMessage, 0, len(grouped))
	for _, m := range grouped {
		out = append(out, *m)
	}
	return out
}

// loadHosts 与 manager biz.loadHostSoftware 同一查询。
func loadHosts(db *gorm.DB, logger *zap.Logger) []advisory.HostSoftware {
	type row struct {
		HostID, Hostname, OSFamily, OSVersion, Arch          string
		PkgName, PkgVer, PkgEpoch, PkgRelease, PkgArch, PURL string
		PackageType                                          string
	}
	// 注：不过滤 h.status='online'。等价比对要复现旧 host_vuln 当初匹配的主机群，
	// 而 dev 主机此刻可能已 offline；按 software 表全量主机匹配才能对拍。
	// （生产 consumer 路径仍按 online 过滤——见 biz.loadHostSoftware。）
	var rows []row
	if err := db.Table("hosts h").
		Select("h.host_id, h.hostname, h.os_family, h.os_version, h.arch, s.name as pkg_name, s.version as pkg_ver, s.epoch as pkg_epoch, s.release as pkg_release, s.architecture as pkg_arch, s.purl, s.package_type").
		Joins("JOIN software s ON s.host_id = h.host_id").
		Find(&rows).Error; err != nil {
		logger.Fatal("加载主机清单失败", zap.Error(err))
	}
	out := make([]advisory.HostSoftware, 0, len(rows))
	for _, r := range rows {
		out = append(out, advisory.HostSoftware{
			HostID: r.HostID, Hostname: r.Hostname, OSFamily: r.OSFamily,
			OSVer: r.OSVersion, OSMajor: osMajor(r.OSVersion), Arch: r.Arch,
			PkgName: r.PkgName, PkgVer: r.PkgVer, PkgEpoch: r.PkgEpoch,
			PkgVerRaw: r.PkgVer, PkgRelease: r.PkgRelease, PkgArch: r.PkgArch,
			PURL: r.PURL, PkgEcosystem: ecosystem(r.PackageType), PkgManager: pkgManager(r.PackageType, r.OSFamily),
		})
	}
	return out
}

// queryPairs 取 unpatched (host_id, cve_id) 集合。
// osOnly=true 时仅取 OS advisory 源(rhsa/rocky-apollo/usn/debian-tracker/alpine/centos)
// 的 host_vuln —— 排除 OSV/GHSA 语言包路径，保证与 VulnSync OS-advisory 路径同范围。
func queryPairs(db *gorm.DB, osOnly bool, logger *zap.Logger) map[pair]bool {
	type r struct{ HostID, CveID string }
	q := db.Table("host_vulnerabilities hv").
		Select("hv.host_id, v.cve_id").
		Joins("JOIN vulnerabilities v ON v.id = hv.vuln_id").
		Where("hv.status = ?", "unpatched")
	if osOnly {
		q = q.Where("v.source IN ?", keys(osAdvisorySources))
	}
	var rows []r
	if err := q.Find(&rows).Error; err != nil {
		logger.Fatal("查询 host_vuln 集合失败", zap.Error(err))
	}
	out := make(map[pair]bool, len(rows))
	for _, x := range rows {
		out[pair{x.HostID, x.CveID}] = true
	}
	return out
}

func report(oldSet, newSet map[pair]bool, sampleN int) {
	var onlyOld, onlyNew, both []pair
	for p := range oldSet {
		if newSet[p] {
			both = append(both, p)
		} else {
			onlyOld = append(onlyOld, p)
		}
	}
	for p := range newSet {
		if !oldSet[p] {
			onlyNew = append(onlyNew, p)
		}
	}

	fmt.Printf("\n=== advisory replay 等价比对 ===\n")
	fmt.Printf("旧路径 host_vuln (host,cve) 对: %d\n", len(oldSet))
	fmt.Printf("新路径 host_vuln (host,cve) 对: %d\n", len(newSet))
	fmt.Printf("交集 both:        %d\n", len(both))
	fmt.Printf("only_old(漏报!): %d\n", len(onlyOld))
	fmt.Printf("only_new(多报):  %d\n", len(onlyNew))

	printSample("only_old(新路径漏报)", onlyOld, sampleN)
	printSample("only_new(新路径多报)", onlyNew, sampleN)

	fmt.Printf("\n=== 红线判读 ===\n")
	if len(onlyOld) == 0 {
		fmt.Printf("✅ only_old=0 → 不漏报红线通过，可进 S3\n")
	} else {
		fmt.Printf("❌ only_old=%d → 新路径漏报，禁止进 S3，需排查\n", len(onlyOld))
		os.Exit(1)
	}
}

func printSample(title string, ps []pair, n int) {
	if len(ps) == 0 {
		return
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].cve != ps[j].cve {
			return ps[i].cve < ps[j].cve
		}
		return ps[i].host < ps[j].host
	})
	fmt.Printf("\n--- %s 样本(前 %d) ---\n", title, n)
	for i, p := range ps {
		if i >= n {
			break
		}
		fmt.Printf("  host=%s cve=%s\n", p.host, p.cve)
	}
}

// --- 隔离 sqlite ---

func newShadowDB(logger *zap.Logger) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		logger.Fatal("sqlite 内存库创建失败", zap.Error(err))
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	// AutoMigrate 保证与 model 全列一致（避免手写 DDL 漏列导致 upsert 失败）。
	if err := db.AutoMigrate(&model.Vulnerability{}, &model.HostVulnerability{}, &model.AdvisoryPackage{}); err != nil {
		logger.Fatal("sqlite AutoMigrate 失败", zap.Error(err))
	}
	return db
}

// --- helpers（与 manager biz 同义，工具内自包含）---

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func osMajor(ver string) string {
	for i, c := range ver {
		if c == '.' {
			return ver[:i]
		}
	}
	return ver
}

func ecosystem(pkgType string) string {
	switch pkgType {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "maven":
		return "Maven"
	case "golang", "go":
		return "Go"
	case "gem":
		return "RubyGems"
	case "cargo":
		return "crates.io"
	}
	return ""
}

func pkgManager(pkgType, osFamily string) string {
	switch pkgType {
	case "rpm":
		return "rpm"
	case "deb", "dpkg":
		return "dpkg"
	}
	switch osFamily {
	case "debian", "ubuntu":
		return "dpkg"
	}
	return "rpm"
}
