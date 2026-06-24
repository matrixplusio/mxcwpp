package advisory

import (
	"context"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// NVDEnricher 后台 job:扫描 vulnerabilities 表中 cvss_score=0 / severity=none 的记录,
// 按 cve_id 调 NVD JSON 2.0 API enrich,update 回 DB。
//
// 业务背景:prod 2026-06-04 实测 92% (5471/8961) vulnerability 无 CVSS,根因是:
//   - RHSA / OSV 不提供 NVD 风格 CVSS,只给 vendor severity
//   - 之前 NVD source 标记 enabled 但实际无 fetch 实现 → 漂亮的 last_sync 假数据
//
// 本 enricher 解决 enrich gap(不替代 advisory source,只补 CVSS / description)。
//
// 限速:NVD 无 API key 时 5 req / 30s(6s 间隔),5471 个 CVE ≈ 9h 跑完;
// 有 API key 时 50 / 30s,~1h 跑完。建议外部传 API key。
type NVDEnricher struct {
	db     *gorm.DB
	client *NVDClient
	logger *zap.Logger
}

// NewNVDEnricher 创建 enricher。apiKey 留空走无 key 限速。
func NewNVDEnricher(db *gorm.DB, apiKey string, logger *zap.Logger) *NVDEnricher {
	return &NVDEnricher{
		db:     db,
		client: NewNVDClient(apiKey, logger),
		logger: logger,
	}
}

// RunOnce 一次扫描 + enrich。
//
// 参数:
//   - ctx: 整批超时上限(调用方控制,建议 1h+)
//   - batchSize: 每轮处理多少条 vuln(避免锁表过久);0 → 1000
//   - maxRows: 整次最多处理多少条;0 → 不限
//
// 返回:enriched 数量, scanned 数量, error。
func (e *NVDEnricher) RunOnce(ctx context.Context, batchSize, maxRows int) (enriched, scanned int, err error) {
	if batchSize <= 0 {
		batchSize = 1000
	}
	cursor := uint(0)
	for {
		if maxRows > 0 && scanned >= maxRows {
			break
		}
		// 批次:cvss_score=0 OR cwe_id 空 + cve_id 非空 + id > cursor(顺序扫,避免重复)
		var rows []model.Vulnerability
		q := e.db.Model(&model.Vulnerability{}).
			Where("(cvss_score = 0 OR cwe_id = '' OR cwe_id IS NULL) AND cve_id <> '' AND cve_id LIKE 'CVE-%' AND id > ?", cursor).
			Order("id ASC").
			Limit(batchSize)
		if err := q.Find(&rows).Error; err != nil {
			return enriched, scanned, err
		}
		if len(rows) == 0 {
			break
		}

		cveIDs := make([]string, 0, len(rows))
		idByCVE := make(map[string][]uint, len(rows))
		for _, v := range rows {
			cveIDs = append(cveIDs, v.CveID)
			idByCVE[v.CveID] = append(idByCVE[v.CveID], v.ID)
		}
		scanned += len(rows)
		cursor = rows[len(rows)-1].ID

		results := e.client.LookupBatch(ctx, cveIDs)

		// update DB:逐条 update 避免一条失败影响其他
		for cve, res := range results {
			if res == nil {
				continue
			}
			// CWE 数据即使 cvss=0 也值得回填(reserved CVE 有 CWE 但无 CVSS)
			if res.CVSSScore == 0 && res.CWEIDs == "" {
				continue
			}
			ids := idByCVE[cve]
			updates := map[string]interface{}{}
			if res.CVSSScore > 0 {
				updates["cvss_score"] = res.CVSSScore
			}
			if res.Severity != "" {
				updates["severity"] = res.Severity
			}
			if res.Description != "" {
				updates["description"] = res.Description
			}
			if res.CWEIDs != "" {
				updates["cwe_id"] = res.CWEIDs
			}
			if res.CWECategory != "" {
				updates["cwe_category"] = res.CWECategory
			}
			if len(updates) == 0 {
				continue
			}
			if err := e.db.Model(&model.Vulnerability{}).
				Where("id IN ?", ids).
				Updates(updates).Error; err != nil {
				e.logger.Warn("vuln NVD enrich update failed",
					zap.String("cve", cve), zap.Error(err))
				continue
			}
			enriched += len(ids)
		}

		e.logger.Info("NVD enrich batch done",
			zap.Int("batch_size", len(rows)),
			zap.Int("nvd_hits", len(results)),
			zap.Int("total_scanned", scanned),
			zap.Int("total_enriched", enriched),
		)

		if ctx.Err() != nil {
			break
		}
	}
	return enriched, scanned, nil
}

// StartCron 后台 cron。每 24h 跑一次 RunOnce,接收 stop chan 优雅退出。
// 启动后立即跑一次(prod 首部署即开始 backfill)。
func (e *NVDEnricher) StartCron(stop <-chan struct{}) {
	go func() {
		// 启动立即跑一次(backfill)
		e.runWithTimeout()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				e.runWithTimeout()
			}
		}
	}()
}

func (e *NVDEnricher) runWithTimeout() {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	enriched, scanned, err := e.RunOnce(ctx, 500, 0)
	if err != nil {
		e.logger.Error("NVD enrich job failed",
			zap.Int("scanned", scanned), zap.Int("enriched", enriched), zap.Error(err))
		return
	}
	e.logger.Info("NVD enrich job done",
		zap.Int("scanned", scanned), zap.Int("enriched", enriched))
}
