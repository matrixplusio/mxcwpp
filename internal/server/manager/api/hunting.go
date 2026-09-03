package api

import (
	"context"
	"fmt"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/hunting/mql"
	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

const queryTimeout = 30 * time.Second

// HuntingHandler 威胁狩猎 API 处理器
type HuntingHandler struct {
	db     *gorm.DB
	chConn chdriver.Conn
	logger *zap.Logger
}

// NewHuntingHandler 创建威胁狩猎 API 处理器
func NewHuntingHandler(db *gorm.DB, chConn chdriver.Conn, logger *zap.Logger) *HuntingHandler {
	return &HuntingHandler{db: db, chConn: chConn, logger: logger}
}

// queryRequest is the request body for MQL query execution.
type queryRequest struct {
	MQL     string `json:"mql" binding:"required"`
	Timeout int    `json:"timeout_seconds"` // optional, default 30
}

// ExecuteQuery 执行 MQL 查询
// POST /api/v1/hunting/query
func (h *HuntingHandler) ExecuteQuery(c *gin.Context) {
	if h.chConn == nil {
		BadRequest(c, "ClickHouse 未启用，无法执行查询")
		return
	}

	var req queryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数无效")
		return
	}

	// Parse MQL.
	q, err := mql.Parse(req.MQL)
	if err != nil {
		BadRequest(c, fmt.Sprintf("MQL 语法错误: %v", err))
		return
	}

	// Compile to SQL.
	compiled, err := mql.Compile(q)
	if err != nil {
		BadRequest(c, fmt.Sprintf("MQL 编译错误: %v", err))
		return
	}

	// Execute with timeout.
	timeout := queryTimeout
	if req.Timeout > 0 && req.Timeout <= 60 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
	defer cancel()

	start := time.Now()

	rows, err := h.chConn.Query(ctx, compiled.SQL, compiled.Args...)
	if err != nil {
		h.logger.Warn("MQL 查询执行失败",
			zap.String("sql", compiled.SQL),
			zap.Error(err),
		)
		InternalError(c, fmt.Sprintf("查询执行失败: %v", err))
		return
	}
	defer rows.Close()

	// Collect results as generic maps.
	columns := rows.Columns()
	columnTypes := rows.ColumnTypes()
	var results []map[string]any

	for rows.Next() {
		vals := make([]any, len(columns))
		valPtrs := make([]any, len(columns))
		for i, ct := range columnTypes {
			vals[i] = allocScanType(ct.DatabaseTypeName())
			valPtrs[i] = vals[i]
		}

		if err := rows.Scan(valPtrs...); err != nil {
			h.logger.Warn("MQL 结果扫描失败", zap.Error(err))
			continue
		}

		row := make(map[string]any, len(columns))
		for i, col := range columns {
			row[col] = derefScanValue(vals[i])
		}
		results = append(results, row)

		if len(results) >= mql.MaxLimit {
			break
		}
	}

	elapsed := time.Since(start)

	h.logger.Info("MQL 查询执行完成",
		zap.Duration("elapsed", elapsed),
		zap.Int("rows", len(results)),
	)

	Success(c, gin.H{
		"columns":    columns,
		"rows":       results,
		"total_rows": len(results),
		"elapsed_ms": elapsed.Milliseconds(),
		"sql":        compiled.SQL,
	})
}

// ListSavedQueries 获取保存的狩猎查询列表
// GET /api/v1/hunting/queries
func (h *HuntingHandler) ListSavedQueries(c *gin.Context) {
	category := c.Query("category")

	query := h.db.Model(&model.HuntQuery{})
	if category != "" {
		query = query.Where("category = ?", category)
	}
	query = query.Order("updated_at DESC")

	var total int64
	query.Count(&total)

	page, pageSize := ParsePagination(c)
	var queries []model.HuntQuery
	query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&queries)

	SuccessPaginated(c, total, queries)
}

// CreateSavedQuery 保存狩猎查询
// POST /api/v1/hunting/queries
func (h *HuntingHandler) CreateSavedQuery(c *gin.Context) {
	var req model.HuntQuery
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "请求参数无效")
		return
	}

	// Validate MQL syntax.
	if _, err := mql.Parse(req.MQL); err != nil {
		BadRequest(c, fmt.Sprintf("MQL 语法错误: %v", err))
		return
	}

	req.Owner = c.GetString("username")

	if err := h.db.Create(&req).Error; err != nil {
		InternalError(c, "保存查询失败")
		return
	}
	Success(c, req)
}

// DeleteSavedQuery 删除保存的狩猎查询
// DELETE /api/v1/hunting/queries/:id
func (h *HuntingHandler) DeleteSavedQuery(c *gin.Context) {
	id := c.Param("id")
	result := h.db.Where("id = ? AND is_builtin = ?", id, false).Delete(&model.HuntQuery{})
	if result.RowsAffected == 0 {
		NotFound(c, "查询不存在或为内置查询")
		return
	}
	SuccessMessage(c, "查询已删除")
}

// allocScanType creates a pointer to a zero value of the appropriate Go type
// for ClickHouse column scanning.
func allocScanType(dbType string) any {
	switch dbType {
	case "DateTime64", "DateTime":
		return new(time.Time)
	case "Int32", "Int64":
		return new(int64)
	case "UInt32", "UInt64":
		return new(uint64)
	case "Float32", "Float64":
		return new(float64)
	default:
		return new(string)
	}
}

// derefScanValue dereferences a scan pointer to its concrete value.
func derefScanValue(v any) any {
	switch p := v.(type) {
	case *time.Time:
		return p.Format(model.TimeFormat)
	case *int64:
		return *p
	case *uint64:
		return *p
	case *float64:
		return *p
	case *string:
		return *p
	default:
		return v
	}
}
