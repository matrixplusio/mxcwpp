// Package api 提供 HTTP API 处理器
package api

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// ResultsHandler 是检测结果 API 处理器
type ResultsHandler struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewResultsHandler 创建结果处理器
func NewResultsHandler(db *gorm.DB, logger *zap.Logger) *ResultsHandler {
	return &ResultsHandler{
		db:     db,
		logger: logger,
	}
}

// ListResults 获取检测结果列表
// GET /api/v1/results
func (h *ResultsHandler) ListResults(c *gin.Context) {
	// 解析查询参数
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	hostID := c.Query("host_id")
	ruleID := c.Query("rule_id")
	policyID := c.Query("policy_id")
	taskID := c.Query("task_id")
	status := c.Query("status")
	severity := c.Query("severity")

	// 构建查询
	query := h.db.Model(&model.ScanResult{})

	// 过滤条件
	if hostID != "" {
		query = query.Where("host_id = ?", hostID)
	}
	if ruleID != "" {
		query = query.Where("rule_id = ?", ruleID)
	}
	if policyID != "" {
		query = query.Where("policy_id = ?", policyID)
	}
	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}

	// 计算总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		h.logger.Error("查询结果总数失败", zap.Error(err))
		InternalError(c, "查询检测结果失败")
		return
	}

	// 分页查询
	var results []model.ScanResult
	offset := (page - 1) * pageSize
	if err := query.Offset(offset).Limit(pageSize).Order("checked_at DESC").Find(&results).Error; err != nil {
		h.logger.Error("查询检测结果失败", zap.Error(err))
		InternalError(c, "查询检测结果失败")
		return
	}

	SuccessPaginated(c, total, results)
}

// GetResult 获取检测结果详情
// GET /api/v1/results/detail?task_id=xxx&host_id=xxx&rule_id=xxx
func (h *ResultsHandler) GetResult(c *gin.Context) {
	taskID := c.Query("task_id")
	hostID := c.Query("host_id")
	ruleID := c.Query("rule_id")

	if taskID == "" || hostID == "" || ruleID == "" {
		BadRequest(c, "task_id, host_id, rule_id 不能为空")
		return
	}

	var result model.ScanResult
	if err := h.db.Where("task_id = ? AND host_id = ? AND rule_id = ?", taskID, hostID, ruleID).
		Preload("Host").Preload("Rule").First(&result).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "检测结果不存在")
			return
		}
		h.logger.Error("查询检测结果失败", zap.Error(err))
		InternalError(c, "查询检测结果失败")
		return
	}

	Success(c, result)
}

// GetHostBaselineScore 获取主机基线得分
// GET /api/v1/results/host/:host_id/score
func (h *ResultsHandler) GetHostBaselineScore(c *gin.Context) {
	hostID := c.Param("host_id")

	// 查询主机最新的检测结果（按规则分组，取最新的）
	var latestResults []struct {
		RuleID   string
		Status   string
		Severity string
	}

	// 使用子查询获取每个规则的最新结果（过滤已删除的规则）
	subQuery := h.db.Model(&model.ScanResult{}).
		Select("rule_id, MAX(checked_at) as max_checked_at").
		Where("host_id = ?", hostID).
		Group("rule_id")

	if err := h.db.Table("scan_results").
		Select("scan_results.rule_id, scan_results.status, scan_results.severity").
		Joins("INNER JOIN (?) AS latest ON scan_results.rule_id = latest.rule_id AND scan_results.checked_at = latest.max_checked_at", subQuery).
		Joins("INNER JOIN rules ON scan_results.rule_id = rules.rule_id").
		Where("scan_results.host_id = ?", hostID).
		Find(&latestResults).Error; err != nil {
		h.logger.Error("查询主机基线得分失败", zap.Error(err))
		InternalError(c, "查询主机基线得分失败")
		return
	}

	// 计算得分
	if len(latestResults) == 0 {
		Success(c, gin.H{
			"host_id":        hostID,
			"baseline_score": 0,
			"pass_rate":      0.0,
			"total_rules":    0,
			"pass_count":     0,
			"fail_count":     0,
			"error_count":    0,
			"na_count":       0,
		})
		return
	}

	// 统计
	totalRules := len(latestResults)
	passCount := 0
	failCount := 0
	errorCount := 0
	naCount := 0

	// 严重级别权重
	severityWeights := map[string]float64{
		"critical": 10.0,
		"high":     7.0,
		"medium":   4.0,
		"low":      1.0,
	}

	totalWeight := 0.0
	passWeight := 0.0

	for _, result := range latestResults {
		weight := severityWeights[result.Severity]
		if weight == 0 {
			weight = 1.0 // 默认权重
		}
		totalWeight += weight

		switch result.Status {
		case "pass":
			passCount++
			passWeight += weight
		case "fail":
			failCount++
		case "error":
			errorCount++
		case "na":
			naCount++
		}
	}

	// 计算得分（0-100）
	baselineScore := 0.0
	if totalWeight > 0 {
		baselineScore = (passWeight / totalWeight) * 100.0
	}

	// 计算通过率
	passRate := float64(passCount) / float64(totalRules)

	Success(c, gin.H{
		"host_id":        hostID,
		"baseline_score": int(baselineScore),
		"pass_rate":      passRate,
		"total_rules":    totalRules,
		"pass_count":     passCount,
		"fail_count":     failCount,
		"error_count":    errorCount,
		"na_count":       naCount,
		"calculated_at":  time.Now(),
	})
}

// GetHostBaselineSummary 获取主机基线摘要（按严重级别统计）
// GET /api/v1/results/host/:host_id/summary
func (h *ResultsHandler) GetHostBaselineSummary(c *gin.Context) {
	hostID := c.Param("host_id")

	// 查询主机最新的检测结果（按规则分组，取最新的）
	var latestResults []struct {
		RuleID   string
		Status   string
		Severity string
		Category string
	}

	subQuery := h.db.Model(&model.ScanResult{}).
		Select("rule_id, MAX(checked_at) as max_checked_at").
		Where("host_id = ?", hostID).
		Group("rule_id")

	if err := h.db.Table("scan_results").
		Select("scan_results.rule_id, scan_results.status, scan_results.severity, scan_results.category").
		Joins("INNER JOIN (?) AS latest ON scan_results.rule_id = latest.rule_id AND scan_results.checked_at = latest.max_checked_at", subQuery).
		Joins("INNER JOIN rules ON scan_results.rule_id = rules.rule_id").
		Where("scan_results.host_id = ?", hostID).
		Find(&latestResults).Error; err != nil {
		h.logger.Error("查询主机基线摘要失败", zap.Error(err))
		InternalError(c, "查询主机基线摘要失败")
		return
	}

	// 按严重级别和状态统计
	summary := gin.H{
		"host_id": hostID,
		"by_severity": gin.H{
			"critical": gin.H{"pass": 0, "fail": 0, "error": 0, "na": 0},
			"high":     gin.H{"pass": 0, "fail": 0, "error": 0, "na": 0},
			"medium":   gin.H{"pass": 0, "fail": 0, "error": 0, "na": 0},
			"low":      gin.H{"pass": 0, "fail": 0, "error": 0, "na": 0},
		},
		"by_category": make(map[string]gin.H),
	}

	for _, result := range latestResults {
		// 按严重级别统计
		if severityMap, ok := summary["by_severity"].(gin.H)[result.Severity].(gin.H); ok {
			if count, ok := severityMap[result.Status].(int); ok {
				severityMap[result.Status] = count + 1
			}
		}

		// 按类别统计
		if categoryMap, ok := summary["by_category"].(map[string]gin.H); ok {
			if _, exists := categoryMap[result.Category]; !exists {
				categoryMap[result.Category] = gin.H{"pass": 0, "fail": 0, "error": 0, "na": 0}
			}
			if count, ok := categoryMap[result.Category][result.Status].(int); ok {
				categoryMap[result.Category][result.Status] = count + 1
			}
		}
	}

	Success(c, summary)
}

// ExportHostBaselineResults 导出主机基线检查结果
// GET /api/v1/results/host/:host_id/export?format=markdown|excel
func (h *ResultsHandler) ExportHostBaselineResults(c *gin.Context) {
	hostID := c.Param("host_id")
	format := c.DefaultQuery("format", "excel")

	// 查询主机信息
	var host model.Host
	if err := h.db.Where("host_id = ?", hostID).First(&host).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "主机不存在")
			return
		}
		h.logger.Error("查询主机信息失败", zap.Error(err))
		InternalError(c, "查询主机信息失败")
		return
	}

	// 查询失败的基线检查结果
	var results []model.ScanResult
	subQuery := h.db.Model(&model.ScanResult{}).
		Select("rule_id, MAX(checked_at) as max_checked_at").
		Where("host_id = ?", hostID).
		Group("rule_id")

	if err := h.db.Table("scan_results").
		Select("scan_results.*").
		Joins("INNER JOIN (?) AS latest ON scan_results.rule_id = latest.rule_id AND scan_results.checked_at = latest.max_checked_at", subQuery).
		Where("scan_results.host_id = ? AND scan_results.status = ?", hostID, "fail").
		Order("scan_results.severity DESC, scan_results.category ASC").
		Find(&results).Error; err != nil {
		h.logger.Error("查询基线检查结果失败", zap.Error(err))
		InternalError(c, "查询基线检查结果失败")
		return
	}

	switch format {
	case "markdown":
		h.exportMarkdown(c, host, results)
	case "excel":
		h.exportExcel(c, host, results)
	default:
		BadRequest(c, "不支持的导出格式")
	}
}

// exportMarkdown 导出 Markdown 格式
func (h *ResultsHandler) exportMarkdown(c *gin.Context, host model.Host, results []model.ScanResult) {
	var buf bytes.Buffer

	// 主机基本信息
	buf.WriteString("# 主机基线风险报告\n\n")
	buf.WriteString("## 主机信息\n\n")
	buf.WriteString(fmt.Sprintf("- **主机名**: %s\n", host.Hostname))
	buf.WriteString(fmt.Sprintf("- **主机ID**: %s\n", host.HostID))
	buf.WriteString(fmt.Sprintf("- **操作系统**: %s %s\n", host.OSFamily, host.OSVersion))
	if len(host.IPv4) > 0 {
		buf.WriteString(fmt.Sprintf("- **IPv4地址**: %s\n", host.IPv4[0]))
	}
	buf.WriteString(fmt.Sprintf("- **导出时间**: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// 统计信息
	buf.WriteString("## 风险统计\n\n")
	buf.WriteString(fmt.Sprintf("- **失败项总数**: %d\n\n", len(results)))

	severityCount := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, r := range results {
		severityCount[r.Severity]++
	}
	buf.WriteString(fmt.Sprintf("- **严重**: %d\n", severityCount["critical"]))
	buf.WriteString(fmt.Sprintf("- **高危**: %d\n", severityCount["high"]))
	buf.WriteString(fmt.Sprintf("- **中危**: %d\n", severityCount["medium"]))
	buf.WriteString(fmt.Sprintf("- **低危**: %d\n\n", severityCount["low"]))

	// 详细结果
	buf.WriteString("## 检查结果详情\n\n")
	for i, r := range results {
		buf.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, r.Title))
		buf.WriteString(fmt.Sprintf("- **规则ID**: %s\n", r.RuleID))
		buf.WriteString(fmt.Sprintf("- **类别**: %s\n", r.Category))
		buf.WriteString(fmt.Sprintf("- **严重级别**: %s\n", r.Severity))
		buf.WriteString(fmt.Sprintf("- **检查时间**: %s\n", r.CheckedAt.String()))

		if r.Actual != "" {
			buf.WriteString(fmt.Sprintf("- **实际值**: %s\n", r.Actual))
		}
		if r.Expected != "" {
			buf.WriteString(fmt.Sprintf("- **期望值**: %s\n", r.Expected))
		}
		if r.FixSuggestion != "" {
			buf.WriteString(fmt.Sprintf("\n**修复建议**:\n\n%s\n", r.FixSuggestion))
		}
		buf.WriteString("\n---\n\n")
	}

	filename := fmt.Sprintf("baseline_report_%s_%s.md", host.Hostname, time.Now().Format("20060102_150405"))
	c.Header("Content-Type", "text/markdown; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Data(http.StatusOK, "text/markdown", buf.Bytes())
}

// exportExcel 导出 Excel 格式
func (h *ResultsHandler) exportExcel(c *gin.Context, host model.Host, results []model.ScanResult) {
	f := excelize.NewFile()
	defer f.Close()

	sheetName := "基线风险"
	index, _ := f.NewSheet(sheetName)
	f.SetActiveSheet(index)
	f.DeleteSheet("Sheet1")

	// 设置列宽
	f.SetColWidth(sheetName, "A", "A", 15)
	f.SetColWidth(sheetName, "B", "B", 20)
	f.SetColWidth(sheetName, "C", "C", 40)
	f.SetColWidth(sheetName, "D", "D", 12)
	f.SetColWidth(sheetName, "E", "E", 20)
	f.SetColWidth(sheetName, "F", "F", 20)
	f.SetColWidth(sheetName, "G", "G", 50)

	// 标题样式
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 14},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#4472C4"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	// 表头样式
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#D9E1F2"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
		Border: []excelize.Border{
			{Type: "left", Color: "000000", Style: 1},
			{Type: "top", Color: "000000", Style: 1},
			{Type: "bottom", Color: "000000", Style: 1},
			{Type: "right", Color: "000000", Style: 1},
		},
	})

	// 主机信息
	f.MergeCell(sheetName, "A1", "G1")
	f.SetCellValue(sheetName, "A1", "主机基线风险报告")
	f.SetCellStyle(sheetName, "A1", "A1", titleStyle)
	f.SetRowHeight(sheetName, 1, 25)

	row := 3
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "主机名:")
	f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), host.Hostname)
	row++
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "主机ID:")
	f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), host.HostID)
	row++
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "操作系统:")
	f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), fmt.Sprintf("%s %s", host.OSFamily, host.OSVersion))
	row++
	if len(host.IPv4) > 0 {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "IPv4地址:")
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), host.IPv4[0])
		row++
	}
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "导出时间:")
	f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), time.Now().Format("2006-01-02 15:04:05"))
	row += 2

	// 表头
	headers := []string{"规则ID", "类别", "标题", "严重级别", "实际值", "期望值", "修复建议"}
	for i, header := range headers {
		cell := fmt.Sprintf("%c%d", 'A'+i, row)
		f.SetCellValue(sheetName, cell, header)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}
	f.SetRowHeight(sheetName, row, 20)
	row++

	// 数据行
	for _, r := range results {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), r.RuleID)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), r.Category)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), r.Title)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), r.Severity)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), r.Actual)
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), r.Expected)
		f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), r.FixSuggestion)
		row++
	}

	// 生成文件
	buf, err := f.WriteToBuffer()
	if err != nil {
		h.logger.Error("生成Excel文件失败", zap.Error(err))
		InternalError(c, "生成Excel文件失败")
		return
	}

	filename := fmt.Sprintf("baseline_report_%s_%s.xlsx", host.Hostname, time.Now().Format("20060102_150405"))
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Data(http.StatusOK, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", buf.Bytes())
}
