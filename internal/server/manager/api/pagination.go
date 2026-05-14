package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	defaultPage     = 1
	defaultPageSize = 20
	maxPageSize     = 1000
)

// ParsePagination 从请求中解析分页参数，自动校验边界
func ParsePagination(c *gin.Context) (page, pageSize int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ = strconv.Atoi(c.DefaultQuery("page_size", "20"))

	if page < 1 {
		page = defaultPage
	}
	if pageSize < 1 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return
}

// Paginate 对 GORM query 执行分页查询，返回总数和结果切片
func Paginate(query *gorm.DB, page, pageSize int, orderBy string, dest interface{}) (int64, error) {
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return 0, err
	}
	if total == 0 {
		return 0, nil
	}

	offset := (page - 1) * pageSize
	q := query.Offset(offset).Limit(pageSize)
	if orderBy != "" {
		q = q.Order(orderBy)
	}
	if err := q.Find(dest).Error; err != nil {
		return 0, err
	}
	return total, nil
}
