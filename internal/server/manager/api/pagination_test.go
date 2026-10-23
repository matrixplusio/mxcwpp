package api

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestParsePagination_Defaults(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)

	page, pageSize := ParsePagination(c)
	assert.Equal(t, 1, page)
	assert.Equal(t, 20, pageSize)
}

func TestParsePagination_CustomValues(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test?page=3&page_size=50", nil)

	page, pageSize := ParsePagination(c)
	assert.Equal(t, 3, page)
	assert.Equal(t, 50, pageSize)
}

func TestParsePagination_NegativePage(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test?page=-1&page_size=10", nil)

	page, pageSize := ParsePagination(c)
	assert.Equal(t, defaultPage, page)
	assert.Equal(t, 10, pageSize)
}

func TestParsePagination_ZeroPageSize(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test?page=1&page_size=0", nil)

	page, pageSize := ParsePagination(c)
	assert.Equal(t, 1, page)
	assert.Equal(t, defaultPageSize, pageSize)
}

func TestParsePagination_ExceedMaxPageSize(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test?page=1&page_size=9999", nil)

	page, pageSize := ParsePagination(c)
	assert.Equal(t, 1, page)
	assert.Equal(t, maxPageSize, pageSize)
}

func TestParsePagination_InvalidValues(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test?page=abc&page_size=xyz", nil)

	page, pageSize := ParsePagination(c)
	// strconv.Atoi("abc") returns 0, which is < 1, so defaults apply
	assert.Equal(t, defaultPage, page)
	assert.Equal(t, defaultPageSize, pageSize)
}

func TestParsePagination_BoundaryMaxPageSize(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test?page=1&page_size=1000", nil)

	page, pageSize := ParsePagination(c)
	assert.Equal(t, 1, page)
	assert.Equal(t, 1000, pageSize) // 刚好等于 maxPageSize，不截断
}

func TestParsePagination_PageSizeOne(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test?page=100&page_size=1", nil)

	page, pageSize := ParsePagination(c)
	assert.Equal(t, 100, page)
	assert.Equal(t, 1, pageSize)
}
