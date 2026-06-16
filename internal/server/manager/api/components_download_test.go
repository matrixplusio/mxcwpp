package api

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// setupDownloadTest 创建 ComponentsHandler 及测试用的插件包文件，返回 handler 和清理函数
func setupDownloadTest(t *testing.T, fileSize int64) (*ComponentsHandler, func()) {
	t.Helper()

	db := setupTestDB(t)

	// 创建临时目录存放测试文件
	tmpDir := t.TempDir()
	pluginFile := filepath.Join(tmpDir, "virus-database-20260504.tar.gz")

	f, err := os.Create(pluginFile)
	require.NoError(t, err)
	_, err = io.CopyN(f, rand.Reader, fileSize)
	require.NoError(t, err)
	f.Close()

	// 向数据库写入 Component → Version → Package
	comp := model.Component{Name: "virus-database", Category: model.ComponentCategoryPlugin}
	require.NoError(t, db.Create(&comp).Error)

	ver := model.ComponentVersion{ComponentID: comp.ID, Version: "20260504.100000", IsLatest: true}
	require.NoError(t, db.Create(&ver).Error)

	pkg := model.ComponentPackage{
		VersionID: ver.ID,
		Arch:      "all",
		PkgType:   "binary",
		FilePath:  pluginFile,
		FileSize:  fileSize,
		SHA256:    "abc123",
		Enabled:   true,
	}
	require.NoError(t, db.Create(&pkg).Error)

	handler := &ComponentsHandler{
		db:          db,
		logger:      zap.NewNop(),
		uploadDir:   tmpDir,
		downloadSem: make(chan struct{}, 10),
	}

	return handler, func() { os.RemoveAll(tmpDir) }
}

// TestDownloadPluginPackage_Success 验证正常下载：状态码 200、Content-Length 与文件一致、响应体完整
func TestDownloadPluginPackage_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fileSize := int64(1024 * 100) // 100 KB
	handler, cleanup := setupDownloadTest(t, fileSize)
	defer cleanup()

	r := gin.New()
	r.GET("/api/v1/plugins/download/:name", handler.DownloadPluginPackage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins/download/virus-database?arch=amd64", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Content-Length 应等于实际文件大小
	clHeader := w.Header().Get("Content-Length")
	cl, err := strconv.ParseInt(clHeader, 10, 64)
	require.NoError(t, err)
	assert.Equal(t, fileSize, cl)

	// 响应体大小应等于文件大小
	assert.Equal(t, fileSize, int64(w.Body.Len()))

	// 自定义头应存在
	assert.Equal(t, "virus-database", w.Header().Get("X-Plugin-Name"))
	assert.Equal(t, "20260504.100000", w.Header().Get("X-Plugin-Version"))
	assert.Equal(t, "abc123", w.Header().Get("X-Plugin-SHA256"))
}

// TestDownloadPluginPackage_NotFound 验证插件不存在时返回 404
func TestDownloadPluginPackage_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupTestDB(t)
	handler := &ComponentsHandler{
		db:          db,
		logger:      zap.NewNop(),
		downloadSem: make(chan struct{}, 10),
	}

	r := gin.New()
	r.GET("/api/v1/plugins/download/:name", handler.DownloadPluginPackage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins/download/no-such-plugin?arch=amd64", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 统一响应：插件不存在时 handler 走 NotFound()，HTTP 200 + body code=40400
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(CodeNotFound), resp["code"])
}

// TestDownloadPluginPackage_FileMissing 验证数据库有记录但文件已删除时返回 404
func TestDownloadPluginPackage_FileMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	fileSize := int64(1024)
	handler, cleanup := setupDownloadTest(t, fileSize)
	defer cleanup()

	// 删除文件模拟文件丢失
	var pkg model.ComponentPackage
	require.NoError(t, handler.db.First(&pkg).Error)
	os.Remove(pkg.FilePath)

	r := gin.New()
	r.GET("/api/v1/plugins/download/:name", handler.DownloadPluginPackage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins/download/virus-database?arch=amd64", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// 统一响应：文件丢失时 handler 走 NotFound()，HTTP 200 + body code=40400
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(CodeNotFound), resp["code"])
}

// TestDownloadPluginPackage_ContentLengthMatchesActualFile 验证 Content-Length 使用实际文件大小
// 模拟数据库记录的 FileSize 与实际文件大小不一致的情况
func TestDownloadPluginPackage_ContentLengthMatchesActualFile(t *testing.T) {
	gin.SetMode(gin.TestMode)

	actualSize := int64(2048)
	handler, cleanup := setupDownloadTest(t, actualSize)
	defer cleanup()

	// 篡改数据库中的 FileSize，使其与实际文件不一致
	handler.db.Model(&model.ComponentPackage{}).Where("1=1").Update("file_size", 9999)

	r := gin.New()
	r.GET("/api/v1/plugins/download/:name", handler.DownloadPluginPackage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins/download/virus-database?arch=amd64", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Content-Length 应等于实际文件大小（2048），而非数据库记录的 9999
	assert.Equal(t, actualSize, int64(w.Body.Len()))
}
