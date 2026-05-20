package api

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/imkerbos/mxsec-platform/internal/server/model"
)

// TestUploadPackage_ArchParsing 验证 multipart 上传时 arch 字段能被正确解析
// 修复: 前端手动设置 Content-Type: multipart/form-data 不带 boundary 导致解析失败
func TestUploadPackage_ArchParsing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	db.AutoMigrate(&model.Component{}, &model.ComponentVersion{}, &model.ComponentPackage{})

	handler := &ComponentsHandler{
		db:     db,
		logger: zap.NewNop(),
	}

	tests := []struct {
		name        string
		arch        string
		pkgType     string
		wantStatus  int
		wantMessage string
	}{
		{
			name:       "valid amd64 binary",
			arch:       "amd64",
			pkgType:    "binary",
			wantStatus: http.StatusNotFound, // 组件不存在，但说明 arch 解析通过了
		},
		{
			name:       "valid arm64 binary",
			arch:       "arm64",
			pkgType:    "binary",
			wantStatus: http.StatusNotFound,
		},
		{
			name:        "empty arch",
			arch:        "",
			pkgType:     "binary",
			wantStatus:  http.StatusBadRequest,
			wantMessage: "无效的架构",
		},
		{
			name:        "invalid arch",
			arch:        "x86_64",
			pkgType:     "binary",
			wantStatus:  http.StatusBadRequest,
			wantMessage: "无效的架构",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 构造 multipart form（模拟浏览器行为）
			var buf bytes.Buffer
			writer := multipart.NewWriter(&buf)
			writer.WriteField("arch", tt.arch)
			writer.WriteField("pkg_type", tt.pkgType)

			// 添加一个空文件
			part, _ := writer.CreateFormFile("file", "test.bin")
			part.Write([]byte("test content"))
			writer.Close()

			req := httptest.NewRequest(http.MethodPost, "/api/v1/components/1/versions/1/packages", &buf)
			// 让 Go 的 multipart.Writer 设置正确的 Content-Type（带 boundary）
			req.Header.Set("Content-Type", writer.FormDataContentType())

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{
				{Key: "id", Value: "1"},
				{Key: "version_id", Value: "1"},
			}

			handler.UploadPackage(c)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantMessage != "" {
				var resp map[string]any
				json.Unmarshal(w.Body.Bytes(), &resp)
				assert.Contains(t, resp["message"], tt.wantMessage)
			}
		})
	}
}

// TestUploadPackage_NoBoundary 验证没有 boundary 时 arch 解析失败（复现旧 bug）
func TestUploadPackage_NoBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	db.AutoMigrate(&model.Component{}, &model.ComponentVersion{}, &model.ComponentPackage{})

	handler := &ComponentsHandler{
		db:     db,
		logger: zap.NewNop(),
	}

	// 构造 multipart body 但 Content-Type 不带 boundary（复现前端旧 bug）
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("arch", "amd64")
	writer.WriteField("pkg_type", "binary")
	part, _ := writer.CreateFormFile("file", "test.bin")
	part.Write([]byte("test content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/components/1/versions/1/packages", &buf)
	// 故意设置不带 boundary 的 Content-Type（旧前端代码的行为）
	req.Header.Set("Content-Type", "multipart/form-data")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{
		{Key: "id", Value: "1"},
		{Key: "version_id", Value: "1"},
	}

	handler.UploadPackage(c)

	// 没有 boundary 时，Gin 无法解析 PostForm，arch 为空，返回 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "无效的架构")
}
