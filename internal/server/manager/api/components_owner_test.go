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
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// 版本接口必须核对 :version_id 属于 :id 组件。version_id 为空时 GORM 会去掉条件、
// 取到全表第一条，插件包就会挂到别的组件下。
func setupOwnerTest(t *testing.T) (*ComponentsHandler, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{DisableForeignKeyConstraintWhenMigrating: true})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.Component{}, &model.ComponentVersion{}, &model.ComponentPackage{},
		&model.PluginConfig{}))
	// 组件 1 是 agent，版本 1 属于它；组件 2 是插件，版本 2 属于它。
	require.NoError(t, db.Create(&model.Component{ID: 1, Name: "agent", Category: model.ComponentCategoryAgent}).Error)
	require.NoError(t, db.Create(&model.Component{ID: 2, Name: "logcollector", Category: model.ComponentCategoryPlugin}).Error)
	require.NoError(t, db.Create(&model.ComponentVersion{ID: 1, ComponentID: 1, Version: "1.0.0", IsLatest: true}).Error)
	require.NoError(t, db.Create(&model.ComponentVersion{ID: 2, ComponentID: 2, Version: "1.0.0"}).Error)
	return &ComponentsHandler{db: db, logger: zap.NewNop()}, db
}

func callWithParams(h gin.HandlerFunc, method string, body *bytes.Buffer, contentType string, params gin.Params) map[string]any {
	if body == nil {
		body = &bytes.Buffer{}
	}
	req := httptest.NewRequest(method, "/x", body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = params
	h(c)
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return resp
}

func uploadForm(t *testing.T) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("arch", "amd64")
	_ = w.WriteField("pkg_type", "binary")
	part, _ := w.CreateFormFile("file", "logcollector")
	_, _ = part.Write([]byte("bin"))
	require.NoError(t, w.Close())
	return &buf, w.FormDataContentType()
}

func TestUploadPackageRejectsBadVersionID(t *testing.T) {
	h, db := setupOwnerTest(t)
	for _, vid := range []string{"", "1.0", "1 OR 1=1", "0", "-1"} {
		body, ct := uploadForm(t)
		resp := callWithParams(h.UploadPackage, http.MethodPost, body, ct,
			gin.Params{{Key: "id", Value: "2"}, {Key: "version_id", Value: vid}})
		assert.EqualValues(t, CodeInvalidParam, resp["code"], "version_id=%q", vid)
	}
	var n int64
	db.Model(&model.ComponentPackage{}).Count(&n)
	assert.Zero(t, n, "参数非法时不能写入任何包")
}

func TestUploadPackageRejectsVersionOfOtherComponent(t *testing.T) {
	h, db := setupOwnerTest(t)
	body, ct := uploadForm(t)
	// 组件 2 的插件包，指向组件 1（agent）的版本
	resp := callWithParams(h.UploadPackage, http.MethodPost, body, ct,
		gin.Params{{Key: "id", Value: "2"}, {Key: "version_id", Value: "1"}})
	assert.EqualValues(t, CodeNotFound, resp["code"])
	var n int64
	db.Model(&model.ComponentPackage{}).Count(&n)
	assert.Zero(t, n)
}

func TestVersionEndpointsRequireOwnership(t *testing.T) {
	h, db := setupOwnerTest(t)
	cross := gin.Params{{Key: "id", Value: "2"}, {Key: "version_id", Value: "1"}}

	assert.EqualValues(t, CodeNotFound, callWithParams(h.GetVersion, http.MethodGet, nil, "", cross)["code"])
	assert.EqualValues(t, CodeNotFound, callWithParams(h.SetLatestVersion, http.MethodPut, nil, "", cross)["code"])
	assert.EqualValues(t, CodeNotFound, callWithParams(h.DeleteVersion, http.MethodDelete, nil, "", cross)["code"])

	var v1 model.ComponentVersion
	require.NoError(t, db.First(&v1, 1).Error, "跨组件删除不能生效")
	assert.True(t, v1.IsLatest, "跨组件设最新不能动 agent 的 latest")
	var v2 model.ComponentVersion
	require.NoError(t, db.First(&v2, 2).Error)
	assert.False(t, v2.IsLatest)

	// 自己的版本照常可读
	own := gin.Params{{Key: "id", Value: "2"}, {Key: "version_id", Value: "2"}}
	assert.EqualValues(t, CodeOK, callWithParams(h.GetVersion, http.MethodGet, nil, "", own)["code"])
}

func TestApplyLatestVersionUsesVersionsOwnComponent(t *testing.T) {
	h, db := setupOwnerTest(t)
	v2 := model.ComponentVersion{}
	require.NoError(t, db.First(&v2, 2).Error)
	require.NoError(t, h.applyLatestVersion(&v2))

	var v1 model.ComponentVersion
	require.NoError(t, db.First(&v1, 1).Error)
	assert.True(t, v1.IsLatest, "设组件 2 的最新，不能清掉组件 1 的 latest")
	require.NoError(t, db.First(&v2, 2).Error)
	assert.True(t, v2.IsLatest)
}

func TestComponentEndpointsRejectNonNumericID(t *testing.T) {
	h, _ := setupOwnerTest(t)
	for _, id := range []string{"", "1 OR 1=1", "abc"} {
		p := gin.Params{{Key: "id", Value: id}}
		assert.EqualValues(t, CodeInvalidParam, callWithParams(h.GetComponent, http.MethodGet, nil, "", p)["code"], "id=%q", id)
		assert.EqualValues(t, CodeInvalidParam, callWithParams(h.DeleteComponent, http.MethodDelete, nil, "", p)["code"], "id=%q", id)
		assert.EqualValues(t, CodeInvalidParam, callWithParams(h.DeletePackage, http.MethodDelete, nil, "", p)["code"], "id=%q", id)
	}
}

// 路径参数里的 SQL 片段在进库之前就被拒绝：GORM 的 First(&x, 字符串) 会把非数字串原样拼进 WHERE。
func TestPathIDRejectsInjection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, v := range []string{"", "0", "-1", "1 OR 1=1", "0 OR (SELECT 1)", "1;DROP TABLE users", "abc", "99999999999"} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = gin.Params{{Key: "id", Value: v}}
		if _, ok := pathID(c, "id"); ok {
			t.Errorf("pathID(%q) 不该通过", v)
		}
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "42"}}
	if id, ok := pathID(c, "id"); !ok || id != 42 {
		t.Fatalf("pathID(42) = %d, %v", id, ok)
	}
}

func TestUserBackupMigrationHandlersRejectInjectedID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	p := gin.Params{{Key: "id", Value: "0 OR 1=1"}}
	handlers := map[string]gin.HandlerFunc{
		"GetUser":        (&UsersHandler{db: db, logger: zap.NewNop()}).GetUser,
		"DownloadBackup": (&BackupsHandler{db: db, logger: zap.NewNop()}).DownloadBackup,
		"GetJob":         (&MigrationHandler{db: db, logger: zap.NewNop()}).GetJob,
	}
	for name, h := range handlers {
		assert.EqualValues(t, CodeInvalidParam, callWithParams(h, http.MethodGet, nil, "", p)["code"], name)
	}
}
