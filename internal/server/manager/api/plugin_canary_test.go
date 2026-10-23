package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

type fakeResender struct{ calls [][]string }

func (f *fakeResender) ResendPluginConfigs(ids []string) (int, error) {
	f.calls = append(f.calls, append([]string(nil), ids...))
	return len(ids), nil
}

func setupCanaryTest(t *testing.T) (*gin.Engine, *gorm.DB, *fakeResender) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	require.NoError(t, err)
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	require.NoError(t, db.AutoMigrate(&model.Component{}, &model.ComponentVersion{}, &model.ComponentPackage{},
		&model.PluginConfig{}, &model.PluginCanary{}))
	require.NoError(t, db.Exec(`CREATE TABLE hosts (host_id TEXT PRIMARY KEY, status TEXT, behavior_suppress_until DATETIME)`).Error)
	for _, h := range []string{"h1", "h2", "h3"} {
		require.NoError(t, db.Exec(`INSERT INTO hosts (host_id, status) VALUES (?, 'online')`, h).Error)
	}

	comp := model.Component{Name: "fim", Category: model.ComponentCategoryPlugin}
	require.NoError(t, db.Create(&comp).Error)
	for _, v := range []struct {
		ver, sha string
		latest   bool
	}{{"1.0.1", "sha-101", true}, {"1.0.2", "sha-102", false}, {"1.0.3", "sha-103", false}} {
		cv := model.ComponentVersion{ComponentID: comp.ID, Version: v.ver, IsLatest: v.latest}
		require.NoError(t, db.Create(&cv).Error)
		require.NoError(t, db.Create(&model.ComponentPackage{VersionID: cv.ID, Arch: "amd64", PkgType: "binary",
			FilePath: "/nonexistent", SHA256: v.sha, Enabled: true}).Error)
	}
	require.NoError(t, db.Create(&model.PluginConfig{Name: "fim", Type: "fim", Version: "1.0.1", SHA256: "sha-101",
		Enabled: true}).Error)

	res := &fakeResender{}
	h := &ComponentsHandler{db: db, logger: zap.NewNop(), downloadSem: make(chan struct{}, 1)}
	h.SetPluginResender(res)
	r := gin.New()
	r.GET("/canary/:name", h.GetPluginCanary)
	r.POST("/canary/:name", h.StartPluginCanary)
	r.DELETE("/canary/:name", h.RollbackPluginCanary)
	r.POST("/canary/:name/promote", h.PromotePluginCanary)
	return r, db, res
}

// codeOf 取响应体里的业务码：本项目接口一律 HTTP 200，错误码放在 body.code（成功为 0）。
func codeOf(w *httptest.ResponseRecorder) int {
	var b struct {
		Code int `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return b.Code
}

func doJSON(r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestPluginCanary_Lifecycle 开始→追加→拒绝第二个版本→回滚→再开始→转正。
func TestPluginCanary_Lifecycle(t *testing.T) {
	r, db, res := setupCanaryTest(t)

	w := doJSON(r, http.MethodPost, "/canary/fim", map[string]any{"version": "1.0.2", "host_ids": []string{"h1"}})
	require.Equal(t, 0, codeOf(w), w.Body.String())
	var c model.PluginCanary
	require.NoError(t, db.Where("plugin_name = ?", "fim").First(&c).Error)
	require.Equal(t, "sha-102", c.SHA256, "sha 取该版本 amd64 包")
	require.Equal(t, []string{"h1"}, res.calls[0], "开始灰度要立即给名单内主机重发")

	// 同一版本追加主机
	w = doJSON(r, http.MethodPost, "/canary/fim", map[string]any{"version": "1.0.2", "host_ids": []string{"h2", "h1"}})
	require.Equal(t, 0, codeOf(w), w.Body.String())
	require.NoError(t, db.Where("plugin_name = ?", "fim").First(&c).Error)
	require.ElementsMatch(t, []string{"h1", "h2"}, []string(c.HostIDs))

	// 另一个版本在灰度中时拒绝
	w = doJSON(r, http.MethodPost, "/canary/fim", map[string]any{"version": "1.0.3", "host_ids": []string{"h3"}})
	require.Equal(t, CodeConflict, codeOf(w))

	// 回滚：删记录并给原名单重发
	w = doJSON(r, http.MethodDelete, "/canary/fim", nil)
	require.Equal(t, 0, codeOf(w), w.Body.String())
	var n int64
	db.Model(&model.PluginCanary{}).Count(&n)
	require.Zero(t, n)
	require.ElementsMatch(t, []string{"h1", "h2"}, res.calls[len(res.calls)-1])

	// 再开始并转正：全局版本切到灰度版本，灰度记录删除
	require.Equal(t, 0, codeOf(doJSON(r, http.MethodPost, "/canary/fim", map[string]any{"version": "1.0.3", "host_ids": []string{"h3"}})))
	w = doJSON(r, http.MethodPost, "/canary/fim/promote", nil)
	require.Equal(t, 0, codeOf(w), w.Body.String())
	var pc model.PluginConfig
	require.NoError(t, db.Where("name = ?", "fim").First(&pc).Error)
	require.Equal(t, "1.0.3", pc.Version)
	require.Equal(t, "sha-103", pc.SHA256)
	db.Model(&model.PluginCanary{}).Count(&n)
	require.Zero(t, n)
}

// TestPluginCanary_Rejects 全局版本、未知主机、不存在的版本都拒绝。
func TestPluginCanary_Rejects(t *testing.T) {
	r, _, _ := setupCanaryTest(t)
	require.Equal(t, CodeInvalidParam, codeOf(doJSON(r, http.MethodPost, "/canary/fim", map[string]any{"version": "1.0.1", "host_ids": []string{"h1"}})))
	require.Equal(t, CodeInvalidParam, codeOf(doJSON(r, http.MethodPost, "/canary/fim", map[string]any{"version": "1.0.2", "host_ids": []string{"nope"}})))
	require.Equal(t, CodeNotFound, codeOf(doJSON(r, http.MethodPost, "/canary/fim", map[string]any{"version": "9.9.9", "host_ids": []string{"h1"}})))
	require.Equal(t, CodeNotFound, codeOf(doJSON(r, http.MethodDelete, "/canary/fim", nil)))
}

// 全新插件没有全局配置：灰度先建一条不带下载地址的占位配置（AC 会跳过它，只有灰度主机拿得到），
// 追加主机不重复建，转正时被正式配置覆盖。
func TestPluginCanary_NewPluginGetsPlaceholder(t *testing.T) {
	r, db, _ := setupCanaryTest(t)
	comp := model.Component{Name: "logcollector", Category: model.ComponentCategoryPlugin}
	require.NoError(t, db.Create(&comp).Error)
	cv := model.ComponentVersion{ComponentID: comp.ID, Version: "1.0.0"}
	require.NoError(t, db.Create(&cv).Error)
	require.NoError(t, db.Create(&model.ComponentPackage{VersionID: cv.ID, Arch: "amd64", PkgType: "binary",
		FilePath: "/nonexistent", SHA256: "sha-lc", Enabled: true}).Error)

	w := doJSON(r, http.MethodPost, "/canary/logcollector", map[string]any{"version": "1.0.0", "host_ids": []string{"h1"}})
	require.Equal(t, 0, codeOf(w), w.Body.String())
	var pcs []model.PluginConfig
	require.NoError(t, db.Where("name = ?", "logcollector").Find(&pcs).Error)
	require.Len(t, pcs, 1)
	require.True(t, pcs[0].Enabled)
	require.Empty(t, pcs[0].DownloadURLs, "占位配置不能带下载地址，否则全网都会拉")
	require.Empty(t, pcs[0].Version)

	w = doJSON(r, http.MethodPost, "/canary/logcollector", map[string]any{"version": "1.0.0", "host_ids": []string{"h2"}})
	require.Equal(t, 0, codeOf(w), w.Body.String())
	var n int64
	db.Model(&model.PluginConfig{}).Where("name = ?", "logcollector").Count(&n)
	require.EqualValues(t, 1, n, "追加主机不重复建占位")

	w = doJSON(r, http.MethodPost, "/canary/logcollector/promote", nil)
	require.Equal(t, 0, codeOf(w), w.Body.String())
	var pc model.PluginConfig
	require.NoError(t, db.Where("name = ?", "logcollector").First(&pc).Error)
	require.Equal(t, "1.0.0", pc.Version)
	require.Equal(t, "sha-lc", pc.SHA256)
	require.NotEmpty(t, pc.DownloadURLs, "转正后才是正式的全局配置")
}
