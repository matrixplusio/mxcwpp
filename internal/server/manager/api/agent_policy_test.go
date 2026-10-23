package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func agentPolicyRouter(t *testing.T) *gin.Engine {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.Exec("CREATE TABLE system_configs (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, `key` TEXT, value TEXT, category TEXT, description TEXT, created_at DATETIME, updated_at DATETIME)").Error; err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := NewSystemConfigHandler(db, zap.NewNop(), t.TempDir(), "/uploads")
	r := gin.New()
	r.GET("/p", h.GetAgentPolicy)
	r.PUT("/p", h.UpdateAgentPolicy)
	return r
}

func callPolicy(r *gin.Engine, method string, body any) (int, map[string]any) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "/p", &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var resp struct {
		Code int            `json:"code"`
		Data map[string]any `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.Code, resp.Data
}

func TestAgentPolicyAPI(t *testing.T) {
	r := agentPolicyRouter(t)

	code, data := callPolicy(r, http.MethodGet, nil)
	if code != 0 || data["configured"] != false {
		t.Fatalf("未初始化时应返回默认值并标明 configured=false，实际 code=%d data=%v", code, data)
	}

	if code, _ := callPolicy(r, http.MethodPut, map[string]any{"identity_conflict": "drop"}); code == 0 {
		t.Fatal("非法取值应被拒绝")
	}

	if code, _ := callPolicy(r, http.MethodPut, map[string]any{"identity_conflict": "reject", "auto_update": false}); code != 0 {
		t.Fatalf("合法取值应保存成功，实际 %d", code)
	}
	_, data = callPolicy(r, http.MethodGet, nil)
	policy, _ := data["policy"].(map[string]any)
	if data["configured"] != true || policy["identity_conflict"] != "reject" {
		t.Fatalf("保存后应读回，实际 %v", data)
	}
}
