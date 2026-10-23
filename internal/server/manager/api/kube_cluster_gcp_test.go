package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

type prefixKMS struct{}

func (prefixKMS) EncryptString(s string) (string, error) { return "kms:v1:" + strings.ToUpper(s), nil }
func (prefixKMS) DecryptString(s string) (string, error) {
	return strings.ToLower(strings.TrimPrefix(s, "kms:v1:")), nil
}

// 保存 GCP 凭证时必须落成密文。原先按字段表更新，绕过了模型上的加密钩子，密钥明文落库。
func TestUpdateGCPConfigEncryptsCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	model.SetKMS(prefixKMS{})
	defer model.SetKMS(nil)

	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// kube_clusters 的 updated_at 带 MySQL 专有的 ON UPDATE，sqlite 建不了；只建这个接口读写的列。
	if err := db.Exec("CREATE TABLE kube_clusters (id INTEGER PRIMARY KEY, name TEXT, kube_config TEXT, " +
		"gcp_enabled BOOLEAN, gcp_project_id TEXT, gcp_subscription TEXT, gcp_location TEXT, " +
		"gcp_cluster_name TEXT, gcp_credentials_json TEXT, updated_at DATETIME)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO kube_clusters (id, name) VALUES (1, 'c1')").Error; err != nil {
		t.Fatal(err)
	}
	h := NewKubeClusterHandler(db, zap.NewNop(), nil, nil, nil)
	r := gin.New()
	r.PUT("/kube/clusters/:id/gcp-config", h.UpdateGCPConfig)
	// 接口约定 HTTP 一律 200，结果看返回体里的 code。
	put := func(body string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/kube/clusters/1/gcp-config", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		var resp struct {
			Code int `json:"code"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("返回体不是 JSON：%s", w.Body.String())
		}
		return resp.Code
	}
	stored := func() string {
		var v string
		db.Raw("SELECT gcp_credentials_json FROM kube_clusters WHERE id = 1").Scan(&v)
		return v
	}

	key := `{\"type\":\"service_account\",\"private_key\":\"secret-material\"}`
	if code := put(`{"projectId":"p","subscription":"s","clusterName":"g","credentialsJson":"` + key + `"}`); code != CodeOK {
		t.Fatalf("合法的服务账号密钥应保存成功，得 %d", code)
	}
	if v := stored(); !strings.HasPrefix(v, "kms:v1:") || strings.Contains(v, "secret-material") {
		t.Fatalf("凭证应以密文落库：%q", v)
	}

	// 以加密前缀开头的字符串会被当成「已加密」原样存进去，之后这个集群解密失败。
	before := stored()
	for _, bad := range []string{`kms:v1:plain`, `not json`, `{\"type\":\"authorized_user\"}`} {
		if code := put(`{"projectId":"p","subscription":"s","credentialsJson":"` + bad + `"}`); code != CodeInvalidParam {
			t.Errorf("%q 应被拒绝，得 %d", bad, code)
		}
	}
	if stored() != before {
		t.Error("被拒绝的请求不该改动已存的凭证")
	}
}
