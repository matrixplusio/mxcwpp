package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/internal/server/manager/biz"
)

func TestGetHostMetricsReturnsDatasourceConfigError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHostsHandler(nil, zap.NewNop(), nil, biz.NewMetricsService(nil, nil, nil, zap.NewNop()))
	router := gin.New()
	router.GET("/api/v1/hosts/:host_id/metrics", handler.GetHostMetrics)

	recorder := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/hosts/host-1/metrics?range=1h", nil)
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Code != CodeInternalError {
		t.Fatalf("code = %d, want %d", response.Code, CodeInternalError)
	}
	if response.Message != "找不到数据源，请配置 Prometheus 数据源" {
		t.Fatalf("message = %q, want %q", response.Message, "找不到数据源，请配置 Prometheus 数据源")
	}
}
