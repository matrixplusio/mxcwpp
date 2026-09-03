package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuccess(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Success(c, gin.H{"key": "value"})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(0), resp["code"])
	data := resp["data"].(map[string]any)
	assert.Equal(t, "value", data["key"])
}

func TestSuccessMessage(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	SuccessMessage(c, "操作成功")

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(0), resp["code"])
	assert.Equal(t, "操作成功", resp["message"])
}

func TestSuccessWithMessage(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	SuccessWithMessage(c, "done", gin.H{"id": 1})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(0), resp["code"])
	assert.Equal(t, "done", resp["message"])
	assert.NotNil(t, resp["data"])
}

func TestSuccessPaginated(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	items := []string{"a", "b"}
	SuccessPaginated(c, 100, items)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(0), resp["code"])

	data := resp["data"].(map[string]any)
	assert.Equal(t, float64(100), data["total"])
	assert.Len(t, data["items"].([]any), 2)
}

func TestCreated(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Created(c, gin.H{"id": 42})

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(0), resp["code"])
}

func TestErrorResponses(t *testing.T) {
	tests := []struct {
		name       string
		fn         func(*gin.Context, string)
		wantStatus int
		wantCode   float64
	}{
		// 统一响应约定：业务错误一律 HTTP 200 + body code（见 respcode.go）。
		{"BadRequest", BadRequest, http.StatusOK, float64(CodeInvalidParam)},
		{"NotFound", NotFound, http.StatusOK, float64(CodeNotFound)},
		{"Conflict", Conflict, http.StatusOK, float64(CodeConflict)},
		{"InternalError", InternalError, http.StatusOK, float64(CodeInternalError)},
		{"Unauthorized", Unauthorized, http.StatusOK, float64(CodeUnauthorized)},
		{"Forbidden", Forbidden, http.StatusOK, float64(CodeForbidden)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			tt.fn(c, "test error")

			assert.Equal(t, tt.wantStatus, w.Code)

			var resp map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, tt.wantCode, resp["code"])
			assert.Equal(t, "test error", resp["message"])
		})
	}
}
