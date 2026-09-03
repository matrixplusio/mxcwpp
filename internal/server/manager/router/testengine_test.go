package router

import (
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/config"
	"github.com/matrixplusio/mxcwpp/internal/server/manager/sd"
)

// buildTestEngineWithSecret 用最小依赖（内存 sqlite + nil 可选依赖）构建真实路由引擎，
// 以便对实际 Gin 注册结果做访问控制断言。internalSecret 决定内部路由中间件行为。
func buildTestEngineWithSecret(t *testing.T, internalSecret string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	logger := zap.NewNop()
	cfg := &config.Config{}
	cfg.Server.JWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	cfg.Server.InternalSecret = internalSecret
	cfg.Server.GRPC.Host, cfg.Server.GRPC.Port = "127.0.0.1", 6751
	cfg.Server.HTTP.Host, cfg.Server.HTTP.Port = "127.0.0.1", 8080

	reg := sd.NewRegistry(logger)
	dispatcher := sd.NewACDispatcher(reg, nil, logger, internalSecret)

	return Setup(db, logger, cfg,
		nil, // scoreCache
		nil, // metricsService
		reg, dispatcher,
		nil, // chConn
		nil, // redisClient
		nil, // promClient
		nil, // virusDBUpdater
		nil, // consumerManager
	)
}

func buildTestEngine(t *testing.T) *gin.Engine {
	return buildTestEngineWithSecret(t, "")
}
