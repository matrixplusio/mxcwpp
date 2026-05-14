// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/plugins/collector/engine"
)

// KmodHandler 是内核模块采集器
type KmodHandler struct {
	Logger *zap.Logger
}

// Collect 采集内核模块信息
func (h *KmodHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var modules []interface{}

	// 读取 /proc/modules 获取已加载的内核模块
	modulesData, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/modules: %w", err)
	}

	lines := strings.Split(string(modulesData), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return modules, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析 /proc/modules 格式：module_name size used_by_count used_by_list state
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		moduleName := fields[0]
		sizeStr := fields[1]
		usedByStr := fields[2]

		// 解析大小（字节）
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			h.Logger.Debug("failed to parse module size",
				zap.String("module", moduleName),
				zap.String("size", sizeStr),
				zap.Error(err))
			continue
		}

		// 解析引用计数
		usedBy, err := strconv.Atoi(usedByStr)
		if err != nil {
			h.Logger.Debug("failed to parse used_by count",
				zap.String("module", moduleName),
				zap.String("used_by", usedByStr),
				zap.Error(err))
			usedBy = 0
		}

		// 解析状态（如果有）
		state := "Live"
		if len(fields) > 4 {
			state = fields[4]
		}

		module := &engine.KmodAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			ModuleName: moduleName,
			Size:       size,
			UsedBy:     usedBy,
			State:      state,
		}

		modules = append(modules, module)
	}

	return modules, nil
}
