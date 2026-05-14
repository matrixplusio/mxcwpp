// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/imkerbos/mxsec-platform/plugins/collector/engine"
)

// UserHandler 是账户采集器
type UserHandler struct {
	Logger *zap.Logger
}

// Collect 采集账户信息
func (h *UserHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var users []interface{}

	// 读取 /etc/passwd
	passwdPath := "/etc/passwd"
	passwdData, err := os.ReadFile(passwdPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/passwd: %w", err)
	}

	// 读取 /etc/shadow（如果可读，用于判断是否有密码）
	shadowPath := "/etc/shadow"
	shadowData, _ := os.ReadFile(shadowPath)
	shadowMap := h.parseShadow(shadowData)

	// 解析 passwd 文件
	lines := strings.Split(string(passwdData), "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return users, ctx.Err()
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		userAsset, err := h.parsePasswdLine(line, shadowMap)
		if err != nil {
			h.Logger.Debug("failed to parse passwd line",
				zap.String("line", line),
				zap.Error(err))
			continue
		}

		if userAsset != nil {
			users = append(users, userAsset)
		}
	}

	return users, nil
}

// parsePasswdLine 解析 /etc/passwd 行
// 格式：username:password:uid:gid:comment:home_dir:shell
func (h *UserHandler) parsePasswdLine(line string, shadowMap map[string]bool) (*engine.UserAsset, error) {
	parts := strings.Split(line, ":")
	if len(parts) < 7 {
		return nil, fmt.Errorf("invalid passwd line format")
	}

	username := parts[0]
	uid := parts[2]
	gid := parts[3]
	comment := parts[4]
	homeDir := parts[5]
	shell := parts[6]

	// 解析组名
	groupname := ""
	if g, err := user.LookupGroupId(gid); err == nil {
		groupname = g.Name
	}

	// 判断是否有密码（基于 shadow 文件）
	hasPassword := shadowMap[username]

	// 构建账户资产数据
	userAsset := &engine.UserAsset{
		Asset: engine.Asset{
			CollectedAt: time.Now(),
		},
		Username:    username,
		UID:         uid,
		GID:         gid,
		Groupname:   groupname,
		HomeDir:     homeDir,
		Shell:       shell,
		Comment:     comment,
		HasPassword: hasPassword,
	}

	return userAsset, nil
}

// parseShadow 解析 /etc/shadow 文件，返回用户名到是否有密码的映射
// 格式：username:password:last_change:min:max:warn:inactive:expire
func (h *UserHandler) parseShadow(data []byte) map[string]bool {
	shadowMap := make(map[string]bool)

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		username := parts[0]
		password := parts[1]

		// 如果密码字段不是 * 或 !，则认为有密码
		hasPassword := password != "" && password != "*" && password != "!"
		shadowMap[username] = hasPassword
	}

	return shadowMap
}
