// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/plugins/collector/engine"
)

// AppHandler 是应用采集器
type AppHandler struct {
	Logger *zap.Logger
}

// Collect 采集应用信息
func (h *AppHandler) Collect(ctx context.Context) ([]interface{}, error) {
	var apps []interface{}

	// 检测常见应用
	appDetectors := []func(context.Context) ([]interface{}, error){
		h.detectMySQL,
		h.detectPostgreSQL,
		h.detectRedis,
		h.detectMongoDB,
		h.detectNginx,
		h.detectApache,
		h.detectKafka,
		h.detectElasticsearch,
		h.detectRabbitMQ,
	}

	for _, detector := range appDetectors {
		select {
		case <-ctx.Done():
			return apps, ctx.Err()
		default:
		}

		detectedApps, err := detector(ctx)
		if err != nil {
			h.Logger.Debug("failed to detect app", zap.Error(err))
			continue
		}

		apps = append(apps, detectedApps...)
	}

	return apps, nil
}

// detectMySQL 检测 MySQL
func (h *AppHandler) detectMySQL(ctx context.Context) ([]interface{}, error) {
	var apps []interface{}

	// 检测 mysqld 进程
	processes, err := h.findProcessByName("mysqld")
	if err != nil || len(processes) == 0 {
		return apps, nil
	}

	for _, proc := range processes {
		port := h.extractPortFromProcess(proc)
		version := h.getMySQLVersion(ctx)

		app := &engine.AppAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			AppType:   "mysql",
			AppName:   "MySQL",
			Version:   version,
			Port:      port,
			ProcessID: proc["pid"],
		}

		// 尝试找到配置文件
		if configPath := h.findMySQLConfig(proc); configPath != "" {
			app.ConfigPath = configPath
		}

		apps = append(apps, app)
	}

	return apps, nil
}

// detectPostgreSQL 检测 PostgreSQL
func (h *AppHandler) detectPostgreSQL(ctx context.Context) ([]interface{}, error) {
	var apps []interface{}

	processes, err := h.findProcessByName("postgres")
	if err != nil || len(processes) == 0 {
		return apps, nil
	}

	for _, proc := range processes {
		port := h.extractPortFromProcess(proc)
		version := h.getPostgreSQLVersion(ctx)

		app := &engine.AppAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			AppType:   "postgresql",
			AppName:   "PostgreSQL",
			Version:   version,
			Port:      port,
			ProcessID: proc["pid"],
		}

		if configPath := h.findPostgreSQLConfig(proc); configPath != "" {
			app.ConfigPath = configPath
		}

		apps = append(apps, app)
	}

	return apps, nil
}

// detectRedis 检测 Redis
func (h *AppHandler) detectRedis(ctx context.Context) ([]interface{}, error) {
	var apps []interface{}

	processes, err := h.findProcessByName("redis-server")
	if err != nil || len(processes) == 0 {
		return apps, nil
	}

	for _, proc := range processes {
		port := h.extractPortFromProcess(proc)
		version := h.getRedisVersion(ctx, proc["pid"])

		app := &engine.AppAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			AppType:   "redis",
			AppName:   "Redis",
			Version:   version,
			Port:      port,
			ProcessID: proc["pid"],
		}

		if configPath := h.findRedisConfig(proc); configPath != "" {
			app.ConfigPath = configPath
		}

		apps = append(apps, app)
	}

	return apps, nil
}

// detectMongoDB 检测 MongoDB
func (h *AppHandler) detectMongoDB(ctx context.Context) ([]interface{}, error) {
	var apps []interface{}

	processes, err := h.findProcessByName("mongod")
	if err != nil || len(processes) == 0 {
		return apps, nil
	}

	for _, proc := range processes {
		port := h.extractPortFromProcess(proc)
		version := h.getMongoDBVersion(ctx)

		app := &engine.AppAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			AppType:   "mongodb",
			AppName:   "MongoDB",
			Version:   version,
			Port:      port,
			ProcessID: proc["pid"],
		}

		if configPath := h.findMongoDBConfig(proc); configPath != "" {
			app.ConfigPath = configPath
		}

		apps = append(apps, app)
	}

	return apps, nil
}

// detectNginx 检测 Nginx
func (h *AppHandler) detectNginx(ctx context.Context) ([]interface{}, error) {
	var apps []interface{}

	processes, err := h.findProcessByName("nginx")
	if err != nil || len(processes) == 0 {
		return apps, nil
	}

	for _, proc := range processes {
		port := h.extractPortFromProcess(proc)
		version := h.getNginxVersion(ctx)

		app := &engine.AppAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			AppType:   "nginx",
			AppName:   "Nginx",
			Version:   version,
			Port:      port,
			ProcessID: proc["pid"],
		}

		if configPath := h.findNginxConfig(proc); configPath != "" {
			app.ConfigPath = configPath
		}

		apps = append(apps, app)
	}

	return apps, nil
}

// detectApache 检测 Apache
func (h *AppHandler) detectApache(ctx context.Context) ([]interface{}, error) {
	var apps []interface{}

	processes, err := h.findProcessByName("httpd")
	if err != nil {
		processes, err = h.findProcessByName("apache2")
	}

	if err != nil || len(processes) == 0 {
		return apps, nil
	}

	for _, proc := range processes {
		port := h.extractPortFromProcess(proc)
		version := h.getApacheVersion(ctx)

		appName := "Apache"
		if strings.Contains(proc["cmdline"], "apache2") {
			appName = "Apache2"
		}

		app := &engine.AppAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			AppType:   "apache",
			AppName:   appName,
			Version:   version,
			Port:      port,
			ProcessID: proc["pid"],
		}

		if configPath := h.findApacheConfig(proc); configPath != "" {
			app.ConfigPath = configPath
		}

		apps = append(apps, app)
	}

	return apps, nil
}

// detectKafka 检测 Kafka
func (h *AppHandler) detectKafka(ctx context.Context) ([]interface{}, error) {
	var apps []interface{}

	processes, err := h.findProcessByName("kafka")
	if err != nil || len(processes) == 0 {
		return apps, nil
	}

	for _, proc := range processes {
		port := h.extractPortFromProcess(proc)

		app := &engine.AppAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			AppType:   "kafka",
			AppName:   "Kafka",
			Port:      port,
			ProcessID: proc["pid"],
		}

		apps = append(apps, app)
	}

	return apps, nil
}

// detectElasticsearch 检测 Elasticsearch
func (h *AppHandler) detectElasticsearch(ctx context.Context) ([]interface{}, error) {
	var apps []interface{}

	processes, err := h.findProcessByName("elasticsearch")
	if err != nil || len(processes) == 0 {
		return apps, nil
	}

	for _, proc := range processes {
		port := h.extractPortFromProcess(proc)

		app := &engine.AppAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			AppType:   "elasticsearch",
			AppName:   "Elasticsearch",
			Port:      port,
			ProcessID: proc["pid"],
		}

		apps = append(apps, app)
	}

	return apps, nil
}

// detectRabbitMQ 检测 RabbitMQ
func (h *AppHandler) detectRabbitMQ(ctx context.Context) ([]interface{}, error) {
	var apps []interface{}

	processes, err := h.findProcessByName("rabbitmq-server")
	if err != nil || len(processes) == 0 {
		return apps, nil
	}

	for _, proc := range processes {
		port := h.extractPortFromProcess(proc)

		app := &engine.AppAsset{
			Asset: engine.Asset{
				CollectedAt: time.Now(),
			},
			AppType:   "rabbitmq",
			AppName:   "RabbitMQ",
			Port:      port,
			ProcessID: proc["pid"],
		}

		apps = append(apps, app)
	}

	return apps, nil
}

// findProcessByName 根据进程名查找进程
func (h *AppHandler) findProcessByName(name string) ([]map[string]string, error) {
	var processes []map[string]string

	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		cmdlinePath := filepath.Join(procDir, pid, "cmdline")
		cmdline, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}

		cmdlineStr := strings.ReplaceAll(string(cmdline), "\x00", " ")
		if strings.Contains(cmdlineStr, name) {
			processes = append(processes, map[string]string{
				"pid":     pid,
				"cmdline": cmdlineStr,
			})
		}
	}

	return processes, nil
}

// extractPortFromProcess 从进程命令行中提取端口号
func (h *AppHandler) extractPortFromProcess(proc map[string]string) int {
	cmdline := proc["cmdline"]

	// 尝试从命令行参数中提取端口（--port、-p、--listen 等）
	patterns := []string{"--port=", "-p ", "--listen=", "--port "}
	for _, pattern := range patterns {
		idx := strings.Index(cmdline, pattern)
		if idx != -1 {
			parts := strings.Fields(cmdline[idx+len(pattern):])
			if len(parts) == 0 {
				continue
			}
			if port, err := strconv.Atoi(parts[0]); err == nil {
				return port
			}
		}
	}

	return 0
}

// getMySQLVersion 获取 MySQL 版本
func (h *AppHandler) getMySQLVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "mysql", "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// getPostgreSQLVersion 获取 PostgreSQL 版本
func (h *AppHandler) getPostgreSQLVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "psql", "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// getRedisVersion 获取 Redis 版本
func (h *AppHandler) getRedisVersion(ctx context.Context, pid string) string {
	cmd := exec.CommandContext(ctx, "redis-cli", "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// getMongoDBVersion 获取 MongoDB 版本
func (h *AppHandler) getMongoDBVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "mongod", "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return ""
}

// getNginxVersion 获取 Nginx 版本
func (h *AppHandler) getNginxVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "nginx", "-v")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// getApacheVersion 获取 Apache 版本
func (h *AppHandler) getApacheVersion(ctx context.Context) string {
	output, err := exec.CommandContext(ctx, "httpd", "-v").Output()
	if err != nil {
		output, err = exec.CommandContext(ctx, "apache2", "-v").Output()
		if err != nil {
			return ""
		}
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return ""
}

// findMySQLConfig 查找 MySQL 配置文件
func (h *AppHandler) findMySQLConfig(proc map[string]string) string {
	cmdline := proc["cmdline"]
	configPaths := []string{"/etc/my.cnf", "/etc/mysql/my.cnf", "/usr/local/mysql/etc/my.cnf"}

	// 从命令行提取配置文件路径
	if idx := strings.Index(cmdline, "--defaults-file="); idx != -1 {
		path := strings.Fields(cmdline[idx+len("--defaults-file="):])[0]
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// 检查常见路径
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// findPostgreSQLConfig 查找 PostgreSQL 配置文件
func (h *AppHandler) findPostgreSQLConfig(proc map[string]string) string {
	configPaths := []string{"/etc/postgresql/", "/var/lib/pgsql/data/postgresql.conf"}
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// findRedisConfig 查找 Redis 配置文件
func (h *AppHandler) findRedisConfig(proc map[string]string) string {
	cmdline := proc["cmdline"]
	configPaths := []string{"/etc/redis/redis.conf", "/usr/local/etc/redis.conf"}

	if idx := strings.Index(cmdline, "--config"); idx != -1 {
		path := strings.Fields(cmdline[idx+len("--config"):])[0]
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// findMongoDBConfig 查找 MongoDB 配置文件
func (h *AppHandler) findMongoDBConfig(proc map[string]string) string {
	configPaths := []string{"/etc/mongod.conf", "/usr/local/etc/mongod.conf"}
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// findNginxConfig 查找 Nginx 配置文件
func (h *AppHandler) findNginxConfig(proc map[string]string) string {
	configPaths := []string{"/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf"}
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// findApacheConfig 查找 Apache 配置文件
func (h *AppHandler) findApacheConfig(proc map[string]string) string {
	configPaths := []string{"/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf"}
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
