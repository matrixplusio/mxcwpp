package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDSN_ExplicitWins(t *testing.T) {
	c := DBConfig{
		DSN:   "user:pw@tcp(h:3306)/db",
		MySQL: MySQLParams{Host: "ignored", User: "x"},
	}
	if got := c.ResolveDSN(); got != "user:pw@tcp(h:3306)/db" {
		t.Fatalf("explicit DSN must win, got %q", got)
	}
}

// TestResolveDSN_FromStructured 回归: 部署用的结构化 database.mysql.* 必须能拼出
// DSN，否则 Engine 读不到 DB → 检测 stage 全空 → noop。
func TestResolveDSN_FromStructured(t *testing.T) {
	c := DBConfig{MySQL: MySQLParams{
		Host: "10.0.0.1", Port: 3306, User: "u", Password: "p", Database: "mxcwpp",
	}}
	want := "u:p@tcp(10.0.0.1:3306)/mxcwpp?charset=utf8mb4&parseTime=true&loc=Local&allowNativePasswords=true"
	if got := c.ResolveDSN(); got != want {
		t.Fatalf("ResolveDSN()\n got=%q\nwant=%q", got, want)
	}
}

func TestResolveDSN_EmptyWhenNoInfo(t *testing.T) {
	if got := (DBConfig{}).ResolveDSN(); got != "" {
		t.Fatalf("no connection info should yield empty DSN, got %q", got)
	}
}

// TestLoadEngine_UnreadableFileIsError 指定的配置文件在但读不出（无权限）必须报错：
// 放过去进程会带着空的 broker 与 DSN 启动，看着在跑、实际什么都不做。文件不存在仍然允许（纯环境变量部署）。
func TestLoadEngine_UnreadableFileIsError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root 不受文件权限限制")
	}
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte("kafka:\n  brokers: [\"k:9092\"]\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEngine(path); err == nil {
		t.Fatal("无权限读取配置应返回错误")
	}
	if _, err := LoadEngine(filepath.Join(t.TempDir(), "absent.yaml")); err != nil {
		t.Fatalf("配置文件不存在应允许: %v", err)
	}
}
