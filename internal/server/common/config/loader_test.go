package config

import "testing"

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
