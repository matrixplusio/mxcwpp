package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// verifyBackupBody 抽取 deploy.sh 的 verify_backup 并对各类文件实跑。
const verifyBackupBody = `set -uo pipefail
eval "$(sed -n '/^BACKUP_MIN_BYTES=/p; /^verify_backup() {/,/^}/p' "$SCRIPT")"
log_error(){ :; }
verify_backup "$TARGET"`

func runVerify(t *testing.T, script, target string) bool {
	t.Helper()
	cmd := exec.Command("bash", "-c", verifyBackupBody)
	cmd.Env = append(os.Environ(), "SCRIPT="+script, "TARGET="+target)
	return cmd.Run() == nil
}

// TestVerifyBackup_RejectsTruncatedDump 备份校验必须挡住"看起来存在但没内容"的文件。
//
// 原实现是 `mysqldump | gzip > file`，未开 pipefail：dump 失败时 gzip 依然成功，
// 管道整体返回 0，于是留下一个 20 字节的文件并打印"备份完成"，升级照常继续。
// 能骗人的备份比没有备份更危险——运维以为有退路，实际没有。
func TestVerifyBackup_RejectsTruncatedDump(t *testing.T) {
	script := deployScriptPath(t)
	if _, err := exec.LookPath("gzip"); err != nil {
		t.Skip("gzip 不可用，跳过")
	}
	dir := t.TempDir()

	// 空 dump 压缩后的产物：正是 pipefail 缺失时留下的那种文件。
	empty := filepath.Join(dir, "empty.sql.gz")
	if err := exec.Command("bash", "-c", "printf '' | gzip > "+empty).Run(); err != nil {
		t.Fatal(err)
	}
	if runVerify(t, script, empty) {
		t.Error("空备份应被判为无效")
	}

	// 内容被截断（非法 gzip）。
	broken := filepath.Join(dir, "broken.sql.gz")
	if err := os.WriteFile(broken, []byte(strings.Repeat("x", 4096)), 0o644); err != nil {
		t.Fatal(err)
	}
	if runVerify(t, script, broken) {
		t.Error("gzip 损坏的备份应被判为无效")
	}

	// 不存在的文件。
	if runVerify(t, script, filepath.Join(dir, "nope.sql.gz")) {
		t.Error("不存在的备份应被判为无效")
	}
}

// TestVerifyBackup_RejectsNonDumpContent 内容合法但不是数据库转储的文件必须被拒。
// 只查"文件够大"会放过日志、配置等误传进来的文件。
func TestVerifyBackup_RejectsNonDumpContent(t *testing.T) {
	script := deployScriptPath(t)
	dir := t.TempDir()
	notDump := filepath.Join(dir, "notdump.sql.gz")
	// 足够大且 gzip 合法，但没有任何建表语句。
	body := strings.Repeat("2026-07-31 some application log line\n", 200)
	if err := exec.Command("bash", "-c",
		"printf '%s' "+shellQuote(body)+" | gzip > "+notDump).Run(); err != nil {
		t.Fatal(err)
	}
	if runVerify(t, script, notDump) {
		t.Error("不含建表语句的文件不应被当作有效备份")
	}
}

// TestVerifyBackup_AcceptsRealDump 合法转储必须通过，否则校验会挡住正常升级。
func TestVerifyBackup_AcceptsRealDump(t *testing.T) {
	script := deployScriptPath(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.sql.gz")
	dump := "-- MySQL dump\n" +
		strings.Repeat("-- padding comment line to exceed the size floor\n", 40) +
		"CREATE TABLE `alerts` (`id` int NOT NULL);\n" +
		"INSERT INTO `alerts` VALUES (1);\n"
	if err := exec.Command("bash", "-c",
		"printf '%s' "+shellQuote(dump)+" | gzip > "+good).Run(); err != nil {
		t.Fatal(err)
	}
	if !runVerify(t, script, good) {
		t.Error("合法数据库转储应通过校验")
	}
}

// TestUpgradeHasRollbackPath 升级必须留下回滚点并在失败时说明如何回退。
//
// 原实现 sleep 10 后无条件打印"升级完成"，且没有任何回滚手段：
// 新版本起不来时，运维既不知道失败了，也没有退路。
func TestUpgradeHasRollbackPath(t *testing.T) {
	data, err := os.ReadFile(deployScriptPath(t))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)

	for _, must := range []string{
		"persist_env_kv PREV_VERSION", // 记录回滚点
		"persist_env_kv PREV_BACKUP",  // 记录对应备份
		"wait_healthy",                // 真的验证健康
		"./deploy.sh rollback",        // 失败时给出退路
	} {
		if !strings.Contains(script, must) {
			t.Errorf("升级流程缺少 %q", must)
		}
	}
	// 备份失败必须中止升级：没有退路就不该往前走。
	if !strings.Contains(script, "备份失败，升级中止") {
		t.Error("备份失败时未中止升级")
	}
	// 回滚不得默认还原数据库——升级后写入的数据会被抹掉。
	if !strings.Contains(script, "本次回滚**不会**还原数据库") {
		t.Error("回滚未声明其数据库语义")
	}
}

// shellQuote 单引号包裹，供 bash -c 内嵌字面量。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
