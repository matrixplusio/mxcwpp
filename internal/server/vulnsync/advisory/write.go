package advisory

import (
	"errors"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
)

// writeMu 串行化本包对 vulnerabilities / host_vulnerabilities / advisory_packages 的批量写与清理。
//
// 这些写入来自多条路径：Kafka 通告消费（按分区并发 flush）、OSV 扫描、FP 清理。它们并发时
// 以不同顺序锁同一批行，会出现长事务、锁等待超时与死锁，导致整批回滚。通告入库是
// 后台同步，串行的吞吐完全够用。
//
// 范围有限，冲突仍会发生、要靠重试兜：预检巡检、修复回写、控制台的处置接口等也写
// host_vulnerabilities，它们不经过这把锁；它也只在单个 manager 进程内有效，多副本时要换成
// 数据库层面的互斥。
var writeMu sync.Mutex

// writeRetries 单批写遇到可重试错误时最多重试的次数。
const writeRetries = 3

// writeRetryBase 重试退避的起点，按次翻倍。
var writeRetryBase = time.Second

// dataErrorCodes 能确定是「这行数据本身有问题」的 MySQL 错误码：重试多少次结果都一样。
//
// 判定方向是故意反过来的：只有列在这里的才算不可重试，其余一律重试。反过来列「可重试」的
// 话，数据库重启、连接被拒、连接数满、只读切换这些故障会漏判成数据问题，整批被当成坏数据
// 跳过、offset 照常提交——恰好在最需要保住数据的时候把积压一次性丢掉。
var dataErrorCodes = map[uint16]bool{
	1048: true,             // 列不能为 NULL
	1062: true,             // 唯一键冲突（upsert 不应出现，出现即数据或语句问题）
	1264: true,             // 数值越界
	1265: true,             // 数据被截断
	1292: true,             // 日期时间等取值非法
	1366: true,             // 字符串取值非法（编码/类型）
	1406: true,             // 字段过长
	1451: true, 1452: true, // 外键约束
	3140: true, // JSON 非法
}

// IsRetryableDBError 判断写失败是否值得重试。除明确的数据错误外都算可重试：
// 锁等待超时、死锁、连接失效、连接被拒、服务器关闭、超时等。
func IsRetryableDBError(err error) bool {
	if err == nil {
		return false
	}
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		return !dataErrorCodes[me.Number]
	}
	return true
}

// withRetry 执行一次写，遇可重试错误按指数退避重试。
func withRetry(op func() error) error {
	err := op()
	for i := 0; i < writeRetries && IsRetryableDBError(err); i++ {
		time.Sleep(writeRetryBase << i)
		err = op()
	}
	return err
}

// IngestResult 一次入库的结果。
//
// Skipped 是因不可重试错误被跳过的行（真正丢了的数据，调用方计量告警）；可重试错误
// 用尽重试后由返回的 error 表达，调用方据此不提交 offset、整批重做——写入都是幂等的
// upsert，重做不会产生重复。
type IngestResult struct {
	Vulns     int
	HostVulns int
	APRows    int
	Skipped   int
}

// OnSkipped 有行因数据错误被跳过时调用（由 manager 接到指标上）。为 nil 时不计。
var OnSkipped func(n int)

func reportSkipped(n int) {
	if n > 0 && OnSkipped != nil {
		OnSkipped(n)
	}
}

// firstRetryable 保留第一个可重试错误。
func firstRetryable(cur, err error) error {
	if cur == nil && IsRetryableDBError(err) {
		return err
	}
	return cur
}
