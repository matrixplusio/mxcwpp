package intrusion

import (
	"os"
	"testing"
	"time"
)

// 暴力破解检测在生产上按服务端收到事件的时间计算。测试要在一瞬间走完几分钟的窗口，
// 所以把时钟换成读事件自带的时间；需要验证生产行为的测试自己再换回去。
func TestMain(m *testing.M) {
	bruteClock = func(att LoginAttempt) time.Time {
		if att.Timestamp.IsZero() {
			return time.Now()
		}
		return att.Timestamp
	}
	os.Exit(m.Run())
}
