package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolationGoesThroughApproval 隔离接口不得绕过审批直接下发命令。
//
// 隔离会切断业务流量。原实现是一次调用即刻生效——没有第二个人看过，事后也回答不了
// "这台机器当时为什么被隔离、谁批的"。闸门建好了但接口仍能直接执行的话，等于没建。
//
// 用源码断言：这里要守的是"执行路径唯一"，而不是某次调用的返回值。
func TestIsolationGoesThroughApproval(t *testing.T) {
	src := readSource(t, "host_isolation.go")

	// 提申请，而不是直接执行。
	if !strings.Contains(src, "requestHostResponse") {
		t.Error("隔离接口未走处置申请，可能绕过了审批")
	}
	// 命令下发必须只存在于 executor 里。
	for _, forbidden := range []string{"SendCommand", "grpcProto.Command"} {
		if strings.Contains(src, forbidden) {
			t.Errorf("隔离接口仍直接下发命令（出现 %q）；执行应收敛到 executor，"+
				"否则未审批也能生效", forbidden)
		}
	}
	// 申请必须写明理由：没有理由的处置事后无从追溯。
	if !strings.Contains(src, "隔离申请必须写明理由") {
		t.Error("隔离申请未强制要求理由")
	}
}

// TestExecutorFailsWithoutDispatcher dispatcher 缺失必须报错而非静默成功。
//
// 原实现打一条 warn 后 return nil，于是"隔离命令未下发"被当作隔离成功——
// 界面显示主机已隔离，实际流量照通。
func TestExecutorFailsWithoutDispatcher(t *testing.T) {
	src := readSource(t, "response_executor.go")
	if !strings.Contains(src, "AC dispatcher 未初始化，处置命令无法下发") {
		t.Error("dispatcher 缺失时未报错，隔离会静默失败并显示为成功")
	}
	if strings.Contains(src, "h.logger.Warn(\"隔离命令未下发") {
		t.Error("仍存在把未下发当作成功的旧路径")
	}
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(".", name))
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", name, err)
	}
	return string(data)
}
