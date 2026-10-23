package kafka

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// docPath 定位 docs/datatype-allocation.md（向上找 go.mod 确定仓库根）。
func docPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "docs", "datatype-allocation.md")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("未找到仓库根，跳过")
		}
		dir = parent
	}
}

var (
	rowRe   = regexp.MustCompile(`^\|\s*([0-9,\s-]+?)\s*\|\s*` + "`" + `([a-z0-9.\-]+)` + "`" + `\s*\|`)
	rangeRe = regexp.MustCompile(`^(\d+)\s*-\s*(\d+)$`)
)

// parseDocRouting 解析文档「Kafka Topic 路由映射」表，返回 DataType → Topic。
// 兜底行（**其他**）不含反引号包裹的纯 topic，天然不被 rowRe 命中。
func parseDocRouting(t *testing.T) map[int32]string {
	t.Helper()
	data, err := os.ReadFile(docPath(t))
	if err != nil {
		t.Fatalf("读取 DataType 分配表失败: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	inTable := false
	out := map[int32]string{}
	for _, line := range lines {
		if strings.HasPrefix(line, "## ") {
			inTable = strings.Contains(line, "Kafka Topic 路由映射")
			continue
		}
		if !inTable {
			continue
		}
		m := rowRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		topic := m[2]
		for _, part := range strings.Split(m[1], ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if r := rangeRe.FindStringSubmatch(part); r != nil {
				lo, _ := strconv.Atoi(r[1])
				hi, _ := strconv.Atoi(r[2])
				for dt := lo; dt <= hi; dt++ {
					out[int32(dt)] = topic
				}
				continue
			}
			n, err := strconv.Atoi(part)
			if err != nil {
				t.Fatalf("无法解析 DataType 规格 %q（行: %s）", part, line)
			}
			out[int32(n)] = topic
		}
	}
	if len(out) == 0 {
		t.Fatal("未从文档解析出任何路由条目——表格结构可能已变，测试失效")
	}
	return out
}

// TestRouteDataTypeMatchesDoc 文档与路由函数必须双向一致。
//
// 单向检查不够：漏在文档里，下一个人分配 DataType 时会撞段；漏在代码里，消息走兜底进
// 心跳 Topic 被消费者静默忽略，数据没了却没有错误。本项目已因后者丢过一次数据
// （9200 路由缺口），文档自己也把它记为"兜底陷阱"。
func TestRouteDataTypeMatchesDoc(t *testing.T) {
	doc := parseDocRouting(t)

	// 方向一：文档声明的每个 DataType，代码必须显式路由到同一 Topic。
	for dt, wantTopic := range doc {
		gotTopic, routed := RouteDataTypeChecked(dt, "")
		if !routed {
			t.Errorf("DataType %d 文档声明路由到 %s，代码却走了兜底（消息会被静默忽略）", dt, wantTopic)
			continue
		}
		if gotTopic != wantTopic {
			t.Errorf("DataType %d 路由不一致：代码 %s，文档 %s", dt, gotTopic, wantTopic)
		}
	}

	// 方向二：代码显式路由的每个 DataType，文档必须登记。
	// 未登记的段会让下一个分配 DataType 的人撞车，而分配表正是本项目要求的唯一权威来源。
	var undocumented []int32
	for dt := int32(0); dt <= 20000; dt++ {
		if _, routed := RouteDataTypeChecked(dt, ""); !routed {
			continue
		}
		if _, ok := doc[dt]; !ok {
			undocumented = append(undocumented, dt)
		}
	}
	if len(undocumented) > 0 {
		t.Errorf("代码显式路由但 docs/datatype-allocation.md 未登记的 DataType 共 %d 个，起止：%d..%d",
			len(undocumented), undocumented[0], undocumented[len(undocumented)-1])
	}
}

// TestRouteDataTypeChecked_FallbackIsExplicit 兜底必须是可判定状态。
//
// 兜底本身不能去掉（去掉即直接丢弃），但调用方必须能区分"显式登记"与"走了兜底"，
// 否则接线缺口只能等到有人发现数据缺失才暴露。
func TestRouteDataTypeChecked_FallbackIsExplicit(t *testing.T) {
	// 文档明确声明不走 Kafka 的类型（AC→Agent 直发 / AC 直处理）必须是未路由状态。
	for _, dt := range []int32{6004, 9300, 9400, 9900, 9997, 9998} {
		if _, routed := RouteDataTypeChecked(dt, ""); routed {
			t.Errorf("DataType %d 文档声明不走 Kafka，却被显式路由——两者必须同步", dt)
		}
	}
	// 未分配段走兜底，且兜底 topic 仍是心跳（不改变既有投递行为，只让状态可判定）。
	topic, routed := RouteDataTypeChecked(19999, "")
	if routed {
		t.Error("未分配 DataType 应报告为未路由")
	}
	if topic != TopicHeartbeat {
		t.Errorf("兜底 topic = %s，want %s（兜底行为不应改变）", topic, TopicHeartbeat)
	}
	// 前缀必须同样作用于兜底路径。
	if topic, _ := RouteDataTypeChecked(19999, "pfx."); topic != "pfx."+TopicHeartbeat {
		t.Errorf("兜底路径未应用 topic 前缀: %s", topic)
	}
}
