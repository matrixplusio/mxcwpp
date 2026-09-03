package metrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// unroutedDataTypeTotal 统计投递时未显式登记路由、走了心跳兜底的记录数。
//
// 兜底意味着消息进了心跳 Topic 而心跳消费者不认识它——数据静默消失且没有错误。
// 本项目已因此丢过一次数据（9200 路由缺口）。任何非零值都表示存在接线缺口：
// 要么补 RouteDataType，要么补 Consumer 的 handleMessage。
var unroutedDataTypeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "mxcwpp_ac_unrouted_datatype_total",
	Help: "Records published to the fallback topic because their DataType has no explicit route",
}, []string{"data_type"})

// IncUnroutedDataType 记录一条走了兜底路由的记录。
func IncUnroutedDataType(dataType int32) {
	unroutedDataTypeTotal.WithLabelValues(strconv.Itoa(int(dataType))).Inc()
}
