package alertbus

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

// Egress 是把告警送往客户自有 SIEM 的出口。
//
// 与通知渠道分开是本质区别，不是实现细节：
//   - 通知是叫醒人，因此有类别灰度、等级门槛、抑制窗口；
//   - 外发是把记录交给客户的日志系统，**必须全量**。
//
// 若外发也走抑制与等级门槛，客户 SIEM 里就会出现平台单方面决定的缺口，
// 而他们无从知道少了什么——那正是本项目一直在治的静默丢数据。
type Egress interface {
	// Forward 投递一条告警。实现必须非阻塞。
	Forward(e Event)
}

var (
	// egressTotal 按去向计量外发。
	egressTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mxcwpp_alert_egress_total",
		Help: "Alerts handed to the external SIEM egress, by source and outcome",
	}, []string{"source", "outcome"})
)

// IncEgress 记录一次外发去向。
func IncEgress(source, outcome string) {
	egressTotal.WithLabelValues(source, outcome).Inc()
}

// AsyncEgress 把同步的 SIEM 发送包成有界异步队列。
//
// 底层 Forwarder.SendAlert 持锁写 socket、写超时 5 秒。直接挂在检测热路径上，
// 一个不可达的 SIEM 就能把整条流水线拖住。因此这里用有界队列 + 后台单协程：
// 队列满时丢弃并计量，**宁可外发缺条目也不拖慢检测**——但丢弃必须可见，
// 不能像原实现那样只累加一个没人看的内部计数器。
type AsyncEgress struct {
	sink   func(Event)
	queue  chan Event
	logger *zap.Logger
	done   chan struct{}
}

// NewAsyncEgress 构造异步外发。queueSize <= 0 时用 4096。
func NewAsyncEgress(logger *zap.Logger, queueSize int, sink func(Event)) *AsyncEgress {
	if logger == nil {
		logger = zap.NewNop()
	}
	if queueSize <= 0 {
		queueSize = 4096
	}
	a := &AsyncEgress{
		sink:   sink,
		queue:  make(chan Event, queueSize),
		logger: logger,
		done:   make(chan struct{}),
	}
	go a.run()
	return a
}

func (a *AsyncEgress) run() {
	defer close(a.done)
	for e := range a.queue {
		a.sink(e)
		IncEgress(e.Source, "forwarded")
	}
}

// Forward 入队，队列满则丢弃并计量。
func (a *AsyncEgress) Forward(e Event) {
	select {
	case a.queue <- e:
	default:
		IncEgress(e.Source, "dropped_queue_full")
		a.logger.Warn("SIEM 外发队列已满，本条告警未送出（客户 SIEM 将缺少该记录）",
			zap.String("source", e.Source),
			zap.String("title", e.Title))
	}
}

// Close 停止接收并等待队列排空。
func (a *AsyncEgress) Close() {
	close(a.queue)
	<-a.done
}
