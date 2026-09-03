package anomaly

import (
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// Mode 是 ML 异常检测器的行为安全模式（M0 线上止血）。
//
// 设计原则：默认必须安全，禁止当前不成熟的 ML 信号进入自动响应或被当作正式高危定罪，
// 更禁止"缺配置就默认写正式告警"。旧配置缺失 / 非法值一律回落 ModeShadow（只日志+指标、不落库），
// 绝不回落 ModeContext / ModeAlert。
type Mode string

const (
	// ModeOff 完全关闭：不消费、不打分、不产出任何信号。
	ModeOff Mode = "off"
	// ModeShadow 影子模式（安全默认）：照常打分与关联检测，但只写可观测日志/指标，不落库 anomaly_alerts。
	// 缺配置 / 非法值一律回落到此，保证"缺配置绝不默认写正式告警"，同时保留观测能力。
	ModeShadow Mode = "shadow"
	// ModeContext 上下文模式：落库 anomaly_alerts 供 SOC 分析上下文，
	// 但严重度封顶 high（绝不 critical）、绝不进入自动响应。需显式配置才启用。
	ModeContext Mode = "context"
	// ModeRanking 排序模式：在 context 的基础上，额外让异常分参与**已有告警的排序**。
	//
	// 它不新建任何告警——只影响已因其他原因存在的告警的 risk_score，让分析师先看到
	// 异常主机上的告警。这是 1.0 允许 ML 产生价值的唯一方式：**排序，不定罪**。
	// 严重度与 context 一样封顶 high。
	ModeRanking Mode = "ranking"
	// ModeAlert 正式告警模式：允许 critical 定罪。仅在显式配置 + schema gate 通过时生效，
	// schema 未就绪时由 EffectiveMode fail-closed 降级为 ModeShadow（只观测不落库，不是 context）。M0 默认不启用。
	//
	// 1.0 不开放：升档校验（mlquality.EvaluateModeChange）对该档硬拒。
	ModeAlert Mode = "alert"
)

// normalizeMode 把外部字符串规整为合法 Mode；未知/空值回落 ModeShadow（安全默认：只观测不落库）。
func normalizeMode(s string) Mode {
	switch Mode(s) {
	case ModeOff, ModeShadow, ModeContext, ModeRanking, ModeAlert:
		return Mode(s)
	default:
		return ModeShadow
	}
}

// LoadMode 从 feature_flags 读取 anomaly.detector_mode。
// 查不到 / 非法一律回落 ModeShadow（缺配置绝不默认写正式告警；对齐 readDataSourceFlag 的安全回落精神）。
func LoadMode(db *gorm.DB, logger *zap.Logger) Mode {
	if db == nil {
		return ModeShadow
	}
	var f model.FeatureFlag
	if err := db.Where("flag_key = ?", model.FlagAnomalyDetectorMode).First(&f).Error; err != nil {
		logger.Warn("anomaly detector mode flag 查询失败，回落 shadow 安全默认", zap.Error(err))
		return ModeShadow
	}
	m := normalizeMode(f.Value)
	if string(m) != f.Value {
		logger.Warn("anomaly detector mode flag 值非法，回落 shadow 安全默认",
			zap.String("raw", f.Value), zap.String("effective", string(m)))
	}
	return m
}

// Status 汇报检测器运行时状态，供 /readyz 与 Prometheus 指标使用。
type Status struct {
	Mode          Mode // 配置模式
	EffectiveMode Mode // 生效模式（context/alert 在 schema 未就绪时降级为 shadow）
	SchemaReady   bool // anomaly_alerts 必需列 + 去重唯一索引齐备
	DNSFieldReady bool // DNS domain/rcode 字段是否可信（M0 恒为 false）
	Trained       bool // IForest 是否已训练
	SampleCount   int  // 训练样本缓冲区大小
	HostCount     int  // 已跟踪主机数（warmup 覆盖面）
}
