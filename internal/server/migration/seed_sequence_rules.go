package migration

import (
	"errors"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/matrixplusio/mxcwpp/internal/server/model"
)

// seedBuiltinSequenceRules 种入内置多步攻击链(序列)规则。
//
// 背景:序列引擎(celengine.SequenceDetector)已实现但 sequence_rules 表为空 → 攻击链检测空转。
// 单事件规则各自"看起来正常",串成链才是攻击(CrowdStrike IOA 模型)。本函数补齐首批链。
//
// 约束:步骤表达式只能用 buildActivation 暴露的变量(event_type/exe/cmdline/parent_exe/cwd/
// file_path/remote_addr/data_type 等)与 is_private_ip();不可用 ancestor_exes / DNS domain
// (序列求值的 activation 未注入它们)。引擎为 per-host 严格顺序状态机,步骤须按 order 先后命中。
//
// 幂等:按 Name 唯一存在则跳过;builtin=true 标记便于后续与用户自建区分。
func seedBuiltinSequenceRules(db *gorm.DB, logger *zap.Logger) error {
	rules := builtinSequenceRules()
	created := 0
	for i := range rules {
		r := rules[i]
		var existing model.SequenceRule
		err := db.Where("name = ?", r.Name).First(&existing).Error
		if err == nil {
			continue // 已存在,跳过(不覆盖用户可能的修改)
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err := db.Create(&r).Error; err != nil {
			logger.Warn("种入序列规则失败", zap.String("name", r.Name), zap.Error(err))
			continue
		}
		created++
	}
	if created > 0 {
		logger.Info("内置攻击链(序列)规则种入完成", zap.Int("created", created), zap.Int("total", len(rules)))
	}
	return nil
}

// step 构造一个序列步骤
func step(order int, name, expr string) model.SequenceStep {
	return model.SequenceStep{Name: name, Expression: expr, Order: order}
}

// builtinSequenceRules 首批 Linux ATT&CK 攻击链
func builtinSequenceRules() []model.SequenceRule {
	return []model.SequenceRule{
		{
			Name:        "下载-赋权-执行 攻击链",
			Description: "下载工具 → chmod 赋可执行权限 → 从临时目录执行,典型的载荷投递落地链",
			WindowSecs:  600,
			Severity:    "high",
			MitreID:     "T1105",
			Category:    "execution",
			Builtin:     true,
			Enabled:     true,
			Steps: model.SequenceSteps{
				step(0, "下载工具", `event_type == "process_exec" && (exe.endsWith("/curl") || exe.endsWith("/wget") || cmdline.contains("curl ") || cmdline.contains("wget "))`),
				step(1, "赋可执行权限", `event_type == "process_exec" && exe.endsWith("/chmod") && (cmdline.contains("+x") || cmdline.contains("777") || cmdline.contains("755"))`),
				step(2, "临时目录执行", `event_type == "process_exec" && (exe.startsWith("/tmp/") || exe.startsWith("/dev/shm/") || exe.startsWith("/var/tmp/"))`),
			},
		},
		{
			Name:        "Web服务派生Shell-侦察 攻击链",
			Description: "Web 中间件(nginx/apache/php/java)派生 shell → 执行侦察命令,典型 Webshell/RCE 利用",
			WindowSecs:  300,
			Severity:    "critical",
			MitreID:     "T1505.003",
			Category:    "initial_access",
			Builtin:     true,
			Enabled:     true,
			Steps: model.SequenceSteps{
				step(0, "Web服务派生Shell", `event_type == "process_exec" && (parent_exe.contains("nginx") || parent_exe.contains("apache") || parent_exe.contains("httpd") || parent_exe.contains("php") || parent_exe.contains("java") || parent_exe.contains("tomcat")) && (exe.endsWith("/sh") || exe.endsWith("/bash") || exe.endsWith("/dash"))`),
				step(1, "执行侦察命令", `event_type == "process_exec" && (exe.endsWith("/whoami") || exe.endsWith("/id") || exe.endsWith("/uname") || exe.endsWith("/hostname") || cmdline.contains("/etc/passwd"))`),
			},
		},
		{
			Name:        "侦察-提权 攻击链",
			Description: "执行侦察命令 → 提权尝试(sudo/su/已知提权漏洞或内核 commit_creds 异常)",
			WindowSecs:  300,
			Severity:    "high",
			MitreID:     "T1068",
			Category:    "privilege_escalation",
			Builtin:     true,
			Enabled:     true,
			Steps: model.SequenceSteps{
				step(0, "侦察", `event_type == "process_exec" && (exe.endsWith("/whoami") || exe.endsWith("/id") || exe.endsWith("/uname") || exe.endsWith("/netstat") || exe.endsWith("/ss"))`),
				step(1, "提权尝试", `data_type == 3005 || (event_type == "process_exec" && (exe.endsWith("/sudo") || exe.endsWith("/su") || cmdline.contains("pkexec") || cmdline.contains("dirtypipe") || cmdline.contains("dirtycow")))`),
			},
		},
		{
			Name:        "凭证读取-外联 攻击链",
			Description: "读取敏感凭证(shadow/ssh key/云凭证) → 对外网外联,典型凭证窃取后回传",
			WindowSecs:  300,
			Severity:    "high",
			MitreID:     "T1552",
			Category:    "credential_access",
			Builtin:     true,
			Enabled:     true,
			Steps: model.SequenceSteps{
				step(0, "读取敏感凭证", `(event_type == "file_open" || event_type == "file_write") && (file_path.contains("/etc/shadow") || file_path.contains("/.ssh/") || file_path.contains("id_rsa") || file_path.contains(".aws/credentials") || file_path.contains(".kube/config"))`),
				step(1, "外网外联", `event_type == "tcp_connect" && remote_addr != "" && !is_private_ip(remote_addr)`),
			},
		},
		{
			Name:        "可疑执行-持久化 攻击链",
			Description: "临时目录/Web 派生的可疑进程 → 写入持久化位置(cron/systemd/authorized_keys/ld.so.preload)",
			WindowSecs:  600,
			Severity:    "high",
			MitreID:     "T1543",
			Category:    "persistence",
			Builtin:     true,
			Enabled:     true,
			Steps: model.SequenceSteps{
				step(0, "可疑进程", `event_type == "process_exec" && (exe.startsWith("/tmp/") || exe.startsWith("/dev/shm/") || parent_exe.contains("nginx") || parent_exe.contains("php") || parent_exe.contains("apache"))`),
				step(1, "写入持久化位置", `(event_type == "file_write" || event_type == "file_rename") && (file_path.contains("/etc/cron") || file_path.contains("/.ssh/authorized_keys") || file_path.contains("/etc/systemd/") || file_path.contains("ld.so.preload") || file_path.contains("/etc/rc.local"))`),
			},
		},
		{
			Name:        "下载-挖矿 攻击链",
			Description: "下载工具 → 启动挖矿程序(xmrig/minerd 或 stratum 矿池连接参数)",
			WindowSecs:  600,
			Severity:    "high",
			MitreID:     "T1496",
			Category:    "cryptomining",
			Builtin:     true,
			Enabled:     true,
			Steps: model.SequenceSteps{
				step(0, "下载工具", `event_type == "process_exec" && (exe.contains("curl") || exe.contains("wget"))`),
				step(1, "启动挖矿", `event_type == "process_exec" && (exe.contains("xmrig") || exe.contains("minerd") || cmdline.contains("stratum+tcp") || cmdline.contains("--donate-level") || cmdline.contains("--cpu-priority"))`),
			},
		},
		{
			Name:        "内存执行-外联 攻击链",
			Description: "无文件内存执行(memfd/匿名 RWX) → 对外网外联,典型 fileless 载荷 + C2 回连",
			WindowSecs:  300,
			Severity:    "critical",
			MitreID:     "T1620",
			Category:    "defense_evasion",
			Builtin:     true,
			Enabled:     true,
			Steps: model.SequenceSteps{
				step(0, "内存执行", `data_type == 3004`),
				step(1, "外网外联", `event_type == "tcp_connect" && remote_addr != "" && !is_private_ip(remote_addr)`),
			},
		},
	}
}
