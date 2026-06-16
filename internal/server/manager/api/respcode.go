package api

// 统一业务响应码库（HTTP 状态码扩展为 5 位）。
//
// 约定：
//   - HTTP 层一律 200（业务接口），真正的错误用 body 里的 code 表达。
//   - code=0 表示成功；非 0 为业务错误，前缀对齐 HTTP 语义便于阅读。
//   - 例外（仍返回真实 HTTP 状态码）：/health 等探针、gin panic 兜底、K8s Admission Webhook。
//
// 新增错误码时在此登记，并补 codeMessages 默认文案；前后端共同遵循此表。
const (
	CodeOK = 0

	CodeInvalidParam  = 40000 // 请求参数错误
	CodeUnauthorized  = 40100 // 未授权 / 认证失败（如用户名或密码错误）
	CodeTokenExpired  = 40101 // 登录已过期 / Token 无效（前端据此跳转登录）
	CodeForbidden     = 40300 // 无权限
	CodeNotFound      = 40400 // 资源不存在
	CodeConflict      = 40900 // 资源冲突
	CodeRateLimited   = 42900 // 请求过于频繁
	CodeInternalError = 50000 // 服务器内部错误
	CodeUnavailable   = 50300 // 服务不可用（降级）
)

// codeMessages 各业务码的默认中文文案，调用方未显式传 message 时回退使用。
var codeMessages = map[int]string{
	CodeOK:            "成功",
	CodeInvalidParam:  "请求参数错误",
	CodeUnauthorized:  "未授权",
	CodeTokenExpired:  "登录已过期，请重新登录",
	CodeForbidden:     "没有权限执行此操作",
	CodeNotFound:      "资源不存在",
	CodeConflict:      "资源冲突",
	CodeRateLimited:   "请求过于频繁，请稍后再试",
	CodeInternalError: "服务器内部错误",
	CodeUnavailable:   "服务暂不可用",
}

// codeMessage 返回业务码默认文案，未登记则返回通用提示。
func codeMessage(code int) string {
	if m, ok := codeMessages[code]; ok {
		return m
	}
	return "请求失败"
}

// msgOr 调用方传了 message 用其值，否则回退该 code 的默认文案。
func msgOr(message string, code int) string {
	if message != "" {
		return message
	}
	return codeMessage(code)
}
