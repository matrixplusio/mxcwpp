/**
 * 业务响应码库（与后端 internal/server/manager/api/respcode.go 对齐）。
 *
 * 约定：业务接口一律 HTTP 200，用 body 的 code 表达结果。
 * code=0 成功；非 0 为业务错误，前缀对齐 HTTP 语义。
 */
export const RespCode = {
  OK: 0,
  INVALID_PARAM: 40000, // 请求参数错误
  UNAUTHORIZED: 40100, // 未授权 / 认证失败（如用户名或密码错误）
  TOKEN_EXPIRED: 40101, // 登录已过期 / Token 无效（前端据此跳转登录）
  FORBIDDEN: 40300, // 无权限
  NOT_FOUND: 40400, // 资源不存在
  CONFLICT: 40900, // 资源冲突
  RATE_LIMITED: 42900, // 请求过于频繁
  INTERNAL: 50000, // 服务器内部错误
  UNAVAILABLE: 50300, // 服务不可用
} as const
