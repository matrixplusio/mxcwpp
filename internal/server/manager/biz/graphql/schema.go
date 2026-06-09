// Package graphql 给 mxsec API 暴露 GraphQL 入口 (P4-7).
//
// 为避免引入重型依赖 (graphql-go/graphql 自带 parser + executor 数千行),
// 当前实现走 "命名查询白名单" 模式:
//   - 客户端 POST /api/v2/graphql {"operation":"hosts","variables":{...}}
//   - 服务端按 operation 名找 resolver, 用 variables 调它, 返回结果
//   - 不解析任意 GraphQL DSL, 不支持 fragment/subscription
//
// 后续可平滑迁移到 graphql-go/graphql, 接口保持稳定.
package graphql

import (
	"context"
	"errors"
	"sync"
)

// Request 客户端入参.
type Request struct {
	Operation string         `json:"operation"`
	Variables map[string]any `json:"variables,omitempty"`
	TenantID  string         `json:"-"`
}

// Response GraphQL 风格响应.
type Response struct {
	Data   any      `json:"data,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

// Resolver 单个 operation 的执行函数.
type Resolver func(ctx context.Context, req *Request) (any, error)

// Registry 集中注册 resolver.
type Registry struct {
	mu        sync.RWMutex
	resolvers map[string]Resolver
}

// NewRegistry 构造.
func NewRegistry() *Registry {
	return &Registry{resolvers: make(map[string]Resolver)}
}

// Register 注册 operation.
func (r *Registry) Register(name string, fn Resolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolvers[name] = fn
}

// Lookup 查 resolver.
func (r *Registry) Lookup(name string) (Resolver, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.resolvers[name]
	return fn, ok
}

// Operations 列出已注册 operation (introspection 用).
func (r *Registry) Operations() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.resolvers))
	for k := range r.resolvers {
		out = append(out, k)
	}
	return out
}

// Execute 执行一个请求.
func (r *Registry) Execute(ctx context.Context, req *Request) *Response {
	if req == nil || req.Operation == "" {
		return &Response{Errors: []string{"operation required"}}
	}
	fn, ok := r.Lookup(req.Operation)
	if !ok {
		return &Response{Errors: []string{"unknown operation: " + req.Operation}}
	}
	data, err := fn(ctx, req)
	if err != nil {
		return &Response{Errors: []string{err.Error()}}
	}
	if data == nil {
		return &Response{Errors: []string{"resolver returned no data"}}
	}
	return &Response{Data: data}
}

// ErrUnauthorized 缺租户上下文.
var ErrUnauthorized = errors.New("graphql: tenant context missing")

// VarString 从 Variables 取 string 字段.
func VarString(req *Request, key string) string {
	if req == nil || req.Variables == nil {
		return ""
	}
	if v, ok := req.Variables[key].(string); ok {
		return v
	}
	return ""
}

// VarInt 从 Variables 取 int (容忍 float64, 因 JSON 数字默认 float64).
func VarInt(req *Request, key string, def int) int {
	if req == nil || req.Variables == nil {
		return def
	}
	switch v := req.Variables[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return def
}
