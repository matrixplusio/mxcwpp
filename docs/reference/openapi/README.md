# mxcwpp OpenAPI 3.0 Schema

OpenAPI 3.0 schema + 客户 SDK.

> **覆盖范围**：`openapi.yaml` 目前只收录了部分端点（约 70 个路径），Manager 实际提供的路由有约 500 条。
> 完整列表以 [API 参考](../api-reference.md) 为准——每个路由都必须登记在那里，有门禁检查；
> 这份 OpenAPI 定义没有门禁，用它生成的 SDK 只覆盖已收录的端点。

## 文件

| 文件 | 用途 |
|---|---|
| `openapi.yaml` | v1 + v2 API 定义（部分端点，见上方覆盖范围） |
| `README.md` | 本文档 |

## 生成 SDK

```sh
# Python SDK
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/docs/reference/openapi/openapi.yaml \
  -g python \
  -o /local/sdk/python \
  --additional-properties=packageName=mxcwpp_sdk,packageVersion=2.0.0

# Go SDK
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/docs/reference/openapi/openapi.yaml \
  -g go \
  -o /local/sdk/go \
  --additional-properties=packageName=mxcwpp

# TypeScript SDK
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/docs/reference/openapi/openapi.yaml \
  -g typescript-axios \
  -o /local/sdk/typescript

# Java SDK
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/docs/reference/openapi/openapi.yaml \
  -g java \
  -o /local/sdk/java \
  --additional-properties=groupId=io.mxcwpp,artifactId=mxcwpp-sdk,artifactVersion=2.0.0
```

## Swagger UI 部署

```sh
docker run -p 8088:8080 \
  -e SWAGGER_JSON=/api/openapi.yaml \
  -v ${PWD}/docs/openapi:/api \
  swaggerapi/swagger-ui

# 访问 http://localhost:8088
```

## 已收录端点

- auth: /api/v1/auth/login
- hosts: GET /api/v1/hosts, GET /api/v1/hosts/{host_id}
- alerts: GET /api/v1/alerts
- vulnerabilities: GET /api/v1/vulnerabilities
- mode: GET /api/v2/system/mode, POST /api/v2/admin/tenants/{id}/mode
- config-changes: POST/GET /api/v2/config/change-requests
                   POST /api/v2/config/change-requests/{id}/approve|reject
- quarantine: GET /api/v1/quarantine
              POST /api/v1/quarantine/{qid}/restore

## 后续 PR

- 补全所有端点 (~200 个端点全覆盖)
- 自动生成测试 (Schemathesis / Dredd)
- CI 校验 schema 不变更 / 不破坏向后兼容
- 客户使用文档 + 多语言 SDK 发布
- API 版本治理 (Deprecation 头)
