# mxsec OpenAPI 3.0 Schema

ref/09 模块 9 M2-P2-1: OpenAPI 3.0 schema + 客户 SDK.

## 文件

| 文件 | 用途 |
|---|---|
| `openapi.yaml` | 完整 v1 + v2 API 定义 (P2-10 起步, ~15 端点) |
| `README.md` | 本文档 |

## 生成 SDK

```sh
# Python SDK
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/docs/openapi/openapi.yaml \
  -g python \
  -o /local/sdk/python \
  --additional-properties=packageName=mxsec_sdk,packageVersion=2.0.0

# Go SDK
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/docs/openapi/openapi.yaml \
  -g go \
  -o /local/sdk/go \
  --additional-properties=packageName=mxsec

# TypeScript SDK
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/docs/openapi/openapi.yaml \
  -g typescript-axios \
  -o /local/sdk/typescript

# Java SDK
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/docs/openapi/openapi.yaml \
  -g java \
  -o /local/sdk/java \
  --additional-properties=groupId=io.mxsec,artifactId=mxsec-sdk,artifactVersion=2.0.0
```

## Swagger UI 部署

```sh
docker run -p 8088:8080 \
  -e SWAGGER_JSON=/api/openapi.yaml \
  -v ${PWD}/docs/openapi:/api \
  swaggerapi/swagger-ui

# 访问 http://localhost:8088
```

## 已收录端点 (P2-10 首批)

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
