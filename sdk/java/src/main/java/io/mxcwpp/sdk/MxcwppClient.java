package io.mxcwpp.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * mxcwpp API Java SDK (P4-5).
 *
 * 用法:
 *
 *   MxcwppClient cli = MxcwppClient.builder()
 *       .baseUrl("https://mxcwpp.example.com")
 *       .token("eyJhbGc...")
 *       .build();
 *   String hostsJson = cli.listHosts("online");
 *   cli.setMode("t-default", "protect", "incident-2026-06-07");
 *
 * 不引第三方 JSON 库, 调用方自行解析 (推荐 Jackson / Gson).
 */
public class MxcwppClient {

    private final String baseUrl;
    private final String token;
    private final HttpClient http;
    private final String userAgent;

    private MxcwppClient(Builder b) {
        this.baseUrl = b.baseUrl.replaceAll("/+$", "");
        this.token = b.token;
        this.userAgent = b.userAgent;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .version(HttpClient.Version.HTTP_2)
            .build();
    }

    /** 主机列表. */
    public String listHosts(String status) throws IOException, InterruptedException {
        String url = baseUrl + "/api/v1/hosts";
        if (status != null && !status.isEmpty()) {
            url += "?status=" + status;
        }
        return doRequest("GET", url, null);
    }

    /** 主机详情. */
    public String getHost(String hostId) throws IOException, InterruptedException {
        return doRequest("GET", baseUrl + "/api/v1/hosts/" + hostId, null);
    }

    /** 告警列表. */
    public String listAlerts(String severity, String status) throws IOException, InterruptedException {
        StringBuilder url = new StringBuilder(baseUrl + "/api/v1/alerts");
        boolean hasParam = false;
        if (severity != null && !severity.isEmpty()) {
            url.append("?severity=").append(severity);
            hasParam = true;
        }
        if (status != null && !status.isEmpty()) {
            url.append(hasParam ? "&" : "?").append("status=").append(status);
        }
        return doRequest("GET", url.toString(), null);
    }

    /** 切换运行模式. */
    public String setMode(String tenantId, String mode, String reason) throws IOException, InterruptedException {
        if (!"observe".equals(mode) && !"protect".equals(mode)) {
            throw new IllegalArgumentException("mode must be observe or protect");
        }
        String body = String.format(
            "{\"mode\":\"%s\",\"reason\":\"%s\"}",
            mode, escapeJson(reason));
        return doRequest("POST",
            baseUrl + "/api/v2/admin/tenants/" + tenantId + "/mode", body);
    }

    /** 提交配置变更. */
    public String submitConfigChange(String targetTable, String targetKey,
                                     String proposedValue, String reason)
            throws IOException, InterruptedException {
        if (reason == null || reason.length() < 10) {
            throw new IllegalArgumentException("reason must be >= 10 chars");
        }
        String body = String.format(
            "{\"target_table\":\"%s\",\"target_key\":\"%s\","
            + "\"proposed_value\":\"%s\",\"reason\":\"%s\"}",
            targetTable, targetKey, escapeJson(proposedValue), escapeJson(reason));
        return doRequest("POST", baseUrl + "/api/v2/config/change-requests", body);
    }

    private String doRequest(String method, String url, String body)
            throws IOException, InterruptedException {
        HttpRequest.Builder rb = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(30))
            .header("Accept", "application/json")
            .header("User-Agent", userAgent);
        if (token != null && !token.isEmpty()) {
            rb.header("Authorization", "Bearer " + token);
        }
        if (body != null) {
            rb.header("Content-Type", "application/json");
            rb.method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        } else {
            rb.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> resp = http.send(rb.build(), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() >= 400) {
            throw new IOException("mxcwpp " + method + " " + resp.statusCode()
                + ": " + resp.body());
        }
        return resp.body();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.toString();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Builder. */
    public static class Builder {
        private String baseUrl;
        private String token;
        private String userAgent = "mxcwpp-java-sdk/0.1.0";

        public Builder baseUrl(String s) { this.baseUrl = s; return this; }
        public Builder token(String t) { this.token = t; return this; }
        public Builder userAgent(String ua) { this.userAgent = ua; return this; }

        public MxcwppClient build() {
            if (baseUrl == null || baseUrl.isEmpty()) {
                throw new IllegalArgumentException("baseUrl required");
            }
            return new MxcwppClient(this);
        }
    }
}
