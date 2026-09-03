package io.mxcwpp.rasp;

import java.util.Map;

/**
 * RASP 事件 (P4-1).
 *
 * 与 Server engine.rasp.Event 字段对齐 (DataType 4000-4099).
 */
public class RaspEvent {
    public String kind;        // java.runtime_exec / java.process_builder / java.deserialize / ...
    public String className;
    public String methodName;
    public String[] arguments;
    public String[] stackTrace;
    public String httpMethod;
    public String httpURL;
    public String httpRemoteIp;
    public long pid;
    public String tenantId;
    public long timestamp;
    public Map<String, String> metadata;
    public String mode = "observe"; // 永远 observe (硬约束)

    public RaspEvent(String kind, String className, String methodName) {
        this.kind = kind;
        this.className = className;
        this.methodName = methodName;
        this.timestamp = System.currentTimeMillis();
        this.pid = ProcessHandle.current().pid();
    }

    /**
     * 极简 JSON 序列化 (不引第三方依赖).
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder(512);
        sb.append("{");
        appendField(sb, "kind", kind, true);
        appendField(sb, "class_name", className, false);
        appendField(sb, "method_name", methodName, false);
        if (arguments != null) appendArray(sb, "arguments", arguments);
        if (stackTrace != null) appendArray(sb, "stack_trace", stackTrace);
        if (httpMethod != null) appendField(sb, "http_method", httpMethod, false);
        if (httpURL != null) appendField(sb, "http_url", httpURL, false);
        if (httpRemoteIp != null) appendField(sb, "http_remote_ip", httpRemoteIp, false);
        sb.append(",\"pid\":").append(pid);
        sb.append(",\"timestamp\":").append(timestamp);
        if (tenantId != null) appendField(sb, "tenant_id", tenantId, false);
        appendField(sb, "mode", mode, false);
        sb.append("}");
        return sb.toString();
    }

    private static void appendField(StringBuilder sb, String k, String v, boolean first) {
        if (v == null) return;
        if (!first) sb.append(",");
        sb.append("\"").append(k).append("\":\"").append(escape(v)).append("\"");
    }

    private static void appendArray(StringBuilder sb, String k, String[] arr) {
        sb.append(",\"").append(k).append("\":[");
        for (int i = 0; i < arr.length; i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(escape(arr[i])).append("\"");
        }
        sb.append("]");
    }

    private static String escape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }
}
