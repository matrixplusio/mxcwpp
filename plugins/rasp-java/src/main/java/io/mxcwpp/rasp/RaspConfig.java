package io.mxcwpp.rasp;

/**
 * RASP 配置 (P4-1).
 *
 * 来源:
 *   1. -Dmxcwpp.rasp.xxx=yyy JVM 参数
 *   2. agentArgs 形如 "uds=/path/to.sock,tenant=t-default"
 *   3. 默认值
 */
public class RaspConfig {
    private String udsPath = "/var/run/mxcwpp-rasp.sock";
    private String tenantId = "t-default";
    private boolean enabled = true;
    private boolean retransformAtStartup = true;
    private int maxEventsPerSecond = 5000;
    private int queueCapacity = 10000;
    private boolean attachMode;

    public static RaspConfig fromSystemProperties(String agentArgs) {
        RaspConfig c = new RaspConfig();

        // agentArgs key=val,key=val
        if (agentArgs != null && !agentArgs.isEmpty()) {
            for (String kv : agentArgs.split(",")) {
                String[] parts = kv.split("=", 2);
                if (parts.length != 2) continue;
                applyKV(c, parts[0].trim(), parts[1].trim());
            }
        }

        // System properties override
        applyKV(c, "uds", System.getProperty("mxcwpp.rasp.uds"));
        applyKV(c, "tenant", System.getProperty("mxcwpp.rasp.tenant"));
        applyKV(c, "enabled", System.getProperty("mxcwpp.rasp.enabled"));
        applyKV(c, "rps", System.getProperty("mxcwpp.rasp.rps"));

        return c;
    }

    private static void applyKV(RaspConfig c, String k, String v) {
        if (v == null || v.isEmpty()) return;
        switch (k) {
            case "uds":
                c.udsPath = v;
                break;
            case "tenant":
                c.tenantId = v;
                break;
            case "enabled":
                c.enabled = "true".equalsIgnoreCase(v) || "1".equals(v);
                break;
            case "rps":
                try { c.maxEventsPerSecond = Integer.parseInt(v); } catch (Exception ignored) {}
                break;
            case "retransform":
                c.retransformAtStartup = "true".equalsIgnoreCase(v);
                break;
        }
    }

    public String getUdsPath() { return udsPath; }
    public String getTenantId() { return tenantId; }
    public boolean isEnabled() { return enabled; }
    public boolean isRetransformAtStartup() { return retransformAtStartup; }
    public int getMaxEventsPerSecond() { return maxEventsPerSecond; }
    public int getQueueCapacity() { return queueCapacity; }
    public boolean isAttachMode() { return attachMode; }
    public void setAttachMode(boolean attachMode) { this.attachMode = attachMode; }
}
