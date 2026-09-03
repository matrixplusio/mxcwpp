package io.mxcwpp.rasp;

import java.lang.instrument.Instrumentation;

/**
 * mxcwpp Java RASP Agent premain 入口 (P4-1).
 *
 * 启用:
 *   java -javaagent:/opt/mxcwpp/rasp/libmxcwpp_rasp.jar \
 *        -Dmxcwpp.rasp.uds=/var/run/mxcwpp-rasp.sock \
 *        -Dmxcwpp.rasp.tenant=t-default \
 *        -jar app.jar
 *
 * 严格 read-only (Sprint 4 PR63 哲学硬约束):
 *   - 仅观察 + 上报, 不抛异常 / 不修改返回值
 *   - 通过 UDS 发事件给 Agent 主进程
 *   - Agent 主进程转 DataType 4000-4099 上报 AC
 *
 * 触发器 (ClassFileTransformer):
 *   - java.lang.Runtime.exec*         T1059.007
 *   - java.lang.ProcessBuilder.start  T1059.007
 *   - javax.naming.InitialContext.lookup  T1190 (Log4Shell)
 *   - java.io.ObjectInputStream.readObject T1190 反序列化
 *   - java.lang.ClassLoader.defineClass  T1027.004 内存马
 *   - javax.servlet.Filter / Servlet 运行时注册 (Tomcat StandardContext) T1505.003
 *
 * 性能预算:
 *   单 hook 调用开销 < 50µs (95%)
 *   失败必须 silent (永不影响业务流)
 */
public class MxcwppAgent {

    /**
     * JVM 启动时调用 (premain).
     */
    public static void premain(String agentArgs, Instrumentation inst) {
        try {
            startup(agentArgs, inst, false);
        } catch (Throwable t) {
            // 永不抛, 业务零影响
            System.err.println("[mxcwpp-rasp] premain init failed: " + t.getMessage());
        }
    }

    /**
     * 运行时 attach (-Dattach 或 jcmd).
     */
    public static void agentmain(String agentArgs, Instrumentation inst) {
        try {
            startup(agentArgs, inst, true);
        } catch (Throwable t) {
            System.err.println("[mxcwpp-rasp] agentmain init failed: " + t.getMessage());
        }
    }

    private static void startup(String agentArgs, Instrumentation inst, boolean isAttach) {
        // 1. 解析配置
        RaspConfig cfg = RaspConfig.fromSystemProperties(agentArgs);
        cfg.setAttachMode(isAttach);

        // 2. 初始化事件 reporter (UDS → Agent)
        EventReporter reporter = new EventReporter(cfg.getUdsPath(), cfg.getTenantId());
        reporter.start();

        // 3. 注册全局 hook handler (Sink 调用入口)
        Hooks.install(reporter, cfg);

        // 4. 注册 ClassFileTransformer 进行字节码插桩
        SinkTransformer transformer = new SinkTransformer(cfg);
        inst.addTransformer(transformer, true);

        // 5. 已加载类回查 (premain 之后启动应用前已加载的 Sink 类)
        if (isAttach || cfg.isRetransformAtStartup()) {
            try {
                inst.retransformClasses(
                    java.lang.Runtime.class,
                    java.lang.ProcessBuilder.class,
                    java.io.ObjectInputStream.class
                );
            } catch (Throwable t) {
                // 部分 boot 类不可 retransform, 忽略
            }
        }

        System.out.println("[mxcwpp-rasp] agent started"
            + " mode=" + (isAttach ? "attach" : "premain")
            + " uds=" + cfg.getUdsPath()
            + " tenant=" + cfg.getTenantId());
    }
}
