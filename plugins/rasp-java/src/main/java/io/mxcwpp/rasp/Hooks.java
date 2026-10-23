package io.mxcwpp.rasp;

/**
 * 运行时 Hook 调用入口 (P4-1).
 *
 * 字节码插桩后生成的代码调用本类的静态方法:
 *
 *   public void exec(String cmd) {
 *     io.mxcwpp.rasp.Hooks.onRuntimeExec(cmd, this);   // 插桩
 *     return /* original *\/;
 *   }
 *
 * 设计原则:
 *   - 永远 silent (Throwable 全捕获, 不抛回业务)
 *   - 永远 fast (单 hook < 50µs P95)
 *   - read-only (绝不修改业务返回值或参数)
 */
public class Hooks {

    private static volatile EventReporter reporter;
    private static volatile RaspConfig config;
    private static volatile boolean installed;

    public static void install(EventReporter r, RaspConfig c) {
        reporter = r;
        config = c;
        installed = true;
    }

    public static boolean isInstalled() { return installed; }

    /** Runtime.exec(String...) / exec(String[]) 共用入口. */
    public static void onRuntimeExec(String cmdline) {
        if (!installed) return;
        try {
            RaspEvent ev = new RaspEvent("java.runtime_exec",
                "java.lang.Runtime", "exec");
            ev.arguments = new String[]{trunc(cmdline, 256)};
            ev.stackTrace = captureStack();
            reporter.emit(ev);
        } catch (Throwable ignored) {
            // 永不影响业务
        }
    }

    /** ProcessBuilder.start. */
    public static void onProcessBuilderStart(String[] command) {
        if (!installed) return;
        try {
            RaspEvent ev = new RaspEvent("java.process_builder",
                "java.lang.ProcessBuilder", "start");
            ev.arguments = command;
            ev.stackTrace = captureStack();
            reporter.emit(ev);
        } catch (Throwable ignored) {}
    }

    /** InitialContext.lookup (Log4Shell 入口). */
    public static void onJNDILookup(String name) {
        if (!installed) return;
        try {
            RaspEvent ev = new RaspEvent("java.jndi_lookup",
                "javax.naming.InitialContext", "lookup");
            ev.arguments = new String[]{trunc(name, 512)};
            ev.stackTrace = captureStack();
            reporter.emit(ev);
        } catch (Throwable ignored) {}
    }

    /** ObjectInputStream.readObject (反序列化 sink). */
    public static void onDeserialize(String className) {
        if (!installed) return;
        try {
            RaspEvent ev = new RaspEvent("java.deserialize",
                "java.io.ObjectInputStream", "readObject");
            ev.arguments = new String[]{className};
            ev.stackTrace = captureStack();
            reporter.emit(ev);
        } catch (Throwable ignored) {}
    }

    /** ClassLoader.defineClass (内存马动态加载). */
    public static void onDefineClass(String className, int len) {
        if (!installed) return;
        try {
            RaspEvent ev = new RaspEvent("java.define_class",
                "java.lang.ClassLoader", "defineClass");
            ev.arguments = new String[]{className, String.valueOf(len)};
            ev.stackTrace = captureStack();
            reporter.emit(ev);
        } catch (Throwable ignored) {}
    }

    /** Filter/Servlet 运行时注册 (内存马典型). */
    public static void onFilterRegistered(String filterClassName) {
        if (!installed) return;
        try {
            RaspEvent ev = new RaspEvent("java.memshell_filter",
                "javax.servlet.Filter", "register");
            ev.className = filterClassName;
            ev.stackTrace = captureStack();
            reporter.emit(ev);
        } catch (Throwable ignored) {}
    }

    /** 抓调用栈 (最多 30 帧, 跳过 RASP 自身). */
    private static String[] captureStack() {
        try {
            StackTraceElement[] full = Thread.currentThread().getStackTrace();
            int skip = 0;
            for (int i = 0; i < full.length; i++) {
                if (!full[i].getClassName().startsWith("io.mxcwpp.rasp.")
                    && !full[i].getClassName().equals("java.lang.Thread")) {
                    skip = i;
                    break;
                }
            }
            int n = Math.min(30, full.length - skip);
            String[] out = new String[n];
            for (int i = 0; i < n; i++) {
                StackTraceElement e = full[skip + i];
                out[i] = e.getClassName() + "." + e.getMethodName()
                    + "(" + e.getFileName() + ":" + e.getLineNumber() + ")";
            }
            return out;
        } catch (Throwable t) {
            return new String[0];
        }
    }

    private static String trunc(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "...";
    }

    // ===================== P6-2 ASM 字节码注入入口 =====================
    //
    // SinkTransformer 注入的 invokestatic 指令以 Object 形参调用本组重载,
    // 内部再把对象转为 String/数组等格式上报.

    public static void onRuntimeExec(Object arg) {
        if (!installed || arg == null) return;
        try {
            if (arg instanceof String) {
                onRuntimeExec((String) arg);
            } else if (arg instanceof String[]) {
                onProcessBuilderStart((String[]) arg);
            } else {
                onRuntimeExec(String.valueOf(arg));
            }
        } catch (Throwable ignored) {}
    }

    public static void onProcessBuilderStart(Object pbThis) {
        if (!installed || pbThis == null) return;
        try {
            if (pbThis instanceof java.lang.ProcessBuilder) {
                java.util.List<String> cmd = ((java.lang.ProcessBuilder) pbThis).command();
                String[] arr = cmd.toArray(new String[0]);
                onProcessBuilderStart(arr);
            } else {
                RaspEvent ev = new RaspEvent("java.process_builder",
                    "java.lang.ProcessBuilder", "start");
                ev.arguments = new String[]{trunc(String.valueOf(pbThis), 256)};
                ev.stackTrace = captureStack();
                reporter.emit(ev);
            }
        } catch (Throwable ignored) {}
    }

    public static void onJNDILookup(Object name) {
        if (!installed || name == null) return;
        try {
            onJNDILookup(String.valueOf(name));
        } catch (Throwable ignored) {}
    }

    public static void onDeserialize(Object oisThis) {
        if (!installed) return;
        try {
            RaspEvent ev = new RaspEvent("java.deserialize",
                "java.io.ObjectInputStream", "readObject");
            ev.arguments = new String[]{oisThis == null ? "null" : oisThis.getClass().getName()};
            ev.stackTrace = captureStack();
            reporter.emit(ev);
        } catch (Throwable ignored) {}
    }

    public static void onDefineClass(String className, byte[] bytes) {
        if (!installed) return;
        try {
            onDefineClass(className, bytes == null ? 0 : bytes.length);
        } catch (Throwable ignored) {}
    }

    public static void onFilterRegistered(Object filterDef) {
        if (!installed || filterDef == null) return;
        try {
            onFilterRegistered(filterDef.getClass().getName());
        } catch (Throwable ignored) {}
    }
}
