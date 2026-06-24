# Java RASP Agent 设计 (M1-2)

## 目标

JVM 内嵌探针, 实时捕获:

- Web 内存马类加载 (Behinder/Godzilla/AntSword/ChinaShell)
- 反序列化 sink (XStream/Fastjson/Jackson/Hessian)
- Runtime.exec / ProcessBuilder.start (远程命令执行)
- ClassLoader.defineClass 动态加载 (无文件落地)
- JNDI 注入 (Log4Shell 类)

严格 **read-only**:
插件仅观察 + 上报, **不抛异常 / 不修改返回值 / 不阻断业务**。
阻断动作 (mode=protect) 留 Sprint 5+ 客户授权后启用。

## 架构

```
JVM Process
  │
  ├─→ -javaagent:libmxcwpp_rasp.so          (premain Attach API)
  │
  └─→ libmxcwpp_rasp.so (Native Agent)
        │
        ├─→ JVMTI: SetEventCallbacks(ClassFileLoadHook)
        ├─→ ASM / Javassist: 字节码插桩 sensitive sink
        │
        ├─→ 事件队列 (per-thread, lock-free ring)
        │
        └─→ UnixDomainSocket → mxcwpp-agent (DataType 4000-4099)
```

## 钩子表 (Sprint 5+ 启用 protect 时也兼容)

| Sink 类 | 拦截方法 | ATT&CK |
|---|---|---|
| `java.lang.Runtime` | `exec*` | T1059.007 |
| `java.lang.ProcessBuilder` | `start` | T1059.007 |
| `javax.naming.InitialContext` | `lookup` (JNDI) | T1190 (Log4Shell) |
| `java.io.ObjectInputStream` | `readObject` | T1190 反序列化 |
| `java.lang.ClassLoader` | `defineClass` | T1027.004 内存马 |
| `javax.servlet.Filter` | `doFilter` (动态注册) | T1505.003 |
| `javax.servlet.Servlet` | `service` (动态注册) | T1505.003 |

## 字节码插桩规范

```java
// 原方法 (Runtime.exec)
public Process exec(String cmd) {
    return /* original */;
}

// 插桩后
public Process exec(String cmd) {
    RaspEventBus.emit("java.runtime_exec", cmd, /* stack */);
    return /* original */;
}
```

**永远先 emit 后 invoke 原方法**: 失败/异常不影响业务流。
emit 实现走 lock-free ring + per-thread buffer, 避免锁等待。

## 与 Agent 主进程通信

- 协议: UDS (`/var/run/mxcwpp-rasp.sock`)
- 帧格式: 4 字节 BE 长度 + JSON
- Agent 主进程收到 → 转 DataType 4000-4099 上报 AC

## 安全考虑

- 插桩失败白名单: HotSpot 内部类 / boot ClassLoader / 关键 framework
- 死循环防护: RASP 自身代码命中 hook → skip
- OOM 保护: 事件队列 max 10000, 满 → drop oldest, 不阻塞 JVM
- 文件大小: < 5MB (含 ASM lib)
- CPU 开销: < 2% (压测 spring-boot 100 RPS)

## 部署

```sh
# 1. 复制 .so 到 Java 应用机
scp libmxcwpp_rasp.so app-server:/opt/mxcwpp/rasp/

# 2. JVM 启动加参数
java -javaagent:/opt/mxcwpp/rasp/libmxcwpp_rasp.so \
     -Dmxcwpp.rasp.uds=/var/run/mxcwpp-rasp.sock \
     -Dmxcwpp.rasp.tenant=t-default \
     -jar app.jar

# 3. 验证
curl http://app/admin/exec?cmd=id      # 触发 Runtime.exec
# Agent 应上报 DataType 4001, mxcwpp UI 看到 RASP 告警
```

## 不在本 PR

- libmxcwpp_rasp.so 实际实现 (Sprint 5+ 单独工程, C/C++ + JVMTI)
- protect 模式拦截 (默认 observe)
- 多 OpenJDK 版本兼容 (8/11/17/21 矩阵测试)

## 后续 PR 清单

1. M1-2b: Server 端 AntiRootkitReport model + Stage 接 DataType 3006
2. M1-2c: ant-rootkit Indicator 接入 storyline 故事线
3. Sprint 5: libmxcwpp_rasp.so PoC (Runtime.exec hook)
4. Sprint 5: Memshell ASM 字节码扫描
