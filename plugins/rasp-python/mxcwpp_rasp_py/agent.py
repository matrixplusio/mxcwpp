"""Python RASP agent 主入口 (P4-2)."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Optional

from .reporter import EventReporter
from .event import RaspEvent


@dataclass
class RaspConfig:
    """RASP 配置."""
    uds_path: str = "/var/run/mxcwpp-rasp.sock"
    tenant_id: str = "t-default"
    enabled: bool = True
    queue_capacity: int = 10000
    suspect_modules: set = field(default_factory=lambda: {
        "ctypes", "resource", "pty", "telnetlib", "paramiko",
        "crypt", "subprocess",
    })

    @classmethod
    def from_env(cls) -> "RaspConfig":
        return cls(
            uds_path=os.environ.get("MXCWPP_RASP_UDS", "/var/run/mxcwpp-rasp.sock"),
            tenant_id=os.environ.get("MXCWPP_RASP_TENANT", "t-default"),
            enabled=os.environ.get("MXCWPP_RASP_ENABLED", "1") != "0",
        )


# 全局状态
_installed = False
_reporter: Optional[EventReporter] = None
_config: Optional[RaspConfig] = None
_in_hook = False  # 递归保护


# Audit event → RASP kind 映射
_AUDIT_KIND_MAP = {
    "compile": "py.compile",
    "exec": "py.exec",
    "subprocess.Popen": "py.subprocess",
    "os.system": "py.os_system",
    "os.exec": "py.os_exec",
    "os.spawn": "py.os_spawn",
    "socket.connect": "py.socket_connect",
    "socket.bind": "py.socket_bind",
    "pickle.find_class": "py.pickle_deserialize",
    "marshal.loads": "py.marshal_deserialize",
    "importlib.find_spec": "py.dynamic_import",
    "urllib.Request": "py.urllib_request",
    "open": "py.file_open",
}

# 高敏 audit event (一定上报)
_HIGH_PRIORITY = {
    "compile", "exec", "subprocess.Popen", "os.system",
    "os.exec", "pickle.find_class", "marshal.loads",
}


def install(uds_path: Optional[str] = None,
            tenant_id: Optional[str] = None,
            config: Optional[RaspConfig] = None) -> None:
    """安装 audit hook."""
    global _installed, _reporter, _config

    if _installed:
        return

    if config is None:
        config = RaspConfig.from_env()
    if uds_path is not None:
        config.uds_path = uds_path
    if tenant_id is not None:
        config.tenant_id = tenant_id

    if not config.enabled:
        return

    _config = config
    _reporter = EventReporter(config.uds_path, config.tenant_id, config.queue_capacity)
    _reporter.start()

    # 注册 PEP 578 audit hook (Python 3.8+)
    try:
        sys.addaudithook(_audit_hook)
        _installed = True
    except Exception as e:
        sys.stderr.write(f"[mxcwpp-rasp] addaudithook failed: {e}\n")


def _audit_hook(event_name: str, args: tuple) -> None:
    """PEP 578 audit 回调.

    永不抛异常给业务. 无限递归保护 (RASP 自身的 IO 也会触发 audit).
    """
    global _in_hook
    if _in_hook or not _installed or _reporter is None:
        return

    # 优先级: 命中 _AUDIT_KIND_MAP 或 _HIGH_PRIORITY 才报
    kind = _AUDIT_KIND_MAP.get(event_name)
    if kind is None:
        # 检查前缀 (subprocess.Popen / socket.connect 等)
        for prefix, mapped in _AUDIT_KIND_MAP.items():
            if event_name.startswith(prefix):
                kind = mapped
                break

    if kind is None and event_name not in _HIGH_PRIORITY:
        return

    if kind is None:
        kind = f"py.{event_name.replace('.', '_')}"

    try:
        _in_hook = True
        ev = RaspEvent(
            kind=kind,
            class_name=event_name,
            method_name="",
            arguments=_summarize_args(args),
            stack_trace=_capture_stack(),
            tenant_id=_config.tenant_id if _config else "t-default",
            pid=os.getpid(),
        )
        _reporter.emit(ev)
    except Exception:
        pass
    finally:
        _in_hook = False


def _summarize_args(args: tuple) -> list:
    """缩略 args 防内存爆 + 防递归."""
    out = []
    for a in args[:5]:
        try:
            s = repr(a)
            if len(s) > 256:
                s = s[:256] + "..."
            out.append(s)
        except Exception:
            out.append("<unprintable>")
    return out


def _capture_stack(max_frames: int = 30) -> list:
    """抓调用栈 (跳过 RASP 自身)."""
    try:
        import traceback
        frames = traceback.extract_stack()
        out = []
        for f in frames:
            if "mxcwpp_rasp_py" in f.filename:
                continue
            out.append(f"{f.filename}:{f.lineno}:{f.name}")
            if len(out) >= max_frames:
                break
        return out
    except Exception:
        return []


def uninstall() -> None:
    """停止 reporter (sys.addaudithook 不可移除, 但 reporter 可停)."""
    global _installed, _reporter
    if _reporter is not None:
        _reporter.stop()
    _installed = False
