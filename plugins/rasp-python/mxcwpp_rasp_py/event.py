"""RASP 事件 schema (P4-2)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RaspEvent:
    """与 Server engine.rasp.Event 字段对齐 (DataType 4000-4099)."""

    kind: str
    class_name: str = ""
    method_name: str = ""
    arguments: List[str] = field(default_factory=list)
    stack_trace: List[str] = field(default_factory=list)
    http_method: Optional[str] = None
    http_url: Optional[str] = None
    http_remote_ip: Optional[str] = None
    pid: int = 0
    tenant_id: str = "t-default"
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    mode: str = "observe"  # 永远 observe (硬约束)

    def to_dict(self) -> dict:
        d = {
            "kind": self.kind,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "arguments": self.arguments,
            "stack_trace": self.stack_trace,
            "pid": self.pid,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
            "mode": self.mode,
            "language": "python",
        }
        if self.http_method:
            d["http_method"] = self.http_method
        if self.http_url:
            d["http_url"] = self.http_url
        if self.http_remote_ip:
            d["http_remote_ip"] = self.http_remote_ip
        return d
