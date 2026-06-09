"""UDS 事件上报 (P4-2)."""

from __future__ import annotations

import json
import os
import queue
import socket
import struct
import threading
import time
from typing import Optional

from .event import RaspEvent


class EventReporter:
    """事件上报到 Agent 主进程 (UDS).

    协议: 4 字节 BE 长度 + JSON body.

    失败处理:
        - 队列满 → drop oldest
        - 连接断 → 后台 reconnect 自动重连 (3s)
        - 永不抛异常给业务代码
    """

    def __init__(self, uds_path: str, tenant_id: str, queue_capacity: int = 10000):
        self.uds_path = uds_path
        self.tenant_id = tenant_id
        self.queue: queue.Queue[RaspEvent] = queue.Queue(maxsize=queue_capacity)
        self.dropped_count = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    def emit(self, ev: RaspEvent) -> None:
        """入队 (非阻塞)."""
        if not self._running:
            return
        try:
            self.queue.put_nowait(ev)
        except queue.Full:
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(ev)
                self.dropped_count += 1
            except queue.Empty:
                pass

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, name="mxsec-rasp-reporter", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass

    def _run(self) -> None:
        while self._running:
            sock = self._connect()
            if sock is None:
                time.sleep(5.0)
                continue
            self._sock = sock
            try:
                while self._running:
                    ev = self.queue.get(timeout=1.0)
                    if ev is None:
                        continue
                    self._write_frame(sock, ev)
            except queue.Empty:
                pass
            except Exception:
                # 连接断 → 重试
                try:
                    sock.close()
                except Exception:
                    pass
                time.sleep(3.0)

    def _connect(self) -> Optional[socket.socket]:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(self.uds_path)
            sock.settimeout(None)
            return sock
        except Exception:
            return None

    def _write_frame(self, sock: socket.socket, ev: RaspEvent) -> None:
        ev.tenant_id = self.tenant_id
        body = json.dumps(ev.to_dict(), ensure_ascii=False).encode("utf-8")
        header = struct.pack(">I", len(body))
        sock.sendall(header + body)
