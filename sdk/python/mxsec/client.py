"""mxsec API HTTP 客户端."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, List, Optional
from urllib.parse import urlencode

import urllib.request
import urllib.error


class MxsecError(Exception):
    """API 调用异常."""
    def __init__(self, message: str, code: int = 0, status_code: int = 0):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass
class ApiResponse:
    """统一响应信封."""
    code: int
    message: str
    data: Any


class Client:
    """mxsec API 客户端."""

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        timeout: float = 30.0,
        user_agent: str = "mxsec-python-sdk/0.1.0",
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.user_agent = user_agent

    # ============ 主机 ============

    def list_hosts(
        self,
        status: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """GET /api/v1/hosts."""
        params = {"page": page, "page_size": page_size}
        if status:
            params["status"] = status
        resp = self._do("GET", "/api/v1/hosts", params=params)
        return resp.data

    def get_host(self, host_id: str) -> dict:
        """GET /api/v1/hosts/{host_id}."""
        resp = self._do("GET", f"/api/v1/hosts/{host_id}")
        return resp.data

    # ============ 告警 ============

    def list_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[dict]:
        """GET /api/v1/alerts."""
        params = {}
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        resp = self._do("GET", "/api/v1/alerts", params=params)
        return resp.data.get("items", []) if isinstance(resp.data, dict) else []

    # ============ 运行模式 ============

    def get_mode(self) -> dict:
        """GET /api/v2/system/mode."""
        resp = self._do("GET", "/api/v2/system/mode")
        return resp.data

    def set_mode(self, tenant_id: str, mode: str, reason: str) -> dict:
        """POST /api/v2/admin/tenants/{id}/mode."""
        if mode not in ("observe", "protect"):
            raise ValueError("mode must be observe or protect")
        payload = {"mode": mode, "reason": reason}
        resp = self._do("POST", f"/api/v2/admin/tenants/{tenant_id}/mode", payload=payload)
        return resp.data

    # ============ 配置变更审批 ============

    def submit_config_change(
        self,
        target_table: str,
        target_key: str,
        proposed_value: str,
        reason: str,
    ) -> dict:
        """POST /api/v2/config/change-requests."""
        if len(reason) < 10:
            raise ValueError("reason must be >= 10 chars (audit)")
        payload = {
            "target_table": target_table,
            "target_key": target_key,
            "proposed_value": proposed_value,
            "reason": reason,
        }
        resp = self._do("POST", "/api/v2/config/change-requests", payload=payload)
        return resp.data

    def approve_config_change(self, change_id: int) -> dict:
        resp = self._do("POST", f"/api/v2/config/change-requests/{change_id}/approve")
        return resp.data

    def reject_config_change(self, change_id: int, reason: str) -> dict:
        if len(reason) < 5:
            raise ValueError("reject reason >= 5 chars")
        resp = self._do(
            "POST",
            f"/api/v2/config/change-requests/{change_id}/reject",
            payload={"reason": reason},
        )
        return resp.data

    # ============ 漏洞 ============

    def list_vulns(self) -> List[dict]:
        """GET /api/v1/vulnerabilities."""
        resp = self._do("GET", "/api/v1/vulnerabilities")
        if isinstance(resp.data, dict):
            return resp.data.get("items", [])
        return resp.data or []

    # ============ 隔离箱 ============

    def list_quarantine(self) -> List[dict]:
        """GET /api/v1/quarantine."""
        resp = self._do("GET", "/api/v1/quarantine")
        if isinstance(resp.data, dict):
            return resp.data.get("items", [])
        return resp.data or []

    def restore_quarantine(self, qid: str) -> dict:
        resp = self._do("POST", f"/api/v1/quarantine/{qid}/restore")
        return resp.data

    # ============ 内部 ============

    def _do(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        payload: Optional[dict] = None,
    ) -> ApiResponse:
        url = self.base_url + path
        if params:
            url += "?" + urlencode(params)

        body_bytes = None
        if payload is not None:
            body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(url, data=body_bytes, method=method)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", self.user_agent)
        if payload is not None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read().decode("utf-8")
                status = r.status
        except urllib.error.HTTPError as e:
            raise MxsecError(
                f"http {e.code}: {e.read().decode('utf-8', errors='ignore')}",
                status_code=e.code,
            )
        except urllib.error.URLError as e:
            raise MxsecError(f"url error: {e.reason}")

        try:
            j = json.loads(raw)
        except Exception:
            raise MxsecError(f"non-json response: {raw[:200]}")

        ar = ApiResponse(
            code=j.get("code", 0),
            message=j.get("message", ""),
            data=j.get("data"),
        )
        if ar.code != 0:
            raise MxsecError(ar.message, code=ar.code, status_code=status)
        return ar
