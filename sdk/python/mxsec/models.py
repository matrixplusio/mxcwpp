"""mxsec API dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Host:
    host_id: str
    hostname: str = ""
    ip: str = ""
    os_family: str = ""
    os_version: str = ""
    kernel_version: str = ""
    arch: str = ""
    status: str = ""
    agent_version: str = ""
    last_heartbeat: str = ""
    tenant_id: str = ""


@dataclass
class Alert:
    alert_id: str
    host_id: str = ""
    rule_id: str = ""
    severity: str = ""
    category: str = ""
    title: str = ""
    description: str = ""
    mitre_id: str = ""
    status: str = ""
    created_at: str = ""
    tenant_id: str = ""


@dataclass
class ConfigChangeRequest:
    id: int
    tenant_id: str = ""
    target_table: str = ""
    target_key: str = ""
    old_value: str = ""
    proposed_value: str = ""
    reason: str = ""
    status: str = "pending"
    requested_by: str = ""
    approval_required_count: int = 1
    approved_count: int = 0
    approvers: str = ""
    rejected_by: str = ""
    reject_reason: str = ""
    created_at: str = ""
