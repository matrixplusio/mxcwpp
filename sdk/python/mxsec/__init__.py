"""mxsec Python SDK (P4-4).

用法:

    from mxsec import Client

    cli = Client("https://mxsec.example.com", token="eyJhbGc...")
    hosts = cli.list_hosts(status="online")
    alerts = cli.list_alerts(severity="critical")
    cli.set_mode("t-default", "protect", reason="incident-2026-06-07")
"""

from .client import Client, MxsecError, ApiResponse
from .models import Host, Alert, ConfigChangeRequest

__version__ = "0.1.0"

__all__ = ["Client", "MxsecError", "ApiResponse", "Host", "Alert", "ConfigChangeRequest"]
