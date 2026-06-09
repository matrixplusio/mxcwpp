#!/usr/bin/env python3
"""
PR2b helper: add tenant_id column to hardcoded CREATE TABLE strings in tests.

For each `CREATE TABLE name (` block in *_test.go that does not already
contain tenant_id, inject:

    tenant_id TEXT DEFAULT 't-default' NOT NULL,

as the first column after the opening parenthesis.

Idempotent. Run from repo root.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET_DIRS = [
    ROOT / "internal" / "server" / "manager" / "api",
    ROOT / "internal" / "server" / "manager" / "biz",
    ROOT / "internal" / "server" / "manager" / "middleware",
    ROOT / "internal" / "server" / "agentcenter" / "scheduler",
]

CREATE_TABLE_RE = re.compile(
    r"(CREATE TABLE(?:\s+IF NOT EXISTS)?\s+(\w+)\s*\(\s*\n)((?:(?!\)\s*[`;)]).)*?)(\n\s*\)\s*[`;)])",
    re.DOTALL,
)

# Tables that don't need tenant_id (test helpers that emulate global / RBAC
# tables only).  Lower-case.
SKIP_TABLES = {
    "permissions",
    "role_permissions",
    "tenants",
    "tenant_configs",
    "users",  # users already has tenant_id from PR2a model change; tests may
              # define users with explicit column list; we still add it
              # defensively below — comment intentional.
}


def transform(text: str) -> tuple[str, int]:
    changes = 0

    def rewrite(m: re.Match) -> str:
        nonlocal changes
        header = m.group(1)
        name = m.group(2).lower()
        body = m.group(3)
        tail = m.group(4)
        if name in SKIP_TABLES:
            return m.group(0)
        if re.search(r"\btenant_id\b", body):
            return m.group(0)
        # Insert tenant_id as first column.
        # Determine indentation from the first non-empty body line.
        body_lines = body.split("\n")
        first_non_empty = next((ln for ln in body_lines if ln.strip()), "")
        indent_match = re.match(r"(\s+)", first_non_empty)
        indent = indent_match.group(1) if indent_match else "\t\t\t"
        injected = (
            f"{indent}tenant_id TEXT NOT NULL DEFAULT 't-default',\n"
        )
        changes += 1
        return header + injected + body + tail

    new_text = CREATE_TABLE_RE.sub(rewrite, text)
    return new_text, changes


def main() -> int:
    total_files = 0
    total_changes = 0
    for d in TARGET_DIRS:
        for path in d.rglob("*_test.go"):
            text = path.read_text()
            new_text, changes = transform(text)
            if changes:
                path.write_text(new_text)
                total_files += 1
                total_changes += changes
                rel = path.relative_to(ROOT)
                print(f"  {rel}: +{changes} CREATE TABLE")
    print()
    print(f"Done. Files: {total_files}. CREATE TABLE statements patched: {total_changes}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
