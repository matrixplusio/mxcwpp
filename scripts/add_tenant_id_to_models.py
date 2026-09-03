#!/usr/bin/env python3
"""
PR2b: Add tenant_id column to all business models.

Strategy:
  Scan internal/server/model/*.go (excluding *_test.go).
  For each `type XxxName struct { ... }` block whose name is in AllModels
  but not in SKIP_MODELS, insert a TenantID field as the first field
  inside the struct body (right after the opening brace).

  TenantID field schema (matches User in PR2a):
    TenantID string `gorm:"column:tenant_id;type:varchar(64);not null;index;default:'t-default'" json:"tenant_id"`

Already-handled models (skipped):
  - User (PR2a)
  - Tenant / TenantConfig (PR2a, own table)
  - Permission / RolePermission (RBAC metadata, global)

The script is idempotent: if a struct already has TenantID, skip.

Run from repo root:
  python3 scripts/add_tenant_id_to_models.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Set, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT / "internal" / "server" / "model"
MODELS_GO = MODEL_DIR / "models.go"

# Models that should NOT receive tenant_id column.
# Reasoning recorded in commit message + docs/multi-tenant.md §3.
SKIP_MODELS: Set[str] = {
    # Already added in PR2a
    "User",
    "Tenant",
    "TenantConfig",
    # RBAC metadata is platform-global
    "Permission",
    "RolePermission",
}

TENANT_FIELD_LINE = (
    "\tTenantID string `gorm:\"column:tenant_id;type:varchar(64);"
    "not null;index;default:'t-default'\" json:\"tenant_id\"`"
)


def extract_all_models() -> List[str]:
    """Parse AllModels = [...] in models.go, return type names."""
    text = MODELS_GO.read_text()
    m = re.search(r"AllModels\s*=\s*\[\]interface\{\}\{(.+?)\}\s*\)", text, re.DOTALL)
    if not m:
        sys.exit("ERR: cannot locate AllModels in models.go")
    body = m.group(1)
    names = re.findall(r"&(\w+)\{", body)
    return names


def find_struct_block(text: str, name: str) -> Tuple[int, int] | None:
    """Return (open_brace_pos, close_brace_pos) for `type Name struct { ... }`.
    Match top-level struct only (greedy fail-safe).
    """
    pat = re.compile(r"^type\s+" + re.escape(name) + r"\s+struct\s*\{", re.MULTILINE)
    m = pat.search(text)
    if not m:
        return None
    open_pos = m.end() - 1  # position of '{'
    depth = 0
    for i in range(open_pos, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return open_pos, i
    return None


def already_has_tenant(text: str, span: Tuple[int, int]) -> bool:
    body = text[span[0] : span[1] + 1]
    return re.search(r"\bTenantID\b", body) is not None


def insert_tenant_field(text: str, span: Tuple[int, int]) -> str:
    """Insert TENANT_FIELD_LINE on the first line inside the struct body."""
    open_pos, close_pos = span
    # Find newline after '{'
    nl = text.find("\n", open_pos)
    if nl == -1 or nl >= close_pos:
        return text
    head = text[: nl + 1]
    tail = text[nl + 1 :]
    return head + TENANT_FIELD_LINE + "\n" + tail


def process_file(path: Path, targets: Set[str]) -> List[str]:
    """Process a single model file. Return list of struct names modified."""
    text = path.read_text()
    original = text
    modified: List[str] = []
    # Process structs in reverse position order to keep spans stable.
    candidates = []
    for name in targets:
        span = find_struct_block(text, name)
        if span is None:
            continue
        candidates.append((span[0], name, span))
    candidates.sort(key=lambda t: -t[0])
    for _, name, span in candidates:
        if already_has_tenant(text, span):
            continue
        text = insert_tenant_field(text, span)
        modified.append(name)
    if text != original:
        path.write_text(text)
    return modified


def main() -> int:
    all_models = extract_all_models()
    targets = [m for m in all_models if m not in SKIP_MODELS]
    print(f"AllModels count: {len(all_models)}")
    print(f"Skip   count: {len(SKIP_MODELS)}")
    print(f"Target count: {len(targets)}")

    target_set = set(targets)
    found: Set[str] = set()
    files_changed = 0
    for go_file in sorted(MODEL_DIR.glob("*.go")):
        if go_file.name.endswith("_test.go"):
            continue
        modified = process_file(go_file, target_set)
        if modified:
            files_changed += 1
            for m in modified:
                found.add(m)
                print(f"  +TenantID  {go_file.name}::{m}")

    missing = target_set - found
    if missing:
        print()
        print(f"WARN: {len(missing)} target struct(s) NOT found in any model file:")
        for m in sorted(missing):
            print(f"  ? {m}")
        # Not fatal: some structs may share files via init_data or migration.

    print()
    print(f"Done. Files changed: {files_changed}. Structs annotated: {len(found)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
