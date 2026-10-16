"""Offline DepGuard evidence-chain replay; never calls an LLM or data source.

Usage: python -m agent.replay output/session_<id>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent.scan_guard import evidence_chain_errors


def main() -> int:
    parser = argparse.ArgumentParser(description="离线重放 DepGuard 批次合并与证据门禁")
    parser.add_argument("session_dir", type=Path)
    args = parser.parse_args()
    session_dir = args.session_dir.resolve()
    errors = evidence_chain_errors(session_dir)
    print(json.dumps({"ok": not errors, "session_dir": str(session_dir),
                      "errors": errors}, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
