"""Authority Delta development CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .local_proof import build_local_proof
from .registry import FixtureBundle


def _write_json(value: object, output: str | None) -> None:
    content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
        print(json.dumps({"status": "written", "path": str(path)}, ensure_ascii=False))
    else:
        print(content, end="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="authority-delta")
    subcommands = parser.add_subparsers(dest="command", required=True)
    local = subcommands.add_parser("local-proof", help="run contract/replay/delta checks without AWS")
    local.add_argument("--fixtures", default="fixtures/decision_cases.json")
    local.add_argument("--output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "local-proof":
        fixtures = FixtureBundle.load(args.fixtures)
        _write_json(build_local_proof(fixtures), args.output)
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
