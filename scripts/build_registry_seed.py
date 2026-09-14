#!/usr/bin/env python3
"""Build an idempotent DynamoDB transaction for the immutable request registry."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from authority_delta.registry import FixtureBundle


ROOT = Path(__file__).resolve().parents[1]


def build_transaction(fixtures: FixtureBundle, table_name: str) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for case in fixtures.all_cases:
        payload = json.dumps(case.request, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        items.append({
            "Put": {
                "TableName": table_name,
                "Item": {
                    "request_id": {"S": case.request_id},
                    "payload": {"S": payload},
                    "fixture_snapshot_hash": {"S": fixtures.request_registry_snapshot_hash},
                },
                "ConditionExpression": "attribute_not_exists(request_id) OR payload = :payload",
                "ExpressionAttributeValues": {":payload": {"S": payload}},
            }
        })
    return items


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", default="fixtures/decision_cases.json")
    parser.add_argument("--table-name", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    fixtures = FixtureBundle.load(ROOT / args.fixtures)
    output = (ROOT / args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build_transaction(fixtures, args.table_name), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"{output} records={len(fixtures.all_cases)} snapshot={fixtures.request_registry_snapshot_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
