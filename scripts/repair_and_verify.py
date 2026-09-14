#!/usr/bin/env python3
"""Retain the failed run's logs, then run the repaired verifier once."""
from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from launch_deployment import ACCOUNT, AwsCli, DeploymentError
from launch_verification import launch

FAILED_BUILD = "authority-delta-deploy:216ae0dc-03d0-4950-8471-d212e6ccedfb"


def recover_logs(cli):
    builds = cli.run("codebuild", "batch-get-builds", "--ids", FAILED_BUILD).get("builds", [])
    if len(builds) != 1 or builds[0].get("id") != FAILED_BUILD or builds[0].get("projectName") != "authority-delta-deploy":
        raise DeploymentError("Failed build identity mismatch.")
    build = builds[0]
    log = build.get("logs", {})
    if log.get("groupName") != "/aws/codebuild/authority-delta-deploy" or not log.get("streamName"):
        raise DeploymentError("Expected owned CodeBuild log stream is unavailable.")
    events, token = [], None
    complete = False
    for _ in range(20):
        arguments = ["logs", "get-log-events", "--log-group-name", log["groupName"],
            "--log-stream-name", log["streamName"], "--start-from-head", "--limit", "1000"]
        if token:
            arguments += ["--next-token", token]
        page = cli.run(*arguments)
        events.extend(page.get("events", []))
        next_token = page.get("nextForwardToken")
        if not next_token or next_token == token:
            complete = True
            break
        token = next_token
    directory = ROOT / "evidence/aws/recovered-v2"
    directory.mkdir(parents=True, exist_ok=True)
    record = {"build_id": FAILED_BUILD, "build_status": build.get("buildStatus"),
        "log_group": log["groupName"], "log_stream": log["streamName"],
        "pagination_complete": complete, "events": events,
        "scope": "RAW_PROGRESS_LOGS_NOT_A_GATEWAY_PROOF_OR_FINAL_REPORT"}
    (directory / "cloudwatch-log.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
    progress = [e.get("message", "").strip() for e in events
        if re.fullmatch(r"\[gateway\] (?:P-00[1-6]|C-001): (?:PASS|FAIL)\s*", e.get("message", ""))]
    print("Previous run progress: " + json.dumps(progress), flush=True)
    print("Previous logs saved. Progress lines lack the complete request/ledger proof; no gate promoted.", flush=True)
    return record


def main():
    cli = AwsCli()
    try:
        if cli.run("sts", "get-caller-identity").get("Account") != ACCOUNT:
            raise DeploymentError("Wrong AWS account.")
        try:
            recover_logs(cli)
        except (DeploymentError, OSError, KeyError, ValueError) as exc:
            print(f"Previous log recovery unavailable: {exc}", flush=True)
        return launch(cli)
    except (DeploymentError, OSError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
