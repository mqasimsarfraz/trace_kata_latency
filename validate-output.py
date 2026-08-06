#!/usr/bin/env python3
"""Fail-closed semantic validator for trace_kata_latency JSONL."""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime

HANDLERS = {"kata", "kata-preview"}
OPS = {
    "RunPodSandbox",
    "StopPodSandbox",
    "RemovePodSandbox",
    "CreateContainer",
    "StartContainer",
    "StopContainer",
    "RemoveContainer",
}
CORE = {"RunPodSandbox", "CreateContainer", "StartContainer"}
EXTENDED = OPS
REQUIRED_FIELDS = {
    "timestamp",
    "runtime_handler",
    "operation",
    "latency_ns_raw",
    "failed",
    "sandbox_id",
    "container_id",
}
RFC3339_NANO = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d{1,9})?"
    r"(?P<zone>Z|[+-]\d{2}:\d{2})$"
)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_timestamp(value, line_number):
    """Parse the RFC3339Nano subset emitted by Go's time formatter."""
    if not isinstance(value, str) or not RFC3339_NANO.fullmatch(value):
        fail(f"line {line_number}: timestamp must be RFC3339Nano")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        # datetime accepts at most microseconds. Keep syntax checking for all
        # nine RFC3339Nano digits, but parse only six; ordering uses the full
        # canonical text components below and therefore retains nanoseconds.
        match = RFC3339_NANO.fullmatch(value)
        fraction = (match.group("fraction") or ".0")[1:].ljust(9, "0")
        parse_value = (
            f"{match.group('date')}T{match.group('time')}."
            f"{fraction[:6]}{'+00:00' if match.group('zone') == 'Z' else match.group('zone')}"
        )
        parsed = datetime.fromisoformat(parse_value)
    except ValueError as error:
        fail(f"line {line_number}: invalid RFC3339Nano timestamp: {error}")
    # UTC seconds plus the original nanosecond component gives a stable,
    # timezone-independent ordering key without floating-point rounding.
    seconds = int(parsed.timestamp())
    nanoseconds = int(fraction)
    return seconds * 1_000_000_000 + nanoseconds


def require(condition, line_number, message):
    if not condition:
        fail(f"line {line_number}: {message}")


def validate_lifecycle(rows):
    """Validate successful transitions in stream order.

    Failed calls must refer to valid current objects, but never advance or
    delete state. This permits retryable failures without accepting lifecycle
    events detached from an observed successful parent.
    """
    sandboxes = {}  # (handler, sandbox_id) -> running | stopped
    containers = {}  # (handler, container_id) -> {sandbox_id, state}

    for line_number, row in enumerate(rows, 1):
        handler = row["runtime_handler"]
        operation = row["operation"]
        sandbox_id = row["sandbox_id"]
        container_id = row["container_id"]
        failed = row["failed"]
        sandbox_key = (handler, sandbox_id)
        container_key = (handler, container_id)

        if operation == "RunPodSandbox":
            require(not container_id, line_number, "RunPodSandbox must not carry container_id")
            if not failed:
                require(bool(sandbox_id), line_number, "successful RunPodSandbox is missing sandbox_id")
                require(sandbox_key not in sandboxes, line_number, "duplicate active sandbox identity")
                sandboxes[sandbox_key] = "running"
            continue

        if operation == "CreateContainer":
            require(bool(sandbox_id), line_number, "CreateContainer is missing sandbox_id")
            require(
                sandboxes.get(sandbox_key) == "running",
                line_number,
                "CreateContainer has no preceding successful active RunPodSandbox",
            )
            if not failed:
                require(bool(container_id), line_number, "successful CreateContainer is missing container_id")
                require(container_key not in containers, line_number, "duplicate active container identity")
                containers[container_key] = {"sandbox_id": sandbox_id, "state": "created"}
            continue

        if operation in {"StartContainer", "StopContainer", "RemoveContainer"}:
            require(bool(sandbox_id) and bool(container_id), line_number, "parent/container identity missing")
            container = containers.get(container_key)
            require(container is not None, line_number, f"{operation} has no preceding successful CreateContainer")
            require(container["sandbox_id"] == sandbox_id, line_number, f"{operation} parent sandbox mismatch")
            if operation == "StartContainer":
                require(container["state"] == "created", line_number, "StartContainer requires created container state")
            elif operation == "StopContainer":
                require(
                    container["state"] in {"started", "stopped"},
                    line_number,
                    "StopContainer requires started or stopped container state",
                )
            if not failed:
                if operation == "StartContainer":
                    container["state"] = "started"
                elif operation == "StopContainer":
                    container["state"] = "stopped"
                else:
                    del containers[container_key]
            continue

        require(bool(sandbox_id), line_number, f"{operation} is missing sandbox_id")
        require(not container_id, line_number, f"{operation} must not carry container_id")
        require(
            sandboxes.get(sandbox_key) in {"running", "stopped"},
            line_number,
            f"{operation} has no preceding successful RunPodSandbox",
        )
        if not failed:
            if operation == "StopPodSandbox":
                sandboxes[sandbox_key] = "stopped"
                for key, container in containers.items():
                    if key[0] == handler and container["sandbox_id"] == sandbox_id:
                        container["state"] = "stopped"
            else:
                del sandboxes[sandbox_key]
                for key in [
                    key for key, container in containers.items()
                    if key[0] == handler and container["sandbox_id"] == sandbox_id
                ]:
                    del containers[key]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("jsonl")
    parser.add_argument("--profile", choices=("core", "extended"), default="extended")
    args = parser.parse_args()

    rows = []
    previous_timestamp = None
    with open(args.jsonl, encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                fail(f"line {line_number}: invalid JSON: {error}")
            if not isinstance(row, dict):
                fail(f"line {line_number}: object required")
            missing = REQUIRED_FIELDS - row.keys()
            if missing:
                fail(f"line {line_number}: missing {sorted(missing)}")
            if row["runtime_handler"] not in HANDLERS:
                fail(f"line {line_number}: unknown handler")
            if row["operation"] not in OPS:
                fail(f"line {line_number}: unknown operation")
            if not isinstance(row["failed"], bool):
                fail(f"line {line_number}: failed must be boolean")
            latency = row["latency_ns_raw"]
            if isinstance(latency, bool) or not isinstance(latency, int) or latency < 0:
                fail(f"line {line_number}: invalid latency")
            timestamp = parse_timestamp(row["timestamp"], line_number)
            if previous_timestamp is not None and timestamp < previous_timestamp:
                fail(f"line {line_number}: timestamp precedes prior row")
            previous_timestamp = timestamp
            for field in ("sandbox_id", "container_id"):
                if not isinstance(row[field], str) or len(row[field]) > 127:
                    fail(f"line {line_number}: invalid {field}")
            rows.append(row)

    if not rows:
        fail("zero lifecycle rows")
    observed_handlers = {row["runtime_handler"] for row in rows}
    if missing_handlers := HANDLERS - observed_handlers:
        fail(f"both handlers are required; missing {sorted(missing_handlers)}")

    # Check transition semantics before aggregate coverage so an impossible
    # stream reports its first causal lifecycle error, not merely a later
    # missing-operation summary.
    validate_lifecycle(rows)

    required_operations = CORE if args.profile == "core" else EXTENDED
    for handler in HANDLERS:
        successes = {
            row["operation"] for row in rows
            if row["runtime_handler"] == handler and not row["failed"]
        }
        if missing_operations := required_operations - successes:
            fail(f"{handler}: missing successful {sorted(missing_operations)}")
        if not any(row["runtime_handler"] == handler and row["failed"] for row in rows):
            fail(f"{handler}: missing intentional failure")

    owners = {}
    for row in rows:
        for identity in (row["sandbox_id"], row["container_id"]):
            if identity and identity in owners and owners[identity] != row["runtime_handler"]:
                fail(f"identifier crosses handlers: {identity}")
            if identity:
                owners[identity] = row["runtime_handler"]

    switches = sum(
        first["runtime_handler"] != second["runtime_handler"]
        for first, second in zip(rows, rows[1:])
    )
    if switches < 3:
        fail(f"insufficient interleaving: {switches} handler transitions")
    print(
        f"PASS: {len(rows)} rows; profile={args.profile}; switches={switches}; "
        f"handlers={dict(Counter(row['runtime_handler'] for row in rows))}; "
        f"operations={dict(Counter(row['operation'] for row in rows))}"
    )


if __name__ == "__main__":
    main()
