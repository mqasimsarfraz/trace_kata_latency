#!/usr/bin/env python3
"""Regression tests for validate-output.py's fail-closed contract."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "validate-output.py"
FIXTURE = ROOT / "sample-output.jsonl"


class ValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = [
            json.loads(line)
            for line in FIXTURE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def validate(self, rows):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row) + "\n")
            stream.flush()
            return subprocess.run(
                [sys.executable, str(VALIDATOR), stream.name],
                text=True,
                capture_output=True,
                check=False,
            )

    def assert_rejected(self, rows, message):
        result = self.validate(rows)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)

    def test_valid_extended_fixture(self):
        result = self.validate(copy.deepcopy(self.rows))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS: 18 rows", result.stdout)

    def test_empty_timestamp(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["timestamp"] = ""
        self.assert_rejected(rows, "timestamp must be RFC3339Nano")

    def test_malformed_timestamp(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["timestamp"] = "not-a-timestamp"
        self.assert_rejected(rows, "timestamp must be RFC3339Nano")

    def test_invalid_calendar_timestamp(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["timestamp"] = "2026-02-30T00:00:00Z"
        self.assert_rejected(rows, "invalid RFC3339Nano timestamp")

    def test_start_before_create(self):
        rows = copy.deepcopy(self.rows)
        # Change the earlier failed Create into Start for a container whose
        # successful Create still occurs later. Timestamps remain ordered.
        rows[4].update(
            operation="StartContainer",
            failed=False,
            container_id="container-a",
        )
        self.assert_rejected(rows, "no preceding successful CreateContainer")

    def test_remove_before_stop(self):
        rows = copy.deepcopy(self.rows)
        rows[8]["operation"] = "RemoveContainer"
        self.assert_rejected(rows, "requires stopped container state")

    def test_container_chain_without_successful_parent_run(self):
        rows = copy.deepcopy(self.rows)
        # Preserve overall successful Run coverage for kata, but point the
        # complete container chain at a sandbox never learned by a Run.
        for row in rows:
            if row["runtime_handler"] == "kata" and row["sandbox_id"] == "sandbox-a" and row["operation"] != "RunPodSandbox":
                row["sandbox_id"] = "orphan-sandbox"
        self.assert_rejected(rows, "no preceding successful active RunPodSandbox")

    def test_failed_transition_does_not_advance_state(self):
        rows = copy.deepcopy(self.rows)
        rows[8]["failed"] = True
        self.assert_rejected(rows, "StopContainer requires started container state")


if __name__ == "__main__":
    unittest.main()
