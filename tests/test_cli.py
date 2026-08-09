import contextlib
import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from agent_review_coordinator.cli import _ledger_lock, main
from agent_review_coordinator.findings import (
    Disposition,
    Finding,
    FixCost,
    Impact,
    P2Evidence,
    Reachability,
    Severity,
)
from agent_review_coordinator.ledger import ReviewLedger as ReviewLedgerModel
from agent_review_coordinator.ledger import ReviewResult
from agent_review_coordinator.policy import ReviewStage

REPOSITORY = "Boundless-Studios/gaia-free"
HEAD = "d" * 40
DELIVERY_ID = "repo:branch:base"
REVIEW_CHARTER_VERSION = "gaia-v1"


class ReviewLedger(ReviewLedgerModel):
    """Ledger fixture carrying the required delivery identity."""

    delivery_id: str = DELIVERY_ID
    review_charter_version: str = REVIEW_CHARTER_VERSION


def write_policy(path: Path) -> None:
    path.write_text(
        """
version: 1
review:
  local:
    reviewer_count: 2
    required_results: 2
    max_generation_rounds: 2
  backstop:
    reviewer_count: 1
    required_results: 1
    trigger: new_head_sha
settlement:
  p1: address
  p2: evaluate
  automatic_tracker_writes: false
""".strip(),
        encoding="utf-8",
    )


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


class CliTest(unittest.TestCase):
    def test_requirements_print_versioned_provider_neutral_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.yaml"
            write_policy(policy_path)

            code, stdout, _ = run_cli(
                [
                    "requirements",
                    "--policy",
                    str(policy_path),
                    "--stage",
                    "local",
                ]
            )

        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(stdout),
            [
                {"required": True, "schema_version": 1, "slot": "local:1"},
                {"required": True, "schema_version": 1, "slot": "local:2"},
            ],
        )

    def test_slots_print_provider_neutral_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.yaml"
            write_policy(policy_path)

            code, stdout, _ = run_cli(
                [
                    "slots",
                    "--policy",
                    str(policy_path),
                    "--stage",
                    "local",
                    "--round-number",
                    "1",
                ]
            )

        payload = json.loads(stdout)
        self.assertEqual(code, 0)
        self.assertEqual(len(payload), 2)
        self.assertTrue(all(item["provider"] is None for item in payload))

    def test_submit_atomically_creates_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger_path = root / "ledger.json"
            result_path = root / "result.json"
            result_path.write_text(
                ReviewResult(
                    repository=REPOSITORY,
                    head_sha=HEAD,
                    stage=ReviewStage.LOCAL,
                    round_number=1,
                    slot_number=1,
                    reviewer_execution_id="local-r1-slot1",
                ).model_dump_json(),
                encoding="utf-8",
            )

            code, stdout, _ = run_cli(
                [
                    "submit",
                    "--ledger",
                    str(ledger_path),
                    "--repository",
                    REPOSITORY,
                    "--head-sha",
                    HEAD,
                    "--delivery-id",
                    DELIVERY_ID,
                    "--review-charter-version",
                    REVIEW_CHARTER_VERSION,
                    "--result",
                    str(result_path),
                ]
            )

            stored = ReviewLedger.model_validate_json(
                ledger_path.read_text(encoding="utf-8")
            )

        self.assertEqual(code, 0)
        self.assertEqual(len(stored.results), 1)
        self.assertEqual(json.loads(stdout)["head_sha"], HEAD)
        self.assertEqual(stored.delivery_id, DELIVERY_ID)
        self.assertEqual(stored.review_charter_version, REVIEW_CHARTER_VERSION)

    def test_submit_rejects_existing_ledger_delivery_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger_path = root / "ledger.json"
            result_path = root / "result.json"
            ledger_path.write_text(
                ReviewLedger(
                    repository=REPOSITORY,
                    head_sha=HEAD,
                    delivery_id=DELIVERY_ID,
                    review_charter_version=REVIEW_CHARTER_VERSION,
                ).model_dump_json(),
                encoding="utf-8",
            )
            result_path.write_text(
                ReviewResult(
                    repository=REPOSITORY,
                    head_sha=HEAD,
                    stage=ReviewStage.LOCAL,
                    round_number=1,
                    slot_number=1,
                    reviewer_execution_id="local-r1-slot1",
                ).model_dump_json(),
                encoding="utf-8",
            )

            code, _, stderr = run_cli(
                [
                    "submit",
                    "--ledger",
                    str(ledger_path),
                    "--repository",
                    REPOSITORY,
                    "--head-sha",
                    HEAD,
                    "--delivery-id",
                    "repo:other-branch:base",
                    "--review-charter-version",
                    REVIEW_CHARTER_VERSION,
                    "--result",
                    str(result_path),
                ]
            )

        self.assertEqual(code, 2)
        self.assertIn("ledger identity does not match", stderr)

    def test_disposition_updates_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            finding = Finding(
                repository=REPOSITORY,
                head_sha=HEAD,
                reviewer_execution_id="local-r1-slot1",
                severity=Severity.P2,
                title="Do not synthesize green",
                explanation="A missing check is treated as passing.",
                path="scripts/review.py",
                invariant="CI must be terminal",
            )
            ledger = ReviewLedger(
                repository=REPOSITORY,
                head_sha=HEAD,
                findings=[finding],
            )
            ledger_path.write_text(ledger.model_dump_json(), encoding="utf-8")

            code, _, _ = run_cli(
                [
                    "disposition",
                    "--ledger",
                    str(ledger_path),
                    "--fingerprint",
                    finding.fingerprint,
                    "--disposition",
                    "defer",
                    "--rationale",
                    "Unsupported provider path.",
                ]
            )
            stored = ReviewLedger.model_validate_json(
                ledger_path.read_text(encoding="utf-8")
            )

        self.assertEqual(code, 0)
        self.assertEqual(stored.findings[0].disposition.value, "defer")

    def test_cli_round_trips_evidence_and_existing_issue_deferral(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            item = Finding(
                repository=REPOSITORY,
                head_sha=HEAD,
                reviewer_execution_id="local-r1-slot1",
                severity=Severity.P2,
                title="Guard durable state",
                explanation="A retry can overwrite a newer disposition.",
                path="src/ledger.py",
                invariant="Stale writers cannot replace durable state",
                p2_evidence=P2Evidence(
                    reachability=Reachability.SUPPORTED,
                    impact=Impact.MEANINGFUL,
                    observed_recurrence=1,
                    interface_boundary_risk=True,
                    security_risk=False,
                    data_loss_risk=False,
                    durable_state_risk=True,
                    fix_cost=FixCost.ARCHITECTURAL,
                ),
            )
            ledger_path.write_text(
                ReviewLedger(
                    repository=REPOSITORY,
                    head_sha=HEAD,
                    findings=[item],
                ).model_dump_json(),
                encoding="utf-8",
            )

            code, stdout, _ = run_cli(
                [
                    "disposition",
                    "--ledger",
                    str(ledger_path),
                    "--fingerprint",
                    item.fingerprint,
                    "--disposition",
                    Disposition.DEFERRED_TO_EXISTING_ISSUE.value,
                    "--rationale",
                    "The durable-state redesign already owns this work.",
                    "--deferred-to-issue",
                    "BOU-1234",
                ]
            )

        payload = json.loads(stdout)
        self.assertEqual(code, 0)
        self.assertEqual(payload["findings"][0]["deferred_to_issue"], "BOU-1234")
        self.assertEqual(
            payload["findings"][0]["p2_evidence"]["reachability"],
            "supported",
        )

    def test_settle_returns_ten_when_action_remains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.yaml"
            ledger_path = root / "ledger.json"
            write_policy(policy_path)
            ledger_path.write_text(
                ReviewLedger(repository=REPOSITORY, head_sha=HEAD).model_dump_json(),
                encoding="utf-8",
            )

            code, stdout, _ = run_cli(
                [
                    "settle",
                    "--policy",
                    str(policy_path),
                    "--ledger",
                    str(ledger_path),
                ]
            )

        self.assertEqual(code, 10)
        self.assertFalse(json.loads(stdout)["settled"])

    def test_malformed_input_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "policy.yaml"
            policy_path.write_text("not: [valid", encoding="utf-8")

            code, _, stderr = run_cli(
                [
                    "slots",
                    "--policy",
                    str(policy_path),
                    "--stage",
                    "local",
                    "--round-number",
                    "1",
                ]
            )

        self.assertEqual(code, 2)
        self.assertIn("error:", stderr)

    def test_reproduction_and_verification_commands_update_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "ledger.json"
            item = Finding(
                repository=REPOSITORY,
                head_sha=HEAD,
                reviewer_execution_id="local-r1-slot1",
                severity=Severity.P2,
                title="Do not synthesize green",
                explanation="A missing check is treated as passing.",
                path="scripts/review.py",
                invariant="CI must be terminal",
            )
            ledger_path.write_text(
                ReviewLedger(
                    repository=REPOSITORY,
                    head_sha=HEAD,
                    findings=[item],
                ).model_dump_json(),
                encoding="utf-8",
            )

            proof_code, _, _ = run_cli(
                [
                    "reproduction",
                    "--ledger",
                    str(ledger_path),
                    "--fingerprint",
                    item.fingerprint,
                    "--reproduction",
                    "Missing required check returns clean.",
                ]
            )
            verify_code, _, _ = run_cli(
                [
                    "verification",
                    "--ledger",
                    str(ledger_path),
                    "--fingerprint",
                    item.fingerprint,
                    "--passed",
                    "true",
                ]
            )
            stored = ReviewLedger.model_validate_json(
                ledger_path.read_text(encoding="utf-8")
            )

        self.assertEqual(proof_code, 0)
        self.assertEqual(verify_code, 0)
        self.assertEqual(
            stored.findings[0].reproduction,
            "Missing required check returns clean.",
        )
        self.assertTrue(stored.findings[0].verification_passed)

    def test_submit_waits_for_interprocess_ledger_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger_path = root / "ledger.json"
            result_path = root / "result.json"
            result_path.write_text(
                ReviewResult(
                    repository=REPOSITORY,
                    head_sha=HEAD,
                    stage=ReviewStage.LOCAL,
                    round_number=1,
                    slot_number=1,
                    reviewer_execution_id="local-r1-slot1",
                ).model_dump_json(),
                encoding="utf-8",
            )
            command = [
                sys.executable,
                "-m",
                "agent_review_coordinator.cli",
                "submit",
                "--ledger",
                str(ledger_path),
                "--repository",
                REPOSITORY,
                "--head-sha",
                HEAD,
                "--delivery-id",
                DELIVERY_ID,
                "--review-charter-version",
                REVIEW_CHARTER_VERSION,
                "--result",
                str(result_path),
            ]

            with _ledger_lock(ledger_path):
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                time.sleep(0.2)
                self.assertIsNone(process.poll())

            _, stderr = process.communicate(timeout=5)

        self.assertEqual(process.returncode, 0, stderr)


if __name__ == "__main__":
    unittest.main()
