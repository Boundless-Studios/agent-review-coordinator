import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from agent_review_coordinator.cli import main
from agent_review_coordinator.findings import Finding, Severity
from agent_review_coordinator.ledger import ReviewLedger, ReviewResult
from agent_review_coordinator.policy import ReviewStage

REPOSITORY = "Boundless-Studios/gaia-free"
HEAD = "d" * 40


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


if __name__ == "__main__":
    unittest.main()
