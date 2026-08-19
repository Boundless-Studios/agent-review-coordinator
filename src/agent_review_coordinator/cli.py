"""JSON command-line interface for review coordination."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import sys
import tempfile
from pathlib import Path

import yaml

from .findings import Disposition, FixCost, Impact, P2Evidence, Reachability
from .ledger import (
    ArchitectureDecision,
    ArchitectureDecisionKind,
    ReviewLedger,
    ReviewResult,
)
from .policy import ReviewPolicy, ReviewStage
from .settlement import evaluate


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-review-coordinator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    slots = subparsers.add_parser("slots")
    slots.add_argument("--policy", type=Path, required=True)
    slots.add_argument(
        "--stage", choices=[item.value for item in ReviewStage], required=True
    )
    slots.add_argument("--round-number", type=int, required=True)

    requirements = subparsers.add_parser("requirements")
    requirements.add_argument("--policy", type=Path, required=True)
    requirements.add_argument(
        "--stage",
        choices=[item.value for item in ReviewStage],
        required=True,
    )

    submit = subparsers.add_parser("submit")
    submit.add_argument("--ledger", type=Path, required=True)
    submit.add_argument("--repository", required=True)
    submit.add_argument("--head-sha", required=True)
    submit.add_argument("--delivery-id", required=True)
    submit.add_argument("--review-charter-version", required=True)
    submit.add_argument("--result", type=Path, required=True)

    disposition = subparsers.add_parser("disposition")
    disposition.add_argument("--ledger", type=Path, required=True)
    disposition.add_argument("--fingerprint", required=True)
    disposition.add_argument(
        "--disposition",
        choices=[item.value for item in Disposition],
        required=True,
    )
    disposition.add_argument("--rationale", required=True)
    disposition.add_argument("--evidence")
    disposition.add_argument("--duplicate-of")
    disposition.add_argument("--deferred-to-issue")
    # P2Evidence is frozen and forbids extras, so it is all-or-nothing: the
    # risk flags have no defaults to fall back on, and store_true alone cannot
    # tell "not supplied" from "supplied as false". Without these flags the
    # block was reachable only from reviewer-submitted findings, which left
    # every disposition that depends on it unsettleable in practice.
    disposition.add_argument(
        "--reachability", choices=[item.value for item in Reachability]
    )
    disposition.add_argument("--impact", choices=[item.value for item in Impact])
    disposition.add_argument("--observed-recurrence", type=int)
    disposition.add_argument("--fix-cost", choices=[item.value for item in FixCost])
    disposition.add_argument("--interface-boundary-risk", choices=["true", "false"])
    disposition.add_argument("--security-risk", choices=["true", "false"])
    disposition.add_argument("--data-loss-risk", choices=["true", "false"])
    disposition.add_argument("--durable-state-risk", choices=["true", "false"])

    reproduction = subparsers.add_parser("reproduction")
    reproduction.add_argument("--ledger", type=Path, required=True)
    reproduction.add_argument("--fingerprint", required=True)
    reproduction.add_argument("--reproduction", required=True)

    verification = subparsers.add_parser("verification")
    verification.add_argument("--ledger", type=Path, required=True)
    verification.add_argument("--fingerprint", required=True)
    verification.add_argument("--passed", choices=["true", "false"], required=True)

    architecture_decision = subparsers.add_parser("architecture-decision")
    architecture_decision.add_argument("--ledger", type=Path, required=True)
    architecture_decision.add_argument("--lineage-id", required=True)
    architecture_decision.add_argument(
        "--decision",
        choices=[item.value for item in ArchitectureDecisionKind],
        required=True,
    )
    architecture_decision.add_argument("--rationale", required=True)
    architecture_decision.add_argument("--decided-by", required=True)

    settle = subparsers.add_parser("settle")
    settle.add_argument("--policy", type=Path, required=True)
    settle.add_argument("--ledger", type=Path, required=True)
    return parser


def _load_policy(path: Path) -> ReviewPolicy:
    return ReviewPolicy.from_yaml(path.read_text(encoding="utf-8"))


def _load_ledger(path: Path) -> ReviewLedger:
    return ReviewLedger.model_validate_json(path.read_text(encoding="utf-8"))


@contextlib.contextmanager
def _ledger_lock(path: Path):
    """Serialize ledger read-modify-write operations across processes."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f"{path.name}.lock")
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _write_ledger(path: Path, ledger: ReviewLedger) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(ledger.model_dump_json(indent=2))
            handle.write("\n")
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _slots(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    slots = policy.slots_for(
        stage=ReviewStage(args.stage),
        round_number=args.round_number,
    )
    _print_json([slot.model_dump(mode="json") for slot in slots])
    return 0


def _requirements(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)
    requirements = policy.requirements_for(stage=ReviewStage(args.stage))
    _print_json(
        [
            requirement.model_dump(mode="json", exclude_none=True)
            for requirement in requirements
        ]
    )
    return 0


def _submit(args: argparse.Namespace) -> int:
    result = ReviewResult.model_validate_json(args.result.read_text(encoding="utf-8"))
    with _ledger_lock(args.ledger):
        if args.ledger.exists():
            ledger = _load_ledger(args.ledger)
            if (
                ledger.repository != args.repository
                or ledger.head_sha != args.head_sha
                or ledger.delivery_id != args.delivery_id
                or ledger.review_charter_version != args.review_charter_version
            ):
                raise ValueError(
                    "ledger identity does not match repository, head SHA, delivery ID, "
                    "and review charter version"
                )
        else:
            ledger = ReviewLedger(
                repository=args.repository,
                head_sha=args.head_sha,
                delivery_id=args.delivery_id,
                review_charter_version=args.review_charter_version,
            )
        ledger.submit(result)
        _write_ledger(args.ledger, ledger)
    _print_json(ledger.model_dump(mode="json"))
    return 0


_P2_EVIDENCE_FLAGS = (
    "reachability",
    "impact",
    "observed_recurrence",
    "fix_cost",
    "interface_boundary_risk",
    "security_risk",
    "data_loss_risk",
    "durable_state_risk",
)


def _p2_evidence(args: argparse.Namespace) -> P2Evidence | None:
    """Build the decision-input block, or refuse a half-specified one."""

    supplied = [name for name in _P2_EVIDENCE_FLAGS if getattr(args, name) is not None]
    if not supplied:
        return None
    missing = [name for name in _P2_EVIDENCE_FLAGS if name not in supplied]
    if missing:
        raise ValueError(
            "p2 evidence is all-or-nothing; missing "
            + ", ".join(f"--{name.replace('_', '-')}" for name in missing)
        )
    return P2Evidence(
        reachability=Reachability(args.reachability),
        impact=Impact(args.impact),
        observed_recurrence=args.observed_recurrence,
        fix_cost=FixCost(args.fix_cost),
        interface_boundary_risk=args.interface_boundary_risk == "true",
        security_risk=args.security_risk == "true",
        data_loss_risk=args.data_loss_risk == "true",
        durable_state_risk=args.durable_state_risk == "true",
    )


def _disposition(args: argparse.Namespace) -> int:
    p2_evidence = _p2_evidence(args)
    with _ledger_lock(args.ledger):
        ledger = _load_ledger(args.ledger)
        ledger.record_disposition(
            fingerprint=args.fingerprint,
            disposition=Disposition(args.disposition),
            rationale=args.rationale,
            evidence=args.evidence,
            duplicate_of=args.duplicate_of,
            deferred_to_issue=args.deferred_to_issue,
            p2_evidence=p2_evidence,
        )
        _write_ledger(args.ledger, ledger)
    _print_json(ledger.model_dump(mode="json"))
    return 0


def _reproduction(args: argparse.Namespace) -> int:
    with _ledger_lock(args.ledger):
        ledger = _load_ledger(args.ledger)
        ledger.record_reproduction(
            fingerprint=args.fingerprint,
            reproduction=args.reproduction,
        )
        _write_ledger(args.ledger, ledger)
    _print_json(ledger.model_dump(mode="json"))
    return 0


def _verification(args: argparse.Namespace) -> int:
    with _ledger_lock(args.ledger):
        ledger = _load_ledger(args.ledger)
        ledger.record_verification(
            fingerprint=args.fingerprint,
            passed=args.passed == "true",
        )
        _write_ledger(args.ledger, ledger)
    _print_json(ledger.model_dump(mode="json"))
    return 0


def _architecture_decision(args: argparse.Namespace) -> int:
    with _ledger_lock(args.ledger):
        ledger = _load_ledger(args.ledger)
        ledger.record_architecture_decision(
            ArchitectureDecision(
                repository=ledger.repository,
                delivery_id=ledger.delivery_id,
                review_charter_version=ledger.review_charter_version,
                lineage_id=args.lineage_id,
                decision=ArchitectureDecisionKind(args.decision),
                rationale=args.rationale,
                decided_by=args.decided_by,
            )
        )
        _write_ledger(args.ledger, ledger)
    _print_json(ledger.model_dump(mode="json"))
    return 0


def _settle(args: argparse.Namespace) -> int:
    report = evaluate(
        policy=_load_policy(args.policy), ledger=_load_ledger(args.ledger)
    )
    _print_json(report.model_dump(mode="json"))
    return 0 if report.settled else 10


def main(argv: list[str] | None = None) -> int:
    """Run one coordinator command and return a process exit code."""

    try:
        args = _parser().parse_args(argv)
        commands = {
            "slots": _slots,
            "requirements": _requirements,
            "submit": _submit,
            "disposition": _disposition,
            "reproduction": _reproduction,
            "verification": _verification,
            "architecture-decision": _architecture_decision,
            "settle": _settle,
        }
        return commands[args.command](args)
    except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
