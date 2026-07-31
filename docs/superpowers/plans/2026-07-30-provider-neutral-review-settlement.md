# Provider-Neutral Review Settlement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a provider-neutral double-review contract whose settlement rules converge deterministically and whose P2 decisions retain the evidence needed to fix, decline, or defer findings.

**Architecture:** Keep the existing separation between declarative policy, immutable reviewer results, the durable ledger, and pure settlement evaluation. Add explicit versioned requirement and P2-evidence models at the contract boundary, deduplicate identical submissions in the ledger, and expose normalized settlement states without coupling the core to GitHub, Gaia, providers, or issue-tracker writes.

**Tech Stack:** Python 3.11+, Pydantic 2, PyYAML, pytest/unittest, Ruff, uv.

---

## File structure

- `src/agent_review_coordinator/policy.py`: versioned `ReviewRequirement` contract and deterministic provider-neutral slots.
- `src/agent_review_coordinator/findings.py`: P0-P3 severity, structured P2 decision evidence, explicit dispositions, and normalized settlement state.
- `src/agent_review_coordinator/ledger.py`: idempotent review-result submission and evidence-backed disposition validation.
- `src/agent_review_coordinator/settlement.py`: severity policy, convergence, and per-finding settlement-state reporting.
- `src/agent_review_coordinator/__init__.py`: public contract exports.
- `tests/test_policy.py`, `tests/test_findings.py`, `tests/test_ledger.py`, `tests/test_settlement.py`, `tests/test_cli.py`: contract-first behavioral coverage.
- `README.md`: human-readable protocol and JSON examples.

### Task 1: Publish the review-requirement contract

- [ ] Add failing tests in `tests/test_policy.py` proving that two required slots serialize as `ReviewRequirement { schema_version, slot, required, provider_constraint? }`, omit provider constraints by default, optionally express provider diversity, and allow one provider to fill separate executions when diversity is not requested.
- [ ] Run `uv run pytest -q tests/test_policy.py` and confirm failures are caused by the missing `ReviewRequirement` contract.
- [ ] Add the minimal strict Pydantic model and a `requirements_for(stage, round_number)` policy method in `src/agent_review_coordinator/policy.py`; preserve `slots_for` as the execution adapter for the v0.1 API.
- [ ] Run the focused tests and commit the green contract slice.

### Task 2: Make findings carry decision-grade P2 evidence

- [ ] Add failing tests in `tests/test_findings.py` for P0/P3 severities and `P2Evidence` fields covering supported reachability, impact, recurrence, interface-boundary/security/data-loss/durable-state risk, and fix cost.
- [ ] Add failing ledger tests for explicit `declined` and `deferred_to_existing_issue` dispositions, including required rationale and required existing-issue reference.
- [ ] Run the focused tests and confirm the new contract is absent.
- [ ] Implement strict evidence/disposition models in `findings.py` and validation/storage in `ledger.py`; retain existing v0.1 disposition values for wire compatibility.
- [ ] Run focused finding/ledger tests and commit the green evidence slice.

### Task 3: Make repeated review converge

- [ ] Add failing tests in `tests/test_ledger.py` proving an identical resubmission is idempotent, duplicate findings merge contributing execution IDs, severity can promote, and materially new exact-head feedback is retained.
- [ ] Add failing tests in `tests/test_settlement.py` proving two providers or two independent executions can satisfy two slots, while the same execution cannot fill both required responsibilities.
- [ ] Run focused tests and confirm identical submissions currently append redundant results.
- [ ] Add a stable `ReviewResult` submission identity and make `ReviewLedger.submit` ignore exact duplicates without discarding new evidence.
- [ ] Run focused ledger/settlement tests and commit the green convergence slice.

### Task 4: Normalize evidence-based settlement

- [ ] Add failing settlement tests for: P0/P1 blocking; reachable, meaningful, recurrent, boundary-risk, or cheap P2s requiring a fix decision; speculative/unreachable/architectural P2s being declineable with rationale; deferred P2s requiring an existing issue; P3 never blocking; severity promotion; incorrect feedback; and late exact-head feedback.
- [ ] Assert every finding is reported as exactly one of `fixed`, `declined_with_rationale`, `deferred_to_existing_issue`, or `unresolved`.
- [ ] Run `uv run pytest -q tests/test_settlement.py` and confirm failures identify missing policy behavior.
- [ ] Implement the minimal pure settlement mapping in `settlement.py`; do not add provider, GitHub, Gaia, or tracker behavior.
- [ ] Run focused tests and commit the green settlement slice.

### Task 5: Publish and verify the contract

- [ ] Add CLI round-trip coverage in `tests/test_cli.py` for the new JSON fields and settlement states.
- [ ] Update `__init__.py` exports and README examples/policy guidance, explicitly documenting provider neutrality and that adapters—not the core—perform tracker writes.
- [ ] Run `uv run pytest -q`, `uv run ruff check .`, and `uv run ruff format --check .`.
- [ ] Build the package with `uv build`.
- [ ] Push `bou-2711-review-policy`, open one focused PR, address review/CI feedback, and record the PR in the bead and Linear issue.

## Self-review

- Spec coverage: two-slot provider-neutral requirements, duplicate-run convergence, stable fingerprints, P0-P3 policy, explicit P2 evidence/dispositions, exact-head feedback, and one policy/schema PR are each assigned above.
- Placeholder scan: no TBD/TODO/“similar to” implementation placeholders.
- Type consistency: `ReviewRequirement`, `P2Evidence`, `Disposition`, and normalized settlement-state names are introduced once and consumed by ledger, settlement, CLI, and docs.
