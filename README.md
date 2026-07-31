# Agent Review Coordinator

Provider-neutral coordination and settlement for agentic code review.

The coordinator defines review topology, findings, dispositions, and settlement.
It does not choose reviewer providers, call GitHub, modify code, or write to an
issue tracker.

## Policy

Reviewer topology is declarative. This requests two independent local reviewer
executions without requiring any particular provider:

```yaml
version: 1
review:
  local:
    reviewer_count: 2
    required_results: 2
    distinct_executions: true
    distinct_providers: false
    max_generation_rounds: 2
  backstop:
    reviewer_count: 1
    required_results: 1
    trigger: new_head_sha
settlement:
  p1: address
  p2: evaluate
  automatic_tracker_writes: false
```

An adapter may fill those slots with Codex, Claude, Gemini, multiple independent
executions of the same provider, or another reviewer. Set
`distinct_providers: true` when provider diversity is itself required.

## Protocol

Integrations create a `ReviewLedger` for an immutable repository and head SHA,
submit versioned `ReviewResult` documents, record explicit finding dispositions,
and call `evaluate`. Findings from older heads remain available for audit but do
not participate in current settlement.

The contract has two independent axes:

1. **Review requirements** describe which independent responsibilities must be
   filled. A requirement has `schema_version`, `slot`, `required`, and an
   optional `provider_constraint`. Constraints are absent by default; slots are
   responsibilities, not model identities.
2. **Finding settlement** describes what happened to each stable finding.
   Reports normalize outcomes to `fixed`, `declined_with_rationale`,
   `deferred_to_existing_issue`, or `unresolved`.

P0 and P1 findings block until fixed and verified, identified as duplicates, or
rejected with evidence. P3 is optional cleanup and does not block. P2 findings
record supported reachability, impact, observed recurrence, interface/security/
data-loss/durable-state boundaries, and fix cost. Reachable or meaningful
findings, recurring failures, boundary risks, and cheap interface defenses
require a fix or an explicit deferral to existing work. Unsupported,
unreachable, low-impact findings whose fix requires disproportionate
architecture may be declined with rationale.

Submitting identical reviewer output is idempotent. It neither consumes another
stored run nor creates another finding. A severity promotion or changed evidence
on the exact head reopens that finding; a provider rerun with no new evidence
does not reset convergence. Review-generation limits never waive a known
blocking finding, and no disposition creates tracker work.

The CLI exposes the same JSON contract:

```bash
agent-review-coordinator slots \
  --policy review-policy.yaml \
  --stage local \
  --round-number 1

agent-review-coordinator requirements \
  --policy review-policy.yaml \
  --stage local

agent-review-coordinator submit \
  --ledger review-ledger.json \
  --repository Boundless-Studios/gaia-free \
  --head-sha "$COMMIT_SHA" \
  --result local-review-result.json

agent-review-coordinator disposition \
  --ledger review-ledger.json \
  --fingerprint "$FINGERPRINT" \
  --disposition deferred_to_existing_issue \
  --rationale "The durable-state redesign already owns this work." \
  --deferred-to-issue BOU-1234

agent-review-coordinator reproduction \
  --ledger review-ledger.json \
  --fingerprint "$FINGERPRINT" \
  --reproduction "Missing required check returns a clean result."

agent-review-coordinator verification \
  --ledger review-ledger.json \
  --fingerprint "$FINGERPRINT" \
  --passed true

agent-review-coordinator settle \
  --policy review-policy.yaml \
  --ledger review-ledger.json
```

`settle` exits `0` when settled, `10` when review work or evaluation remains, and
`2` for invalid input. Ledger mutations use a repository-local advisory lock and
atomic replacement so independent reviewer processes cannot overwrite one
another.
