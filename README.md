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

P1 findings always block until fixed and verified or rejected with evidence.
P2 findings must be evaluated as `fix_now`, `prove_first`, `defer`, `reject`,
`duplicate`, `stale`, or `wrong_owner`. Review-generation limits never waive a
known P1, and no disposition creates tracker work.

The CLI exposes the same JSON contract:

```bash
agent-review-coordinator slots \
  --policy review-policy.yaml \
  --stage local \
  --round-number 1

agent-review-coordinator submit \
  --ledger review-ledger.json \
  --repository Boundless-Studios/gaia-free \
  --head-sha "$COMMIT_SHA" \
  --result local-review-result.json

agent-review-coordinator disposition \
  --ledger review-ledger.json \
  --fingerprint "$FINGERPRINT" \
  --disposition defer \
  --rationale "Unsupported configuration with no observed occurrence."

agent-review-coordinator settle \
  --policy review-policy.yaml \
  --ledger review-ledger.json
```

`settle` exits `0` when settled, `10` when review work or evaluation remains, and
`2` for invalid input.
