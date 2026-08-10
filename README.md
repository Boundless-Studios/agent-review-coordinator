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

Integrations create a protocol-v2 `ReviewLedger` for one delivery identity: a
repository, `delivery_id`, and `review_charter_version`. The ledger's `head_sha`
advances with the delivery. Integrations submit versioned `ReviewResult`
documents, record explicit finding dispositions, and call `evaluate`. Findings
from older heads remain available for audit but do not participate in current
settlement.

The contract has two independent axes:

1. **Review requirements** describe which independent responsibilities must be
   filled. A requirement has `schema_version`, `slot`, `required`, and an
   optional `provider_constraint`. Constraints are absent by default; slots are
   responsibilities, not model identities. When policy requires provider
   diversity, every required slot carries `provider_constraint: distinct`.
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

Review generation rounds are cumulative across every head in one delivery
ledger. A round consumes budget only after its required slot quorum completes;
reusing a completed round number on a descendant head does not create another
generation. With `max_generation_rounds: 2`, completed rounds 1 and 2 exhaust
full-review generation for the delivery.

After the final generation, an adapter may advance to a descendant head without
inventing another reviewer result. It records a typed `HeadAttestation` that
references a head with completed local quorum, the exact descendant head, a
delta SHA-256, and concrete evidence. The adapter remains responsible for
proving Git ancestry and computing the diff hash. The coordinator accepts the
attestation only for an exhausted delivery and uses it solely for local quorum;
current-head backstop review and unresolved P0/P1 findings remain blocking.

Findings also carry a snapshot-independent `lineage_id`. When one lineage is
observed in both allowed generations or on three distinct heads, settlement
returns `architecture_reevaluation_required` once. Automated fix/review cycling
must stop until an `ArchitectureDecision` records `core_fix_planned`,
`explicitly_deferred`, or `rejected`, with a nonempty actor and rationale. A new
delivery budget is valid only for explicit core replanning, never merely because
the head changed.

CLI integrations record that terminal choice through the same locked, atomic
ledger mutation path as dispositions and verification:

```bash
agent-review-coordinator architecture-decision \
  --ledger .gaia/review-ledger.json \
  --lineage-id <LINEAGE_ID> \
  --decision explicitly_deferred \
  --rationale "The lifecycle redesign is outside this bounded delivery." \
  --decided-by "human:<OWNER>"
```

Retrying the same provider and slot without new evidence is idempotent even when
the adapter assigns a new execution ID or review round. It neither consumes
another stored run nor creates another finding. Evidence merges monotonically:
severity and structured risk signals may strengthen, while text rephrasing and
weaker evidence cannot overwrite the canonical record or reset convergence. Use
`evidence_artifacts` with a stable `key`, `kind`, and `summary` when a later run
has genuinely new evidence: a new key is retained and reopens the finding,
while rephrasing the summary for an existing key is idempotent. Legacy
disposition values remain readable but follow the same P2-evidence policy.
At the final completed local generation, remaining P2 findings are recorded as
`Disposition.DEFER` with a `review_budget_exhausted` audit rationale, even when
their evidence would otherwise request a fix or proof. P0 and P1 findings are
never auto-disposed and remain blocking. No disposition creates tracker work or
requires an existing tracker issue.

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
  --delivery-id "Boundless-Studios/gaia-free:feature-branch:base-sha" \
  --review-charter-version "gaia-v1" \
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
