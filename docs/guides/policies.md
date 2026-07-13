# Writing policies

A policy is a YAML document evaluated on **every tool call** an agent makes. The verdict is one of `allow`, `deny`, or `approve` (pause for a human). Policies live in the control plane (seeded from [`policies/*.yaml`](../../policies) at boot, managed via the API), and every run **freezes a snapshot** of its policy into the RunSpec — editing a policy only affects future runs, never in-flight ones.

## The document

```yaml
name: default            # must match the API body's `name` on upsert

defaults:
  tool_action: approve   # verdict when NO rule matches; fail-safe = ask a human

budgets:                 # per-run CEILING — revisions/runs may only tighten these
  max_wall_clock_secs: 1800
  max_tokens: 1000000
  max_cost_usd: 2.5
  max_tool_calls: 100

approvals:
  default_ttl_secs: 600  # unanswered approval expires (and denies) after this
  scope: once            # once = re-ask every call | session = approve-once-per-scope-key
  timeout_action: deny

autonomy:
  permitted: true        # false = autonomous runs of this policy are refused (400)
  on_approval_rule: deny # what `approve` becomes when nobody is watching: deny | allow

tools:                   # ORDERED rules; first rule whose `match` hits wins
  - match: ["Read", "Glob", "Grep", "LS"]
    action: allow

  - match: ["Edit", "Write", "MultiEdit"]
    action: allow
    paths:
      allow: ["/workspace/**"]              # outside the allow-set → escalates to approve
      deny: ["**/.env", "**/.git/hooks/**"] # deny always wins, even inside allow

  - match: ["Bash"]
    action: allow
    shell:
      allow_prefixes: ["ls", "pytest", "git status", "git diff"]  # token-boundary matched
      deny_regex: ["rm\\s+-rf\\s+/", "\\bcurl\\b", "\\bwget\\b"]  # checked FIRST, always deny
      on_no_match: approve                  # anything else → ask a human

  - match: ["WebFetch", "WebSearch"]
    action: deny
    risk: "network egress from sandbox"     # becomes the deny reason / approval context

  - match: ["mcp__*"]                       # `*` suffix wildcard on tool names
    action: approve
    on_autonomous: allow                    # per-rule override of autonomy.on_approval_rule
    approval_ttl_secs: 120                  # per-rule approval overrides
    approval_scope: session
```

## Evaluation semantics (what the engine guarantees)

- **First match wins.** Rules are checked top-down; the first rule whose `match` list hits the tool name decides. Order your specific rules above your broad ones.
- **Shell rules:** `deny_regex` is checked before `allow_prefixes` — a deny match is final (`ls && curl evil` is denied even though `ls` is allowed). Prefixes are **token-boundary** matched: `git status` matches `git status -sb` but never `git statusx`. Anything that hits neither gets `on_no_match`.
- **Path rules:** any `deny` glob match is a hard deny. If `allow` globs are set and a touched path falls outside them, the call **escalates to approval** rather than failing the run.
- **Approvals:** `scope: once` re-asks per call; `scope: session` remembers by scope key — for Bash the key is the matched prefix (approving `git push` covers `git push`, not all shell), for other tools the tool name.
- **Autonomy narrows, never widens.** On an autonomous run, an `approve` verdict is rewritten *inside the engine* to `autonomy.on_approval_rule` (or the rule's `on_autonomous` override). `allow` and `deny` verdicts are untouched, an autonomous run can never end up waiting on a human, and the ledger records **both** the original and rewritten verdict. There is no bypass mode: the permission callback stays wired in every autonomy mode.
- **Fork PRs are stricter than any policy.** Runs from untrusted event sources (fork PRs) carry a hard read-only trust tier enforced *above* policy — reads only, no writes/exec/egress, and **no approval can widen it**.

## Managing policies

```bash
# validate without saving (422 with the parse error on bad YAML)
curl -s -X POST localhost:8787/v1/policies/validate \
  -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" -H "content-type: application/json" \
  -d "$(jq -n --rawfile y policies/default.yaml '{yaml: $y}')"

# upsert (bumps the policy version; in-flight runs keep their frozen snapshot)
curl -s -X POST localhost:8787/v1/policies \
  -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" -H "content-type: application/json" \
  -d "$(jq -n --rawfile y policies/default.yaml '{name: "default", yaml: $y}')"

# or push every policies/*.yaml in one go
just policy-sync
```

An agent revision names its policy; the policy's `budgets` are a ceiling the revision and each run may only tighten. Autonomy is chosen per run (`"autonomous": true` on `POST /v1/sessions`) or per trigger subscription — a policy with `autonomy.permitted: false` refuses those outright.

The seed policy ([`policies/default.yaml`](../../policies/default.yaml)) is a good starting point: read-only tools allowed, workspace-scoped writes, a shell classifier derived from observed agent behavior (rationale in its comments), exfil/destructive commands denied, everything else paused for a human. Its exact semantics are pinned by the `seed_policy_semantics` test in `fluidbox-core`.
