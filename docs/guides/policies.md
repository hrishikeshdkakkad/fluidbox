# Policies

A policy is evaluated on **every tool call** an agent makes. The verdict is one of `allow`, `deny`, or `approve` (pause for a human). Policies live in the control plane as **append-only versions**: the Governance page is the authoring surface, every publish is an immutable version with an author and a summary, and every run **freezes a snapshot** of its policy's latest version into the RunSpec — editing a policy only affects future runs, never in-flight ones.

## Where policies live

- **The database is the source of truth.** A policy is a stable identity (`policies`) plus an append-only history (`policy_versions`); the latest version governs future runs. History is immutable — the runtime role can only read and append, and "undo" is a *revert*, which publishes the old content forward as a new version.
- **`policies/*.yaml` is a boot seed, nothing more.** A fresh database seeds each file once (`seed_policy_if_absent`); reboots never clobber what you authored in the UI. To change the seed itself, change the YAML **and** the `seed_policy_semantics` test that pins it.
  Seed files are parsed **strictly** — an unknown key is an error, not a dropped field. The consequence is scoped to what is at stake: if the policy does not exist yet the file is its only source and the server **refuses to boot** (naming the file, the key, and the policy); if it already exists the database's versions govern, the file writes nothing, and the server **warns and boots**.
- **YAML survives as an interchange format.** `POST /v1/policies {name, yaml}` imports a document as a new version (idempotent: byte-equal content appends nothing), and every version exports as YAML from `GET /v1/policies/{name}/versions/{n}`.

## Authoring (the Governance page)

`/governance` lists every policy with its latest version and blast radius (agents using it). A policy's page is a **draft editor**:

- **Rules** — ordered, first-match-wins; each rule has tool matchers (`*` suffix wildcards), an action, and optional `paths` / `shell` constraints. The per-tool **matrix** is the fast path: clicking a tool writes an exact-name head rule into the draft.
- **Defaults · Budgets · Approvals · Autonomy · Egress** — flat forms.
- **Publish** — validates server-side (strictly: an unknown field is refused, never silently dropped), requires a summary, and carries the version your draft loaded from — a publish over a moved head is a 409, so two editors can't silently overwrite each other.
- **History** — every version with author, summary, and date; view any version, diff it, revert to it.

New policies are created by **cloning** an existing one (or starting blank) — `POST /v1/policies/clone {name, from?}` — and removed with `DELETE /v1/policies/{name}`, which also removes their history. A delete is refused while **any** agent revision names the policy (including historical revisions, which are immutable); runs are never affected, because each froze its own snapshot.

## The document

```yaml
name: default            # must match the API body's `name` on import

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

- **First match wins.** Rules are checked top-down; the first rule whose `match` list hits the tool name decides. Order your specific rules above your broad ones — a per-tool decision made in the matrix is simply an exact-name rule at the head of the list.
- **Shell rules:** `deny_regex` is checked before `allow_prefixes` — a deny match is final (`ls && curl evil` is denied even though `ls` is allowed). Prefixes are **token-boundary** matched: `git status` matches `git status -sb` but never `git statusx`. Anything that hits neither gets `on_no_match`.
- **Path rules:** any `deny` glob match is a hard deny. If `allow` globs are set and a touched path falls outside them, the call **escalates to approval** rather than failing the run.
- **Approvals:** `scope: once` re-asks per call; `scope: session` remembers by scope key — for Bash the key is the matched prefix (approving `git push` covers `git push`, not all shell), for other tools the tool name.
- **Autonomy narrows, never widens.** On an autonomous run, an `approve` verdict is rewritten *inside the engine* to `autonomy.on_approval_rule` (or the rule's `on_autonomous` override). `allow` and `deny` verdicts are untouched, an autonomous run can never end up waiting on a human, and the ledger records **both** the original and rewritten verdict. There is no bypass mode: the permission callback stays wired in every autonomy mode.
- **Fork PRs are stricter than any policy.** Runs from untrusted event sources (fork PRs) carry a hard read-only trust tier enforced *above* policy — reads only, no writes/exec/egress, and **no approval can widen it**.

## The API

```bash
# validate YAML without saving (strict: an unknown key is a 422 naming it)
curl -s -X POST localhost:8787/v1/policies/validate \
  -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" -H "content-type: application/json" \
  -d "$(jq -n --rawfile y policies/default.yaml '{yaml: $y}')"

# import YAML as a new version (idempotent on identical content)
curl -s -X POST localhost:8787/v1/policies \
  -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" -H "content-type: application/json" \
  -d "$(jq -n --rawfile y policies/default.yaml '{name: "default", yaml: $y}')"

# publish a structured draft (strict parse; base_version guards concurrent editors)
curl -s -X POST localhost:8787/v1/policies/default/publish \
  -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" -H "content-type: application/json" \
  -d '{"content": {...}, "summary": "tighten shell rules", "base_version": 7}'

# history, one version (content + YAML export), revert, clone
curl -s -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" localhost:8787/v1/policies/default
curl -s -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" localhost:8787/v1/policies/default/versions/7
curl -s -X POST localhost:8787/v1/policies/default/revert \
  -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" -H "content-type: application/json" \
  -d '{"version": 7, "base_version": 9}'
curl -s -X POST localhost:8787/v1/policies/clone \
  -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN" -H "content-type: application/json" \
  -d '{"name": "staging", "from": "default"}'

# delete a policy and its history (409 while any agent revision names it)
curl -s -X DELETE localhost:8787/v1/policies/staging \
  -H "authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
```

Policy names are constrained on creation to `a-z A-Z 0-9 . _ -` (1–64 characters, not starting with `.`) because they travel in URLs, and a handful — `validate`, `preview`, `clone` — are reserved by the static `/v1/policies/*` routes.

An agent revision names its policy; the policy's `budgets` are a ceiling the revision and each run may only tighten. Autonomy is chosen per run (`"autonomous": true` on `POST /v1/sessions`) or per trigger subscription — a policy with `autonomy.permitted: false` refuses those outright.

A policy edit moves the **policy** verdict only. Trust tier (fork-PR read-only), budgets, and frozen-capability availability are all enforced above policy in the gate. Edits affect **future** runs only — in-flight runs keep their frozen snapshot, and the version history records who changed what, when, and why.

The seed policy ([`policies/default.yaml`](../../policies/default.yaml)) is a good starting point: read-only tools allowed, workspace-scoped writes, a shell classifier derived from observed agent behavior (rationale in its comments), exfil/destructive commands denied, everything else paused for a human. Its exact semantics are pinned by the `seed_policy_semantics` test in `fluidbox-core`.
