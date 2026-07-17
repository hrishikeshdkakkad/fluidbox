# Session brief — product positioning, governance, ICP & GTM

> **Date:** 2026-07-13  
> **Type:** product / strategy (not an implementation phase)  
> **Scope:** Public tryout & BYOK reality; X marketing direction; governance mental model; competitive gap vs Claude/Codex; ideal users; “engineers don’t care about governance” reframe  
> **Source of truth for architecture remains:** [`PLAN.md`](../../PLAN.md), [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md)

---

## 1. Why this session

Internalize fluidbox as an **infra / control-plane** offering (not “another coding agent”), so marketing, ICP, and product claims stay honest and sharp. Topics covered:

1. What a public deploy + BYOK tryout would look like today  
2. How to market heavily on X  
3. What governance / policy mean and why they exist  
4. What Claude Agent SDK & Codex *do* ship vs what they leave open  
5. Who perfect users are  
6. How to reconcile “engineers just want to get stuff done” with a governance product  

---

## 2. Product truth (one page)

**fluidbox** is an open-source **control plane** that runs AI coding agents in governed, disposable sandboxes: frozen `RunSpec`, policy gate, human approvals (or autonomous fallbacks), credential inversion, append-only redacted ledger, budgets, triggers/schedules/GitHub fan-out. Harnesses (Claude Agent SDK, Codex) are **workloads**; logic lives in Rust; dashboard is presentation-only.

| Layer | Owner |
|-------|--------|
| Model intelligence | Anthropic / OpenAI |
| Agent harness / loop | Claude Code/SDK · Codex CLI/app-server |
| OS / process isolation | Vendor sandboxes + fluidbox Docker (MicroVM later) |
| **Control plane / governance** | **fluidbox** |

**Not ready as multi-tenant public SaaS.** Ready as **single-tenant self-host** (operator brings keys). Schema is multi-tenant-ready (`tenant_id`); runtime is one default tenant + admin token.

---

## 3. Public deploy + BYOK (session findings)

### 3.1 Auth & tenancy today

- Single `FLUIDBOX_ADMIN_TOKEN`; dashboard injects it server-side  
- No user accounts, signup, or SSO/RBAC (roadmap)  
- One shared admin surface = co-admin for anyone who can reach it  

### 3.2 LLM keys today

| Location | Role |
|----------|------|
| LiteLLM container env | Real `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` (operator-level) |
| Rust server | `LITELLM_MASTER_KEY` only (or Anthropic key in direct-fallback mode) |
| Sandbox | Fake key = **session token** → `/internal/llm` facade → budget stop → upstream |
| Dashboard Settings | Health + security copy only — **no BYOK UI** |
| DB seal (`seal.rs`) | Integration/OAuth/GitHub secrets — **not** Anthropic/OpenAI operator keys |

### 3.3 Two “public” products (do not mix)

| Path | Experience | Key guarantee |
|------|------------|---------------|
| **A. Self-host tryout** (matches product today) | Clone/compose → user puts keys in *their* env → full single-tenant admin | “We never receive your keys” |
| **B. Hosted multi-user BYOK** | Not implemented; needs identity, tenancy, per-user key bind on facade | Must design custody deliberately |

**Do not** put today’s stack on a public URL as multi-user demo without gates (shared admin, shared keys, shared DB).

### 3.4 “We don’t store keys” — ranked claims

1. **Strongest (self-host):** keys never leave user’s machine/VPS  
2. **Strongest (hosted BYOK, if built):** memory-only, session-scoped keys; never Postgres/RunSpec/logs; evict on terminal/TTL/restart  
3. **Weaker:** AEAD-sealed at rest (honest “encrypted custody,” not “we don’t store”)  
4. **Impossible for this architecture:** keys never touch servers if facade must call providers on user’s behalf  

Hosted BYOK should **not** reuse long-lived LiteLLM `os.environ` operator keys for strangers.

---

## 4. Governance mental model (internalize)

### 4.1 Definitions

| Term | Meaning in fluidbox |
|------|---------------------|
| **Governance** | Full regime: who may run, what’s frozen, what’s allowed, who holds secrets, what’s recorded, spend limits |
| **Policy** | Versioned YAML rulebook evaluated **per tool call** → allow / deny / approve |
| **Capability** | Tools that *exist* for the run (attached bundles) |
| **Containment** | What is *impossible* (sandbox, egress, no real secrets inside) |
| **RunSpec** | Immutable constitution of *this* run (policy snapshot, pins, budgets, autonomy, …) |
| **Autonomy** | Who answers “approve?” — human vs policy fallback — **never** whether the gate runs |
| **Ledger** | Append-only redacted audit (decisions, digests, usage, cost — not raw prompts/secrets) |
| **Credential inversion** | Real credentials stay control-plane-side; sandbox holds session token only |

### 4.2 Load-bearing invariant

**Capability ≠ permission ≠ containment.**  
Weakening one layer must not silently kill the others.

### 4.3 Why governance is required here

Coding agents **act** (shell, edit, APIs, PRs). Without a control plane:

- Security: keys + shell adjacent to agent process  
- Safety: wrong-but-confident destructive actions  
- Accountability: no trustworthy “what was decided?”  
- Economics: runaway token/cost loops  

System prompts are suggestions. **Policy is enforced.** Vendor “permission modes” are harness-local UX, not a multi-entry ops plane.

### 4.4 Autonomous ≠ ungoverned

- Supervised: human answers approve  
- Autonomous: policy fallback (default deny) answers  
- Gate + ledger always on; never SDK `bypassPermissions` as the product model  

### 4.5 Tool-call decision order (simplified)

```
budget → frozen capability set → trust tier (e.g. fork PR read-only)
  → policy → approval / autonomy rewrite → execute → ledger
```

---

## 5. Competitive gap: Claude Agent SDK & Codex

### 5.1 What they *do* offer (be fair)

**Claude Code / Agent SDK**

- Permission modes (`default`, `acceptEdits`, `plan`, `auto`, `dontAsk`, `bypassPermissions`)  
- Allow/deny rules (incl. org-managed settings)  
- Agent SDK `canUseTool` + hooks (`PreToolUse`, etc.)  
- OS-level sandbox layers for tools  
- Hosting/secure-deployment guides that push isolation & credential care onto **you**  
- Product-side cost/analytics/gateway spend (Claude as product)  

**Codex**

- Explicit axes: **sandbox mode** (what’s possible) vs **approval policy** (when to ask)  
- Defaults: workspace-write, network off; optional network proxy allowlists  
- Cloud: managed containers; setup vs agent phase; secrets often setup-only  
- Headless flags (`approval_policy=never`, `danger-full-access` / YOLO for disposable envs)  
- Auto-review / enterprise managed config in their ecosystem  

### 5.2 What they do *not* offer (infra gap = fluidbox)

| Need | Vendors | fluidbox |
|------|---------|----------|
| Harness-agnostic policy | ❌ product-specific | ✅ one gate, canonical tools |
| Frozen RunSpec / agent revisions | ❌ | ✅ |
| Autonomous without blinding audit | ⚠️ bypass/YOLO culture | ✅ rewrite-in-engine, both verdicts ledgered |
| Credential inversion (LLM + git + brokered MCP) | ❌ default local keys | ✅ facade + seal + broker |
| Per-run budget stop as control plane | Partial product | ✅ facade + budgets |
| Append-only redacted ledger as SoR | ❌ | ✅ |
| Team approval service + restart-safe idempotency | DIY | ✅ |
| API / cron / webhook → same governed run | Product-bound | ✅ spine |
| Fork-PR hard read-only tier | N/A / product-specific | ✅ |
| Brokered vs sandbox MCP as security model | ❌ | ✅ |
| Self-host full governance stack (MIT control plane) | SDK/CLI pieces | ✅ |

### 5.3 Accurate competitive claim

> Claude and Codex ship powerful **agents** and **local** safety knobs.  
> They do **not** ship a portable **control plane**: frozen run identity, secrets out of the sandbox, one policy across harnesses, multi-entry triggers, redacted ledger as system of record.

**Inaccurate claim (never use):** “They have no security.”

### 5.4 Architecture narrative

```
Claude Agent SDK / Codex  =  how the agent thinks and uses tools
            ▲
            │ runner contract
            │
fluidbox control plane  =  who may run · what is frozen · what is allowed
                           · who holds secrets · what is recorded · spend
```

As infra: **substrate under harnesses**, not a worse Claude Code.

---

## 6. Ideal customers (ICP)

### 6.1 Ranked perfect users (next 90 days)

| Rank | Persona | Why |
|------|---------|-----|
| **1** | **Platform / DevEx engineer** | Installs, operates, standardizes agents org-wide; matches self-host maturity |
| **2** | **Automation owner** (PR bots, cron agents) | Best “aha” for triggers + unattended runs + fan-out |
| **3** | **Security (champion)** | Unlocks trust; rarely installs alone — pair with #1 |
| **4** | **Technical founder / small AI-ops team** | Stars, feedback, content; BYOK self-host |
| **5** | **Regulated enterprise** | Nurture until BYOC / SSO / multi-tenant mature |

### 6.2 Perfect account shape (now)

- ~20–500 eng or a platform team inside larger  
- Agents already in use (Claude and/or Codex)  
- GitHub-centric; Docker OK; self-host OK  
- Trigger: chaos of multi-harness YOLO, security block, first unattended bot, first incident  

**Perfect company quote:**  
> “We’re standardizing how the company runs coding agents. Claude and Codex stay the brains. We need a control plane for policy, secrets, audit, and PR automation.”

### 6.3 Anti-ICP

- Pure vibe-coders optimizing for zero prompts  
- “Which model is smartest?” buyers  
- No-code agent builders  
- Teams with zero agent adoption yet  
- Hosted multi-tenant tourists only  
- Anyone wanting fluidbox to *replace* the model  

### 6.4 Perfect use cases

- Fix failing test under policy + cost stop  
- GitHub PR agent with fork → read-only  
- Scheduled agent with concurrency/missed-run policy  
- Claude + Codex under one ledger  
- Brokered MCP without tokens in the agent  
- Prove what a run was allowed to do last week  

---

## 7. “Engineers don’t care about governance”

### 7.1 Pattern (accept it)

ICs optimize for **task completion**, not system properties.  
Pitching “policy, approvals, audit” sounds like friction.

### 7.2 Reframe

| Don’t sell | Do sell |
|------------|---------|
| Governance platform | Agents you’re **allowed** to leave running |
| Compliance / GRC theater | Keys out of the sandbox; CI/PR green light |
| More interruptions | Safe path silent; only pause on scary calls |
| Abstract ledger | Timeline when stuck + “what happened” when broken |
| Configure first | Run task first; defaults already governing |

**Internal slogan:**

> Governance is the engine.  
> The product is **agents you’re allowed to leave running.**

ICs don’t reject governance — they reject **governance as bureaucracy**. They accept it when it maps to:

- fewer security blocks  
- fewer cost spikes  
- fewer secrets in agent env  
- fewer “what did the bot do?”  
- more unattended runs that finish tickets  

### 7.3 Two-audience messaging

| Audience | Hero message |
|----------|----------------|
| **Problem-solver (IC)** | Ship agent work without babysitting every shell call; keys stay out of the box |
| **Champion (platform / sec / lead)** | One control plane so agents don’t become shadow YOLO infrastructure |

Design for the problem-solver; sell to platform/lead.  
IC is often **user** of a platform install, not **chooser**.

### 7.4 Product implication for defaults

- Strong **seed policy**: allow reads/tests/workspace edits; approve gray; deny exfil  
- Happy path zero-ceremony  
- Timeline UX > compliance dashboard as first impression  

---

## 8. X / marketing direction (summary)

### 8.1 Category frame

Win on: **isolation + governance + credentials + audit + cost**  
Market talks “agent sandboxes”; most stop at isolation.  
Wedge: **sandbox ≠ governance**.

### 8.2 Pitch lines

- Bio: *OSS control plane for AI coding agents — policy · approvals · sandboxes · audit. Keys never enter the sandbox.*  
- Accurate competitive: harnesses = brains; fluidbox = control plane  
- CTA (90 days): **self-host / Docker tryout + GitHub**, not fake multi-tenant SaaS  

### 8.3 Content pillars

| Pillar | Intent |
|--------|--------|
| Problem / fear | Keys + shell; unaccountable agents |
| Mechanism | Credential inversion; RunSpec freeze; gate always on |
| Proof / demo | Timeline, approval pause, cost report |
| OSS / build-in-public | e2e bar, changelog, Rust |
| Newsjack | Reply on sandbox/agent discourse |

### 8.4 Voice

Precise, technical, slightly dry. Teach. Don’t hype. Admit early status. Credit Claude/Codex as harnesses.

### 8.5 Claim hygiene

**Safe:** keys never in sandbox; policy on every tool call; redacted ledger; MIT self-host; Claude + Codex; fork PR read-only.  
**Avoid:** multi-tenant SaaS ready; “keys never touch our servers” on hosted without design; unbreakable sandbox; “replaces Cursor.”

### 8.6 Phased GTM sketch

- Phase 0: handles, pin, 3 demos, compose path solid  
- Phase 1: launch week (category + mechanism + demo + compose CTA)  
- Phase 2: cadence + heavy reply game  
- Phase 3: series on invariants, collabs, user proof  

Full plan discussed in-session; execute against this brief + live metrics (stars, “I tried compose,” quality replies).

---

## 9. Strategic decisions locked this session

1. **Position as infra control plane**, not agent competitor.  
2. **Primary tryout = self-host BYOK**; hosted multi-user is future work.  
3. **ICP primary = Platform/DevEx** (+ automation owners); Sec as champion.  
4. **Market outcomes (unattended, allowed, safe defaults)**; governance is plumbing.  
5. **Compete on layer 4** (governance plane), not model quality.  
6. **Honesty** about single-tenant / early status is a trust asset in OSS/security circles.  

---

## 10. Open follow-ups (not done this session)

- [ ] Hosted BYOK v1 design (auth, memory-only keys, facade bind, demo surface disable list)  
- [ ] 14-day X content calendar with paste-ready copy  
- [ ] One-pager competitive architecture brief for partners/investors  
- [ ] Hero UX/copy pass: “get stuff done” language on README / landing  
- [ ] Design-partner list (10 platform/automation eng)  

---

## 11. Key repo references

| Doc | Role |
|-----|------|
| [`PLAN.md`](../../PLAN.md) | North star, invariants, milestones |
| [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) | Run flow + security model |
| [`docs/guides/policies.md`](../guides/policies.md) | Policy authoring |
| [`README.md`](../../README.md) | Public product + compose tryout |
| [`ROADMAP.md`](../../ROADMAP.md) | Next (Slack, MicroVM BYOC, …) |
| Settings UI copy | Operator-facing security model statements |

---

## 12. One-paragraph summary

fluidbox is the **execution control plane** for coding agents: it freezes what a run is, decides every tool call, keeps secrets out of sandboxes, meters cost, and records a redacted audit trail — across Claude and Codex and multiple entry points. Vendor SDKs/CLIs provide agent intelligence and local permission/sandbox knobs; they do not provide this plane. The product is ready for **self-host operators**, not multi-tenant public SaaS. Perfect users are **platform/DevEx and automation owners** who must make agents work as company infrastructure; pure ICs care about getting work done, so messaging must lead with **unattended, allowed, low-friction agent work**, with governance as the invisible enabler. Market on X as accountable agent infrastructure, with self-host + demos as the funnel.
