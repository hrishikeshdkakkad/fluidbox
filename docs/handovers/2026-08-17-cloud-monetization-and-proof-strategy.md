# Session brief — funding the hosted cloud, and proving the thing works

> **Date:** 2026-08-17
> **Type:** product / strategy (not an implementation phase)
> **Scope:** how to offer fluidbox as a managed cloud without personally carrying API and infrastructure cost; what evidence actually convinces investors and operators; whether the chicken-and-egg is real
> **Builds on:** [`2026-07-13-product-governance-gtm-session-brief.md`](2026-07-13-product-governance-gtm-session-brief.md) (positioning, ICP, claim hygiene — all still holds)
> **Source of truth for architecture remains:** [`PLAN.md`](../../PLAN.md), [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md)
> **Cost figures come from:** [`../hosted/cloud-cost-model.md`](../hosted/cloud-cost-model.md) (live AWS Pricing API, 2026-08-03)

---

## 1. The question

> *"I want to provide this entire platform also as a managed cloud for users on the web. But API and infra costs are something I cannot support individually. How do I prove its usefulness to investors and people in general? I feel like a chicken-and-egg problem."*

The chicken-and-egg is: **hosted usage proves value → value attracts funding → funding pays for hosting → hosting produces usage.** Every arrow needs the previous one.

The loop is real only if you accept three premises. All three are false for this product:

| Premise | Why it's false here |
|---|---|
| "I must pay for users' model tokens" | You must not. BYOK is *on-thesis* for a credential-inversion product — see §3 |
| "Hosted infra is a large, uncontrollable cost" | It is **$157/mo**, and **95% of that is a fixed floor you chose**, not usage — see §4 |
| "Hosted usage is the evidence" | For infra/security, it is close to the *weakest* evidence available to you — see §6 |

Remove all three and there is no loop. There is a sequencing decision, which is a much easier problem.

---

## 2. The counterintuitive conclusion, stated first

**The multi-tenant hosted cloud you are worried about funding is the product you should build *last*, not first.**

Three offerings are possible. They are ordered here by margin and inversely by risk:

| # | Offering | Who pays infra | Who pays tokens | Your marginal cost | Containment risk | Status |
|---|---|---|---|---|---|---|
| **1** | **Self-host** (today) | Customer | Customer | **$0** | Theirs | ✅ shipped |
| **2** | **BYOC / managed-in-their-account** | Customer | Customer | **~$0** | Theirs, one tenant per deployment | 🔶 Terraform module already scoped in [`PLAN.md`](../../PLAN.md) §7 M2 |
| **3** | **Multi-tenant hosted SaaS** | **You** | **You**, unless BYOK | $157/mo floor + per-run + tokens | **Yours, and shared** | ❌ not built; gated behind [`../hosted/rollout-gates.md`](../hosted/rollout-gates.md) Gates 1–5 |

Offering 3 is the one that costs money, carries the most risk, is least differentiated, and is *hardest to sell to the ICP you already identified*. Platform and DevEx engineers at 20–500-engineer companies — the primary persona in the July brief §6.1 — are frequently forbidden from putting source code and repository credentials into a one-person startup's shared multi-tenant plane. **For your buyer, offering 2 is not a downgrade from offering 3. It is the preferred shape.**

Offering 2 is also the classic monetization for exactly this situation: a solo maintainer with no capital, deep infrastructure, and enterprise-shaped buyers. The customer's AWS account absorbs the compute. The customer's Anthropic account absorbs the tokens. You charge for the control plane, the operator runbook, the upgrade path, and support — all of which you have already written ([`../hosted/cloud-operator-runbook.md`](../hosted/cloud-operator-runbook.md), [`../release/upgrade-and-rollback.md`](../release/upgrade-and-rollback.md)).

**Recommendation:** sell offering 2 now. Build a small, invite-only version of offering 3 as a *demo and onboarding surface*, not as the business.

---

## 3. Cost 1 — model tokens: do not carry this, ever

### 3.1 Where you are today

The facade resolves an upstream credential through exactly three cases
(`crates/fluidbox-server/src/llm_keys.rs`, `KeySource`):

| Variant | Credential presented upstream | Who pays |
|---|---|---|
| `Shared` | `cfg.llm_upstream_key` — one deployment key | **you** |
| `Tenant` | a per-tenant LiteLLM virtual key, minted lazily | **you** (it draws on your provider credential; the virtual key is a *quota*, not a *payer*) |
| `RefuseSsoShared` | none — 503 | n/a |

There is no fourth case. **Today, hosting fluidbox for anyone means buying their tokens.** `FLUIDBOX_LLM_KEY_MODE=tenant` bounds the blast radius; it does not move the bill.

This is the cost that is genuinely unbounded and genuinely unaffordable, and it is the correct thing to be afraid of. It is also the one you can delete outright.

### 3.2 BYOK is not a compromise here — it is the product demonstrating itself

fluidbox's entire thesis is that credentials belong to the control plane and never enter the sandbox. A hosted tier where **the customer's own Anthropic key is sealed under their own tenant DEK, never enters a sandbox, and is metered by a policy gate they can audit** is a stronger security story than any competitor who resells tokens can tell. You would be shipping the marketing claim as the architecture.

It also deletes your worst operational risk. The threat model's denial-of-wallet row, the durable budget reservations (migration 0022), the sole-claimant carve-out you disclosed — all of that exists because model spend is the dangerous variable. **Under BYOK that variable is bounded by someone else's credit card, and every one of those mechanisms keeps working as a courtesy to the customer rather than as a defence of your bank account.**

### 3.3 What building it actually costs

Smaller than it looks, because the seams exist:

| Piece | State today |
|---|---|
| Per-tenant sealed custody with per-tenant DEK + AAD binding | ✅ shipped — 13 `SealFamily` variants, `TenantLlmKey` is already one of them |
| Per-tenant credential resolution at request time | ✅ shipped — `llm_keys.rs` resolves/mints/caches per tenant |
| Direct-to-provider upstream (no LiteLLM in the path) | ✅ shipped — `cfg.llm_upstream_is_anthropic` already switches `x-api-key` vs bearer in `send_upstream` |
| Metering, budgets, reservations, ledger | ✅ shipped and **unchanged** — you still meter, you just don't pay |
| A `SealFamily::TenantProviderKey` + a `KeySource::TenantByok` variant | ❌ **to build** |
| Per-tenant upstream selection (tenant key ⇒ tenant's provider endpoint) | ❌ **to build** |
| Settings UI to paste and rotate the key | ❌ **to build** |

The Claude harness is the cheap path: a tenant-supplied Anthropic key on the direct-Anthropic upstream that already exists. Codex needs OpenAI direct or a LiteLLM key-per-tenant arrangement, and can lag.

> ⚠️ **Custody claim hygiene.** Once you hold the customer's provider key, "we never receive your keys" becomes false for the hosted tier. The honest claim is the July brief's rank 2/3: *sealed under a per-tenant DEK, never written to the RunSpec, ledger, or logs, never present in a sandbox, evictable on demand.* Write that claim before you write the code, and make the settings copy say it.

**This is the single highest-leverage engineering task in this document.** Until it ships, every hosted user is a direct debit against you.

---

## 4. Cost 2 — infrastructure: $157/mo, and 95% of it is a decision, not a consequence

From the live-verified model ([`../hosted/cloud-cost-model.md`](../hosted/cloud-cost-model.md), AWS Pricing API, 2026-08-03, revised for the t4g.large OOM finding):

| Line | $/mo | Scales with users? |
|---|---:|---|
| EKS control plane | 73.00 | **no** |
| System node (1× t4g.large) | 49.06 | **no** |
| ALB hours | 16.43 | **no** |
| Public IPv4 × 3 | 10.95 | **no** |
| EBS 50 GiB, KMS, logs, S3, CloudTrail | ~7.2 | barely |
| Sandbox nodegroup | 0.00 idle → **~2.05** at 5–10 orgs | **yes** |
| **Idle total** | **≈ 157** | |
| **Light use (5–10 orgs)** | **≈ 163** | |

Read the right-hand column. **Going from zero users to ten costs about six dollars a month.** The $149 above it is the price of running an EKS control plane, an always-on node, and an always-on ALB — a deliberate M1 choice, documented as such in the cost model §4, taken so that M1 could deploy *today's unchanged chart* with zero core changes.

That was the correct trade for M1's contract. It is the wrong trade for an alpha with eight invited users.

### 4.1 Three levers, in order of effort

**Lever A — cloud credits. Do this first; it costs an afternoon.** You are already on AWS with a real deployment, real Terraform, and a validated cost model. AWS Activate, Google for Startups, and Azure for Startups all issue credits at levels that cover a $157/mo floor for years. Anthropic and OpenAI both run startup credit programmes; Neon, Vercel, and Fly all have OSS/startup tiers. **A funded credit application converts your entire infrastructure problem into a paperwork problem.** Nothing else in this document has a better effort-to-outcome ratio, and it requires no code and no investor.

**Lever B — don't run EKS for an alpha.** You have a working Docker `ExecutionProvider`. A single VM running the control plane, the dashboard behind Cloudflare (no ALB, no billed IPv4), and Neon's free tier lands in roughly the **$20–60/mo** band. *(Estimate — third-party pricing not verified in this session. Price it before committing, to the same standard as the AWS model.)* The Kubernetes provider is what you promote *to* when Gate 3's capacity numbers demand it, not what you start on.

> ⚠️ **The catch, and it is a real one.** Docker `HostDev` is the default profile and it is **not an egress boundary** — `docs/launch/launch-blockers.md` BLK-03, still open. Running *mutually untrusting strangers'* agents as containers on one shared host means a sandbox escape reaches every tenant's sealed credentials. **This is precisely why §2 recommends invite-only.** With named design partners whose identities you know, the threat model is "my eight pilot customers," not "the internet," and cheap infra is defensible. With open signup it is not, and no amount of cost saving makes it so. Do not cross that line silently.

**Lever C — pull a slice of the M4 serverless-core work forward.** The cost model §4 already names the ~$13/mo scale-to-zero alternative and defers it to M4. You do not need all of M4; you need "don't pay $73/mo for an idle Kubernetes control plane." Lever B is the cheap approximation of the same idea.

---

## 5. Cost 3 — per-run compute: this is the only thing you should price on

Sandbox spend at light use is ~$2/mo, scale-to-zero by design, bounded by a global `ResourceQuota` and per-run wall-clock budgets. It is genuinely marginal and genuinely small.

**That makes pricing easy, because your marginal cost per customer under BYOK + BYOC is approximately zero.** You are not reselling compute or tokens. You are selling governance, and governance has software margins.

### Suggested shape

| Tier | Price | What it is |
|---|---|---|
| **Self-host** | Free (MIT) | The funnel. Never cripple it — it is the credibility asset |
| **Design-partner pilot** | **$500/mo, 3 months, invoiced** | Managed deployment + a private channel with you + roadmap influence. See §7 |
| **Cloud (Team)** | ~$25–40/user/mo, org floor ~$1k/mo | Invite-only hosted, BYOK. The demo surface, not the business |
| **BYOC / managed-in-account** | **$2k–5k/mo** | Runs in *their* AWS. Offering 2 in §2. This is the money |

> **Do not build a free hosted tier.** For an infrastructure product it gives you cost you cannot bear, users who will not tell you the truth because they have not paid for the right to complain, and a signal that no investor counts. Counterintuitively, **$500/mo is easier to close than $50/mo** with a platform lead: $50 is too small to justify a procurement conversation, while $500 fits on a corporate card and buys their attention.

---

## 6. Proving it works — the part that is not actually blocked

The chicken-and-egg bites only if hosted usage is the sole evidence. For an infrastructure and security product it is close to the *weakest* evidence you can present. Here is what is stronger, ranked, all available at approximately zero cost.

### 6.1 The nonce demonstration — your single most convincing artifact

Buried in `docs/launch/launch-blockers.md` BLK-01 is this: you configured a policy requiring human approval before shell, ran a live agent, and it returned the SHA-256 of a nonce minted seconds earlier — **proving `Bash` executed while the ledger recorded zero decisions.** You then traced it to `canUseTool` being the ask-path only, fixed it with a mandatory `PreToolUse` hook, and added `GateWitness` to abort runs where a result arrives for a call nothing decided.

That is the entire product thesis, demonstrated rather than asserted, with an unfabricatable proof:

> "Here is a policy that says *ask before running shell*. Here is the setup nearly everyone uses. Here is the agent running shell anyway, with an audit log that shows nothing happened — a log indistinguishable from a run that behaved. Here is the same task under fluidbox."

Sixty seconds. No hosted infrastructure. It converts governance from an abstract virtue into a demonstrated failure the viewer recognises in their own stack. **Cut this video and put it at the top of the README.** Right now it is a table row in a go/no-go document, which is the wrong home for the best asset you have.

### 6.2 The `just demo` path

You already built a no-key, five-minute, deterministic replay through the real gate and a real sandbox. That is a genuinely rare piece of onboarding engineering and it costs you nothing per user. Instrument its completion rate however you can without telemetry (issues, Discussions, asking directly in the beta cohort) and treat it as your top-of-funnel metric.

### 6.3 Depth over breadth in design partners

**Five companies running fluidbox in production on their own infrastructure, with named platform engineers who will take a reference call, beats five hundred free-tier signups** — for this category, decisively. That evidence requires you to host nothing. It is the evidence [`../hosted/rollout-gates.md`](../hosted/rollout-gates.md) Gate 2 already specifies, and every number Gate 2 asks for (observed concurrency, connections per user, per-run cost p50/p95, approval latency p95) is a slide in a fundraising deck.

Your beta apparatus — `docs/beta/` participant guide, facilitator guide, metrics scorecard, triage process — is already built for exactly this. Run it.

### 6.4 What investors actually index on for infrastructure

Not MAU. In rough order:

1. **Why now.** Agents are moving from suggesting code to *acting on real systems, unattended, inside organisations*. That transition creates the control-plane need. This is a strong and honest timing story, and it is currently the best one you have.
2. **Technical depth that is hard to replicate.** The repository is the argument: RLS tenant isolation with a documented bypass inventory, KMS envelope custody with bidirectional retirement gates, credential inversion across LLM/git/MCP, durable execution claims, audience-scoped session tokens. This is multi-year work.
3. **Evidence of unusual engineering judgement.** `docs/launch/launch-blockers.md` is, unexpectedly, a better fundraising artifact than a metrics dashboard. A founder who finds their own P0, reproduces it with an unfabricatable proof, writes four acceptance tests so a stranger can verify the fix without trusting them, and then *ships the document publicly* — that is rare, and it is exactly the disposition a buyer needs from whoever operates their agent control plane. Do not hide it. Lead with it.
4. **A wedge that is sold, not a platform that is adopted.** "Governed agent control plane" is a category. "Your fork-PR bot cannot exfiltrate your secrets and you can prove what it did" is a purchase order.
5. **Paying design partners.** Three logos at $500/mo is $18k ARR and, more importantly, proof that the pain has a budget line.

### 6.5 The three questions you will be asked, and are not yet ready for

Prepare written answers before any investor conversation.

| Question | Current honest answer | Work needed |
|---|---|---|
| **"Won't Anthropic/OpenAI/GitHub just build this?"** | Partly, and product-locally — org-managed settings, sandbox modes, approval policies. What they structurally will not build is a *harness-agnostic* plane spanning Claude and Codex, with self-hostable audit as system of record and one policy across API/cron/webhook/PR entry points. A vendor's control plane governs a vendor's agent | Turn July brief §5.2 into a one-page written answer. This is your hardest question |
| **"What happens if you get hit by a bus?"** | MIT licence, no lock-in, the customer's data is in their Postgres. But there is one maintainer | Bus-factor answer must be *structural* (OSS + BYOC + the customer owns the deployment), not aspirational ("I'll hire") |
| **"Is it secure enough to sell as security?"** | BLK-01 closed and re-verified; BLK-03, BLK-04, BLK-06, BLK-07 open; the transferable `go_url` lure disclosed in the threat model | Close BLK-04 (the eval compose binds `0.0.0.0` and publishes an admin token) before any public push. It is the cheapest open blocker and the most embarrassing one to be asked about |

---

## 7. Sequenced plan

### Phase 0 — weeks 0–2 · cost: ~$0

1. **Apply for cloud credits** — AWS Activate, plus Anthropic/OpenAI startup programmes, plus Neon/Vercel. Highest effort-to-outcome ratio in this document, and it requires nothing from anyone else.
2. **Cut the nonce video** (§6.1) and put it above the fold in the README.
3. **Write the three answers in §6.5.** They gate every conversation that follows.
4. **Close BLK-04.** Cheapest open launch blocker; unacceptable to be asked about.
5. **Design BYOK v1** — the July brief's §10 follow-up that never happened. Custody claim first, then code.

### Phase 1 — weeks 2–6 · cost: ~$40/mo *(estimate — verify)*

6. **Ship BYOK.** `SealFamily::TenantProviderKey`, `KeySource::TenantByok`, per-tenant upstream, settings UI. After this, hosted users cost you compute only.
7. **Stand up the alpha on one VM** (Lever B), invite-only, named humans, BYOK mandatory, `FLUIDBOX_REQUIRE_SSO=1`, `FLUIDBOX_RUNTIME_ROLE` set. Tear down the EKS deployment or park it — do not pay $157/mo to prove something eight people could prove for $40.
8. **Recruit 8–10 design partners** against the July brief's ICP: platform/DevEx at GitHub-centric companies already running Claude or Codex. Sell offering 2 (BYOC/managed), demo on offering 3.

### Phase 2 — weeks 6–16 · target: cash-positive on infrastructure

9. **Convert 3–5 partners to $500/mo pilots.** At three, hosting is self-funding and the question in §1 is answered without an investor.
10. **Run rollout Gate 2 properly.** Its output — observed concurrency, connections per user, per-run cost p50/p95, approval latency p95 — is simultaneously your capacity model and your deck.
11. **Then decide whether to raise.** With three paying partners, live Gate 2 numbers, and written answers to §6.5, you are raising from a position of evidence. Without them, you are raising on a repository, which is a much worse trade for you.

---

## 8. The honest risks

- **BYOK is a real adoption tax.** Some users bounce at "paste your Anthropic key." Mitigation: a hard-capped shared-key trial (you already have per-tenant budgets, per-run budgets, and durable reservations — a $2 lifetime cap is enforceable today), converting to BYOK on the first real repository. Bound it in dollars, not in trust.
- **Invite-only is a real growth tax.** Accept it. Open signup on a shared Docker host with BLK-03 open is a security incident waiting to be written up, and for a security product one such incident is worse than two years of slow growth.
- **"Platform teams prefer BYOC" is a strong hypothesis, not a measured fact.** Test it in the first three sales conversations before building around it.
- **Solo-founder bus factor on a security product is a genuine objection**, not a talking point to deflect. The structural answers — MIT, BYOC, customer-owned deployment — are good ones. Say them plainly.
- **All third-party pricing in §4.1 Lever B is estimated**, not pulled from a pricing API, unlike everything in [`../hosted/cloud-cost-model.md`](../hosted/cloud-cost-model.md). Hold it to the same standard before committing.

---

## 9. One-paragraph summary

The chicken-and-egg dissolves under three corrections. **Model tokens** are not yours to carry: BYOK deletes the unbounded cost and, for a credential-inversion product, is a stronger security claim than reselling tokens — it needs one new `SealFamily`, one new `KeySource`, and a settings screen, on seams that already exist. **Infrastructure** is $157/mo of which $149 is a fixed EKS/ALB floor chosen for M1's zero-core-changes contract; an invite-only alpha on a single VM is roughly $40/mo, and a cloud-credits application may take it to zero this month. **Proof** does not require hosting anything: the nonce demonstration in BLK-01, the no-key `just demo`, and five self-hosted design partners are stronger evidence for this category than any free-tier signup curve, and the go/no-go document where you found and disclosed your own P0 is a better fundraising artifact than a metrics dashboard. The sharpest correction is one of sequencing: **the multi-tenant SaaS you are worried about funding is the offering you should build last.** Your buyer — a platform engineer who often cannot put repository credentials in a one-person startup's shared plane — prefers the managed-in-their-account shape you already scoped as M2, which costs you nothing marginal and prices highest. Sell that; host a small invite-only alpha as the demo; raise later, from evidence.
