import type { Metadata } from "next";
import { PageEcho } from "../components/PageEcho";
import Link from "next/link";
import { GateStrip } from "../components/GateStrip";

const REPO = "https://github.com/hrishikeshdkakkad/fluidbox";

export const metadata: Metadata = {
  title: "Product",
  description:
    "What fluidbox does, end to end: frozen run specifications, disposable sandboxes, the permission gate, human approvals, budgets, the audit ledger, triggers and schedules, and the deployment paths.",
  alternates: { canonical: "/product" },
};

const LIFECYCLE: { n: string; t: string; b: string }[] = [
  {
    n: "01",
    t: "Create — the RunSpec freezes",
    b: "Dashboard, CLI, API trigger, webhook, or schedule — every entry point converges on one code path that freezes an immutable specification: model, system prompt, task, a full policy snapshot, budgets, the exact tool surface, and who invoked it. Nothing that governs the run can change afterwards.",
  },
  {
    n: "02",
    t: "Initialize — the workspace is prepared outside",
    b: "The credentialed git fetch or copy happens control-plane-side, before the agent exists. The sandbox will only ever see a bind-mounted copy at /workspace; the original repository is never touched.",
  },
  {
    n: "03",
    t: "Provision — a fresh sandbox, no secrets",
    b: "A disposable container from the harness's runner image. Its only credential is a per-session token — disguised as its model API key — and it has no network egress to use anything else.",
  },
  {
    n: "04",
    t: "Execute — the harness speaks one contract",
    b: "Claude Agent SDK or Codex, behind the same HTTP runner contract: tool calls to /permission, message streams to /events, liveness to /heartbeat, the outcome to /result. Model calls ride the LLM facade, which meters usage as it streams.",
  },
  {
    n: "05",
    t: "Decide — one gate, every call",
    b: "Budget, frozen tool surface, argument schema, trust tier, policy, approvals — in that order, for every tool call. Ask-a-human pauses the run; deny returns a tool error the model can react to; in autonomous mode the ask verdict rewrites to the policy fallback with both verdicts recorded.",
  },
  {
    n: "06",
    t: "Finish — a diff, a cost report, a ledger",
    b: "The server is the single status writer. Terminal entry enqueues result deliveries — signed webhooks, GitHub comments and checks — decoupled from the run, so a dead receiver can never mutate one. What remains is reviewable: what changed, what it cost, and why each step was allowed.",
  },
];

const GUARANTEES: { t: string; b: string; href: string; link: string }[] = [
  {
    t: "Policies are versioned law",
    b: "Ordered rules over tools, paths, and shell; append-only version history with authors and summaries; every run judged against the snapshot it froze — never against what the policy says today.",
    href: "/docs/policies",
    link: "Policies",
  },
  {
    t: "Approvals that hold up",
    b: "Idempotent by (run, tool call); settled by compare-and-swap; expiry denies. Personal-credential calls are decidable only by their owner — no admin override in either direction.",
    href: "/docs/approvals",
    link: "Approvals",
  },
  {
    t: "Credentials stay out of sandboxes",
    b: "The facade swaps in the real model key; git fetches happen before the agent exists; brokered MCP tools execute control-plane-side with credentials sealed at rest. The workload can't leak what it never holds.",
    href: "/docs/security",
    link: "Security model",
  },
  {
    t: "A ledger you can trust",
    b: "Gapless per-run sequence numbers, resumable streaming, and redaction enforced by the type system — prompts cannot reach storage, digests and verdicts do.",
    href: "/docs/runs",
    link: "Runs & the timeline",
  },
  {
    t: "Two tool classes, one split",
    b: "Sandbox tools are credential-free subprocesses contained by the container. Brokered tools are called by the control plane against per-run frozen bindings. Attach is never allow — the gate decides every call.",
    href: "/docs/capabilities",
    link: "Capabilities",
  },
  {
    t: "Machine-started, equally governed",
    b: "Subscription-scoped API tokens, exactly-once cron schedules, GitHub PR events with fork runs frozen read-only. Same creation path, same RunSpec, same gate.",
    href: "/docs/triggers",
    link: "Triggers & schedules",
  },
];

export default function ProductPage() {
  return (
    <div className="st">
      <section className="site-container site-section tight">
        <PageEcho en="product" es="producto" jp="製品" sc="产品" />
        <h1 className="site-h2" style={{ maxWidth: 720 }}>
          A control plane that answers, afterwards, exactly what an agent did —
          and why it was allowed to.
        </h1>
        <p className="site-lead">
          fluidbox runs underneath agent harnesses, not instead of them. You
          register versioned agents; it gives every run an isolated sandbox, a
          policy gate, human approvals, budgets, and an append-only record.
        </p>
        <div className="shot-frame">
          <div className="st-shot-head" aria-hidden>
            <span className="st-dots">
              <i />
              <i />
              <i />
            </span>
            <span className="st-window-title">fluidbox — operations</span>
          </div>
          <img
            src="/product/overview-light.png"
            width={1440}
            height={900}
            loading="lazy"
            alt="The fluidbox dashboard overview: operations counters for active sandboxes, runs needing review, and completions; the agent, integration, and MCP resource lists; and run history."
          />
        </div>
        <p className="try-note" style={{ marginTop: 14 }}>
          A capture of the shipped product, not a mockup.
        </p>
      </section>

      <section className="site-band">
        <div className="site-container site-section tight">
          <div className="site-kicker">how a run flows</div>
          <h2 className="site-h2">Six stages, one immutable record.</h2>
          <div className="features" style={{ marginTop: 26 }}>
            {LIFECYCLE.map((s) => (
              <article className="feature" key={s.n}>
                <div className="feature-k">{s.n}</div>
                <h3 className="feature-t">{s.t}</h3>
                <p className="feature-b">{s.b}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="site-container site-section tight">
        <div className="site-kicker">the gate</div>
        <h2 className="site-h2">The decision order is part of the product.</h2>
        <p className="site-lead">
          Two stages sit above policy and cannot be approved away: budgets,
          and the read-only trust tier frozen onto runs from fork pull
          requests.
        </p>
        <div style={{ marginTop: 26 }}>
          <GateStrip />
        </div>
      </section>

      <section className="site-band">
        <div className="site-container site-section tight">
          <div className="site-kicker">guarantees</div>
          <h2 className="site-h2">What the design promises.</h2>
          <div className="features" style={{ marginTop: 26 }}>
            {GUARANTEES.map((g) => (
              <article className="feature" key={g.t}>
                <h3 className="feature-t">{g.t}</h3>
                <p className="feature-b">{g.b}</p>
                <Link className="feature-link" href={g.href}>
                  {g.link} →
                </Link>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="site-container site-section tight">
        <div className="site-kicker">runs anywhere containers do</div>
        <h2 className="site-h2">Docker for the desk, Kubernetes for the fleet.</h2>
        <p className="site-lead">
          One compose command runs the whole stack from published images. The
          Helm chart deploys the production shape: sandboxes as Jobs behind
          admission-gated deny-all NetworkPolicies, the runner contract on a
          separate listener, published OCI images and chart.
        </p>
        <div className="hero-ctas" style={{ marginTop: 20 }}>
          <Link className="btn" href="/docs/docker">
            Docker guide
          </Link>
          <Link className="btn" href="/docs/kubernetes">
            Kubernetes guide
          </Link>
          <a className="btn ghost" href={`${REPO}/blob/main/docs/ARCHITECTURE.md`} target="_blank" rel="noreferrer">
            Architecture tour ↗
          </a>
        </div>
      </section>

      <section className="site-container cta-final" style={{ paddingTop: 0 }}>
        <h2 className="site-h2">See it decide something.</h2>
        <div className="hero-ctas">
          <Link className="btn primary" href="/#try-it">
            Try the demo
          </Link>
          <Link className="btn" href="/docs/getting-started">
            Getting started
          </Link>
        </div>
      </section>
    </div>
  );
}
