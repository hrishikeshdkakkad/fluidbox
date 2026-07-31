import type { Metadata } from "next";
import Link from "next/link";
import { ArchitectureDiagram } from "./components/ArchitectureDiagram";
import { GateStrip } from "./components/GateStrip";
import { RunLedger } from "./components/RunLedger";
import { CodeBlock } from "./docs/CodeBlock";
import { OPERATION_COUNT } from "./docs/generated/reference";

const REPO = "https://github.com/hrishikeshdkakkad/fluidbox";
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000";

export const metadata: Metadata = {
  title: {
    absolute: "fluidbox — run AI agents without giving them God mode",
  },
  description:
    "The open-source control plane for governed AI agents: isolated sandboxes, server-side tool policy, human approval gates, budgets, and an append-only audit ledger. MIT-licensed, self-hostable, Docker and Kubernetes.",
  alternates: { canonical: "/" },
  openGraph: {
    title: "fluidbox — run AI agents without giving them God mode",
    description:
      "The open-source control plane for governed AI agents: sandboxes, policy, approvals, budgets, audit receipts.",
    url: "/",
    type: "website",
  },
};

const DOCKER_CMDS = `git clone ${REPO}.git
cd fluidbox
docker compose -f deploy/docker-compose.eval.yml --profile runners pull
ANTHROPIC_API_KEY=sk-ant-... docker compose -f deploy/docker-compose.eval.yml up -d`;

const SOURCE_CMDS = `just setup     # .env + secrets, web deps, runner image
just doctor    # validates every gotcha, prints the fix
just dev       # gateway + control plane + dashboard`;

const FEATURES: {
  k: string;
  t: string;
  b: string;
  code: string;
  href: string;
  link: string;
}[] = [
  {
    k: "policy",
    t: "Server-side tool policy",
    b: "Ordered rules over tools, paths, and shell commands decide allow, deny, or ask-a-human — evaluated in the control plane, where the agent can't reach. Versioned, append-only, authorable from the dashboard.",
    code: `- match: ["Bash"]
  action: allow
  shell:
    deny_regex: ["rm\\\\s+-rf\\\\s+/"]
    on_no_match: approve`,
    href: "/docs/policies",
    link: "Policies",
  },
  {
    k: "approvals",
    t: "Human approval gates",
    b: "An approve verdict pauses the run until someone decides — once, for the session, or deny. Decisions are idempotent; an unanswered approval expires to deny. Absence never widens permission.",
    code: `POST /v1/approvals/{id}/decision
{ "decision": "approved_once" }`,
    href: "/docs/approvals",
    link: "Approvals",
  },
  {
    k: "sandbox",
    t: "Isolated execution",
    b: "Every run gets a fresh, disposable container with a bind-mounted copy of your repository and no network egress. Credentials never enter it — model, git, and tool calls all terminate control-plane-side.",
    code: `workspace  /workspace (copy — original untouched)
egress     none · credentials: none`,
    href: "/docs/security",
    link: "Security model",
  },
  {
    k: "budgets",
    t: "Cost, token, and time budgets",
    b: "Ceilings frozen per run; usage metered off the streamed model response and enforced server-side. A run that hits its budget stops, and the spend that stopped it is in the ledger.",
    code: `budgets: { max_cost_usd: 2.50,
           max_wall_clock_secs: 1800 }
spent:   $0.011 · 2,148 tokens`,
    href: "/docs/runs",
    link: "Runs & budgets",
  },
  {
    k: "ledger",
    t: "Append-only audit timeline",
    b: "Every request, verdict, approval, and dollar — gapless sequence numbers, resumable streaming, and redaction enforced by construction: prompts can't reach the ledger, digests can.",
    code: `seq 23 · tool.brokered · 212ms
result sha256:9f2c… (digest, never payload)`,
    href: "/docs/runs",
    link: "The timeline",
  },
  {
    k: "triggers",
    t: "Agents, triggers, schedules",
    b: "Versioned agent definitions with append-only revisions; runs started by API tokens, cron schedules (exactly-once), or GitHub pull requests — all frozen into the same governed RunSpec.",
    code: `POST /v1/triggers/{id}/invoke
schedule: "0 9 * * 1-5" · concurrency: skip`,
    href: "/docs/triggers",
    link: "Triggers & schedules",
  },
  {
    k: "deploy",
    t: "Docker and Kubernetes",
    b: "One compose command for evaluation; a Helm chart for production-shaped clusters, where sandboxes are Jobs behind admission-gated deny-all NetworkPolicies. Published images, OCI chart.",
    code: `helm install fluidbox \\
  oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox`,
    href: "/docs/kubernetes",
    link: "Kubernetes",
  },
];

// Honest pattern cards: each one is a shipped capability framed as a job —
// no customer claims, every card links to the doc that proves it.
const PATTERNS: { t: string; b: string; href: string; link: string }[] = [
  {
    t: "Review every pull request",
    b: "A GitHub event starts a governed run per PR; results publish as one comment updated in place plus a check per head SHA. Fork PRs are frozen read-only — no approval can widen them.",
    href: "/docs/triggers",
    link: "GitHub triggers",
  },
  {
    t: "Maintenance agents on a schedule",
    b: "Cron subscriptions fire exactly once per tick with explicit concurrency and missed-run policy — dependency bumps, triage sweeps, report generation, all with receipts.",
    href: "/docs/triggers",
    link: "Schedules",
  },
  {
    t: "Human-in-the-loop changes",
    b: "The run pauses on the risky call and resumes on your decision — approve once, approve for the session, or deny. Unanswered approvals expire to deny.",
    href: "/docs/approvals",
    link: "Approvals",
  },
  {
    t: "Autonomous batches, with rails",
    b: "No human watching: ask-a-human verdicts rewrite to the policy fallback with both verdicts recorded, and cost/token/time budgets stop runaways server-side.",
    href: "/docs/runs",
    link: "Autonomy & budgets",
  },
  {
    t: "Credentialed tools, no credential handout",
    b: "Brokered MCP tools run control-plane-side against per-run frozen bindings; the sandbox sends intent and gets a governed result. Your Jira token never meets the model.",
    href: "/docs/capabilities",
    link: "Capabilities",
  },
  {
    t: "Bring your own agent",
    b: "Two harnesses ship — Claude Agent SDK and Codex — behind one HTTP runner contract. Implement the contract and your agent inherits the whole governance stack.",
    href: "/docs/runner-contract",
    link: "The runner contract",
  },
];

const JSON_LD = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      name: "fluidbox",
      url: SITE_URL,
      sameAs: [REPO],
    },
    {
      "@type": "SoftwareApplication",
      name: "fluidbox",
      applicationCategory: "DeveloperApplication",
      operatingSystem: "Docker, Kubernetes",
      description:
        "Open-source control plane for governed AI agents: isolated sandboxes, server-side tool policy, human approvals, budgets, and an append-only audit ledger.",
      url: SITE_URL,
      license: `${REPO}/blob/main/LICENSE`,
      codeRepository: REPO,
      offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
    },
  ],
};

export default function HomePage() {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(JSON_LD) }}
      />

      {/* ── Hero: the thesis, and the ledger that proves it ── */}
      <section className="site-container hero">
        <div>
          <div className="hero-kicker">
            <span className="signal" aria-hidden />
            open-source control plane for governed AI agents
          </div>
          <h1 className="hero-title">
            Run AI agents without giving them{" "}
            <span className="hero-godmode">God mode</span>.
          </h1>
          <p className="hero-sub">
            fluidbox sits underneath agent harnesses like the Claude Agent SDK
            and Codex: every run in a disposable sandbox, every tool call
            through a server-side policy gate, every decision in an append-only
            ledger. Not another reasoning framework — the infrastructure
            underneath one.
          </p>
          <div className="hero-ctas">
            <Link className="btn primary" href="#try-it">
              Try the demo
            </Link>
            <Link className="btn" href="/docs">
              Read the docs
            </Link>
            <a className="btn ghost" href={REPO} target="_blank" rel="noreferrer">
              GitHub ↗
            </a>
            <Link className="btn ghost" href="/sign-in">
              Sign in
            </Link>
          </div>
          <div className="hero-meta">
            <span>
              <strong>MIT</strong> licensed
            </span>
            <span>
              <strong>{OPERATION_COUNT}</strong> API operations
            </span>
            <span>
              <strong>2</strong> harnesses, one contract
            </span>
            <span>
              <strong>Docker + K8s</strong> deploys
            </span>
          </div>
        </div>
        <RunLedger />
      </section>

      {/* ── The gate ── */}
      <section className="site-band">
        <div className="site-container site-section tight">
          <div className="site-kicker">the permission gate</div>
          <h2 className="site-h2">
            Every tool call passes one gate, in one fixed order.
          </h2>
          <p className="site-lead">
            Both harnesses, both tool classes, every autonomy mode. Autonomous
            runs don&apos;t bypass the gate — an ask-a-human verdict is
            rewritten to the policy&apos;s fallback and{" "}
            <em>both verdicts are recorded</em>. Two stages sit above policy
            and can&apos;t be approved away: budgets, and the read-only trust
            tier frozen onto fork pull requests.
          </p>
          <div style={{ marginTop: 28 }}>
            <GateStrip />
          </div>
          <p className="try-note" style={{ marginTop: 14 }}>
            The full sequence, with sources for every denial:{" "}
            <Link href="/docs/governance">the permission gate</Link>.
          </p>
        </div>
      </section>

      {/* ── Capabilities ── */}
      <section className="site-container site-section">
        <div className="site-kicker">capabilities</div>
        <h2 className="site-h2">
          The parts you&apos;d otherwise build around your agent runtime.
        </h2>
        <p className="site-lead">
          fluidbox is deliberately not a reasoning framework. It&apos;s the
          governance and execution layer that makes whichever harness you
          already use safe to hand a repository and a credential.
        </p>
        <div className="features">
          {FEATURES.map((f) => (
            <article
              className={`feature ${f.k === "deploy" ? "feature-wide" : ""}`}
              key={f.k}
            >
              <div className="feature-k">{f.k}</div>
              <h3 className="feature-t">{f.t}</h3>
              <p className="feature-b">{f.b}</p>
              <pre className="feature-code">{f.code}</pre>
              <Link className="feature-link" href={f.href}>
                {f.link} →
              </Link>
            </article>
          ))}
        </div>
      </section>

      {/* ── Patterns (honest use cases, each backed by a doc) ── */}
      <section className="site-band">
        <div className="site-container site-section">
          <div className="site-kicker">what teams run through it</div>
          <h2 className="site-h2">The jobs this was built for.</h2>
          <p className="site-lead">
            Every card is a shipped capability, not an aspiration — and links
            to the documentation that proves it.
          </p>
          <div className="features">
            {PATTERNS.map((p) => (
              <article className="feature" key={p.t}>
                <h3 className="feature-t">{p.t}</h3>
                <p className="feature-b">{p.b}</p>
                <Link className="feature-link" href={p.href}>
                  {p.link} →
                </Link>
              </article>
            ))}
          </div>
        </div>
      </section>

      {/* ── Architecture ── */}
      <section>
        <div className="site-container site-section">
          <div className="site-kicker">architecture</div>
          <h2 className="site-h2">
            Underneath the harness. In front of everything it touches.
          </h2>
          <p className="site-lead">
            The harness runs inside the sandbox and speaks one HTTP contract.
            Models, credentials, tools, and the audit trail all live on the
            other side of it — in a Rust control plane that answers before
            anything happens.
          </p>
          <div className="arch-wrap">
            <ArchitectureDiagram />
          </div>
          <p className="try-note" style={{ marginTop: 16 }}>
            The reader&apos;s tour: <Link href="/docs/concepts">concepts</Link>{" "}
            ·{" "}
            <a
              href={`${REPO}/blob/main/docs/ARCHITECTURE.md`}
              target="_blank"
              rel="noreferrer"
            >
              docs/ARCHITECTURE.md ↗
            </a>
          </p>
        </div>
      </section>

      {/* ── Visibility: the real product, not a mockup ── */}
      <section className="site-band">
        <div className="site-container site-section">
          <div className="site-kicker">the record</div>
          <h2 className="site-h2">Watch it decide — then keep the receipts.</h2>
          <p className="site-lead">
            The dashboard renders what the control plane already knows: live
            runs, pending approvals, agents and their revisions, and a
            per-run timeline where every verdict names the stage that made
            it. This is a real capture of the shipped product, not a mockup.
          </p>
          <div className="shot-frame">
            <img
              src="/product/overview-light.png"
              width={1440}
              height={900}
              loading="lazy"
              alt="The fluidbox dashboard overview: operations counters for active sandboxes, runs needing review, and completions; the agent, integration, and MCP resource lists; and run history."
            />
          </div>
          <p className="try-note" style={{ marginTop: 14 }}>
            The timeline vocabulary, event by event:{" "}
            <Link href="/docs/runs">runs &amp; the timeline</Link>.
          </p>
        </div>
      </section>

      {/* ── Try it ── */}
      <section id="try-it" className="site-container site-section">
        <div className="site-kicker">developer experience</div>
        <h2 className="site-h2">A governed run on your machine, two ways.</h2>
        <p className="site-lead">
          The eval stack runs entirely from published images — bundled
          Postgres, a well-known admin token, nothing built locally. The
          from-source path is three commands, and <code>just doctor</code>{" "}
          explains anything that&apos;s off.
        </p>
        <div className="try-grid">
          <div className="try-col">
            <h3 className="try-col-title">Docker — published images</h3>
            <CodeBlock lang="bash" text={DOCKER_CMDS} />
            <p className="try-note">
              Open localhost:3000 — the dashboard lives at /app. Eval only:
              see <Link href="/docs/docker">Docker</Link> for what&apos;s
              deliberately disabled.
            </p>
          </div>
          <div className="try-col">
            <h3 className="try-col-title">From source</h3>
            <CodeBlock lang="bash" text={SOURCE_CMDS} />
            <p className="try-note">
              Then register an agent and start a run that pauses for your
              approval: <Link href="/docs/getting-started">getting started</Link>.
            </p>
          </div>
        </div>
      </section>

      {/* ── Open source ── */}
      <section className="site-band">
        <div className="site-container site-section">
          <div className="oss-grid">
            <div>
              <div className="site-kicker">open source</div>
              <h2 className="site-h2">MIT-licensed. Self-hosted. No black boxes.</h2>
              <p className="site-p">
                The repository is the product: the Rust control plane, both
                runner images, the dashboard, the Helm chart, the OpenAPI
                description, the threat model, and the end-to-end acceptance
                suites that drive real sandboxes and real approval flows.
              </p>
              <p className="site-p">
                Governance infrastructure only earns trust when you can read
                it. The security model is documented, the residual risks are
                written down rather than rounded away, and every release is
                built in the open.
              </p>
            </div>
            <div>
              <ul className="oss-list">
                <li>
                  <a href={REPO} target="_blank" rel="noreferrer">
                    Repository <small>github.com/hrishikeshdkakkad/fluidbox</small>
                  </a>
                </li>
                <li>
                  <a href={`${REPO}/blob/main/ROADMAP.md`} target="_blank" rel="noreferrer">
                    Public roadmap <small>what&apos;s next, in order</small>
                  </a>
                </li>
                <li>
                  <a href={`${REPO}/blob/main/CONTRIBUTING.md`} target="_blank" rel="noreferrer">
                    Contributing <small>clone → merged PR</small>
                  </a>
                </li>
                <li>
                  <a
                    href={`${REPO}/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Good first issues <small>labeled on the tracker</small>
                  </a>
                </li>
                <li>
                  <Link href="/open-source">
                    The open-source model <small>what&apos;s OSS vs hosted</small>
                  </Link>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ── Final CTA ── */}
      <section className="site-container cta-final">
        <div className="site-kicker">start here</div>
        <h2 className="site-h2">
          Give your agents rules, receipts, and a place to run.
        </h2>
        <div className="hero-ctas">
          <Link className="btn primary" href="#try-it">
            Try the demo
          </Link>
          <a className="btn" href={REPO} target="_blank" rel="noreferrer">
            View GitHub ↗
          </a>
          <Link className="btn ghost" href="/sign-in">
            Sign in
          </Link>
        </div>
      </section>
    </>
  );
}
