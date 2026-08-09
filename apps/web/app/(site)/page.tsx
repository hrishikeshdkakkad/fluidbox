import type { Metadata } from "next";
import Link from "next/link";
import { GateStrip } from "./components/GateStrip";
import { HeroFilm } from "./components/HeroFilm";
import { PixelIcon } from "./components/PixelIcon";
import { RunLedger } from "./components/RunLedger";

const REPO = "https://github.com/hrishikeshdkakkad/fluidbox";
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000";

export const metadata: Metadata = {
  title: {
    absolute: "fluidbox — agents do the work, you keep the veto",
  },
  description:
    "The open-source control plane for AI agents: isolated sandboxes, a server-side gate on every tool call, human approvals, spending caps, and a complete record of every run. MIT-licensed, self-hosted, Docker and Kubernetes.",
  alternates: { canonical: "/" },
  openGraph: {
    title: "fluidbox — agents do the work, you keep the veto",
    description:
      "The open-source control plane for AI agents: sandboxes, rules, approvals, spending caps, receipts.",
    url: "/",
    type: "website",
  },
};

// Six jobs, outcome-first — the mechanism lives one click away in the doc
// each card links to.
const USECASES: { icon: string; t: string; b: string; href: string }[] = [
  {
    icon: "pr",
    t: "Review every pull request",
    b: "A governed run per PR, results posted back as one tidy comment and a check. Fork PRs are read-only, always.",
    href: "/docs/triggers",
  },
  {
    icon: "clock",
    t: "Maintenance on a schedule",
    b: "Dependency bumps, triage sweeps, weekly reports — fired exactly once per tick, with receipts.",
    href: "/docs/triggers",
  },
  {
    icon: "hand",
    t: "You approve the risky steps",
    b: "The run pauses on the call you'd want to see and resumes on your decision. No answer means no.",
    href: "/docs/approvals",
  },
  {
    icon: "rails",
    t: "Autonomy, with rails",
    b: "No one watching? The rules still apply, budgets still stop runaways, and every decision is still recorded.",
    href: "/docs/runs",
  },
  {
    icon: "key",
    t: "Your tools, without handing over keys",
    b: "Agents use Linear, Jira, or GitHub through fluidbox — your tokens never enter the sandbox.",
    href: "/docs/capabilities",
  },
  {
    icon: "meter",
    t: "A spending cap on every run",
    b: "Set a ceiling in dollars, tokens, or minutes. The worst case is a number you chose.",
    href: "/docs/runs",
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
        "Open-source control plane for AI agents: isolated sandboxes, server-side tool policy, human approvals, budgets, and a complete audit record.",
      url: SITE_URL,
      license: `${REPO}/blob/main/LICENSE`,
      codeRepository: REPO,
      offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
    },
  ],
};

export default function HomePage() {
  return (
    <div className="st">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(JSON_LD) }}
      />

      {/* ── Hero: the thesis, and the film that shows it ── */}
      <section className="st-hero">
        <div className="site-container hero">
          {/* kernel.sh signature: the wordmark at architectural scale, its
              lower half cropped by the container. Decorative. */}
          <div className="hero-wordmark" aria-hidden>
            <span>fluidbox</span>
          </div>
          <div className="hero-kicker">
            <span className="signal" aria-hidden />
            the open-source control plane for ai agents
          </div>
          <h1 className="hero-title">
            <span style={{ display: "block" }}>agents do the work.</span>
            <span style={{ display: "block" }}>
              you keep the <span className="tt">veto</span>.
              <span className="hero-chips" aria-hidden>
                <span className="hero-chip">mit</span>
                <span className="hero-chip">self-hosted</span>
              </span>
            </span>
          </h1>
          <p className="hero-sub">
            fluidbox runs your ai agents in disposable sandboxes, checks every
            action against your rules, and keeps a complete record of every
            run — so you can hand them real work without holding your breath.
          </p>
          <div className="hero-ctas">
            <Link className="btn primary" href="/docs/getting-started">
              get started <span className="arr">→</span>
            </Link>
            <Link className="btn" href="/product">
              see how it works
            </Link>
          </div>
          <div className="hero-meta">
            <span>
              <strong>mit</strong> open source
            </span>
            <span>
              <strong>~5 min</strong> to first run
            </span>
            <span>
              <strong>your infra</strong> — self-hosted
            </span>
            <span>
              <strong>docker + k8s</strong> deploys
            </span>
          </div>

          {/* The stage: the product film, from the same public master the
              README links — click to play, narration intact. */}
          <div className="st-stage">
            <HeroFilm />
          </div>
        </div>
      </section>

      {/* ── The gate ── */}
      <section className="site-container st-narr">
        <div className="st-narr-copy">
          <div className="site-kicker">How it protects you</div>
          <h2 className="site-h2">
            Routine work flows. Risky calls <span className="tt">stop</span>.
          </h2>
          <p className="site-lead">
            Every action an agent takes is checked first — against your
            spending limits, your rules, and your list of things that need a
            human. A denial is safe: the agent simply hears &quot;no&quot;
            and keeps working.
          </p>
          <p className="site-lead">
            Autonomous runs follow the same rules. Nothing bypasses the gate.
          </p>
          <Link className="st-link" href="/docs/governance">
            How decisions are made ›
          </Link>
        </div>
        <div className="st-narr-visual">
          <GateStrip vertical />
        </div>
      </section>

      {/* ── The record ── */}
      <section className="site-band">
        <div className="site-container site-section">
          <div className="site-kicker">The receipts</div>
          <h2 className="site-h2">Watch it decide — then keep the receipts.</h2>
          <p className="site-lead">
            Every run ends with a diff, a cost, and a timeline of every
            decision — what was allowed, what was denied, and who approved
            what. When someone asks what the agent did, you have the answer.
          </p>

          {/* The ledger stage: the run record itself, with two satellite
              cards answering what it raises — who decides (approval) and
              why it denied (the policy rule). Decorative duplicates. */}
          <div className="st-stage">
            <RunLedger />
            <aside className="st-stage-card st-stage-approval" aria-hidden>
              <div className="st-stage-head">
                <span className="dot" />
                Approval required
                <span className="ttl">ttl 9:22</span>
              </div>
              <div className="st-stage-tool">mcp__linear__create_issue</div>
              <div className="st-stage-sub">agent fixer · run 0198f2c4</div>
              <div className="st-stage-actions">
                <span className="st-chipbtn approve">Approve once</span>
                <span className="st-chipbtn">Deny</span>
              </div>
            </aside>
            <aside className="st-stage-card st-stage-policy" aria-hidden>
              <div className="st-stage-label">policy default v7</div>
              <pre>{`- match: ["Read", "Edit"]
  paths: ["/workspace/**"]
  on_no_match: deny`}</pre>
            </aside>
          </div>
        </div>
      </section>

      {/* ── Patterns: the daylight band ── */}
      <section className="st-day">
        <div className="site-container site-section">
          <div className="site-kicker">Patterns</div>
          <h2 className="site-h2">
            The <span className="tt">jobs</span> teams hand it first.
          </h2>
          <p className="site-lead">
            Six shipped capabilities, not a roadmap — every card links to the
            documentation that proves it.
          </p>
          <div className="st-uses">
            {USECASES.map((u) => (
              <Link className="st-use" key={u.t} href={u.href}>
                <span className="st-use-icon">
                  <PixelIcon name={u.icon} />
                </span>
                <h3>{u.t}</h3>
                <p>{u.b}</p>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* ── Open + tested ── */}
      <section className="site-container site-section">
        <div className="site-kicker">Open source</div>
        <h2 className="site-h2">Free, open, and tested like infrastructure.</h2>
        <p className="site-lead">
          MIT-licensed, all of it — the whole product, not a limited edition.
          You can read every line that governs your agents, and the test
          suites that prove it behaves.
        </p>
        <div className="st-ghrow">
          <a className="st-ghbtn" href={REPO} target="_blank" rel="noreferrer">
            <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
            </svg>
            Star on GitHub
          </a>
          <span className="st-mit">MIT license</span>
        </div>
        <div className="st-stats">
          <div className="st-stat">
            <strong>850</strong>
            <span>tests, green in seconds</span>
          </div>
          <div className="st-stat">
            <strong>10</strong>
            <span>end-to-end suites against live sandboxes</span>
          </div>
          <div className="st-stat">
            <strong>2</strong>
            <span>agent harnesses supported today</span>
          </div>
          <div className="st-stat">
            <strong>0</strong>
            <span>cloud resources left behind after teardown</span>
          </div>
        </div>
      </section>

      {/* ── Get running ── */}
      <section className="site-band">
        <div className="site-container site-section tight">
          <div className="site-kicker">Get started</div>
          <h2 className="site-h2">
            Your first governed run in about five minutes.
          </h2>
          <p className="site-lead">
            Run it on your own machine with Docker, or on your cluster with
            the Helm chart. Your code and your credentials never leave your
            infrastructure.
          </p>
          <div className="hero-ctas" style={{ justifyContent: "flex-start", marginTop: 24 }}>
            <Link className="btn primary" href="/docs/getting-started">
              Get Started <span className="arr">→</span>
            </Link>
            <Link className="btn" href="/docs/kubernetes">
              Kubernetes Guide
            </Link>
          </div>
        </div>
      </section>

      {/* ── Final CTA ── */}
      <section className="st-bigcta">
        <div className="site-container st-bigcta-inner">
          <h2>
            Give your agents <span className="tt">rules, receipts,</span> and
            a place to run.
          </h2>
          <div className="hero-ctas">
            <Link className="btn primary" href="/docs/getting-started">
              Get Started <span className="arr">→</span>
            </Link>
            <a className="btn" href={REPO} target="_blank" rel="noreferrer">
              View on GitHub ↗
            </a>
          </div>
        </div>
      </section>
    </div>
  );
}
