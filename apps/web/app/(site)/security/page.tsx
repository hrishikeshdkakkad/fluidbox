import type { Metadata } from "next";
import { PageEcho } from "../components/PageEcho";
import Link from "next/link";

const REPO = "https://github.com/hrishikeshdkakkad/fluidbox";

export const metadata: Metadata = {
  title: "Security",
  description:
    "fluidbox's security posture: credential inversion, the single permission gate, redaction-enforced audit, sandbox containment — and how to report a vulnerability privately.",
  alternates: { canonical: "/security" },
};

const POSTURE: { t: string; b: string }[] = [
  {
    t: "Credentials never enter a sandbox",
    b: "The sandbox's model key is its session token — the facade swaps in the real credential upstream. Git fetches happen before the agent exists. Brokered tools execute control-plane-side against credentials sealed at rest with authenticated, tenant-bound envelope encryption.",
  },
  {
    t: "One gate decides every tool call",
    b: "Budget → frozen tool surface → argument schema → trust tier → policy → approval, identically for sandbox and brokered tools. There is no bypass mode; autonomous runs rewrite ask-a-human to the policy fallback and record both verdicts.",
  },
  {
    t: "The audit trail can't be quietly wrong",
    b: "RunSpecs freeze at creation; agents and policies are append-only; the ledger accepts only redacted events by construction, with gapless per-run sequence numbers — a gap is evidence, not noise.",
  },
  {
    t: "The workload has nowhere to go",
    b: "Sandboxes run with no network egress — Docker locally, admission-gated deny-all NetworkPolicies on Kubernetes. The control plane's own egress rides one hardened boundary: private/link-local/metadata address classes blocked at every dial site, credential-bearing clients refusing redirects outright.",
  },
  {
    t: "Multi-user has a database floor",
    b: "Hosted mode adds per-org OIDC, server-side sessions, and RBAC — with tenant isolation enforced twice: as a type-level signature requirement in the data layer, and as forced PostgreSQL row-level security underneath it.",
  },
  {
    t: "Honest scope",
    b: "Pre-1.0. Implemented and tested — unit suites plus end-to-end acceptance driving real sandboxes, approvals, and OAuth — but no compliance certifications and no formal third-party audit yet. Residual risks are documented in the threat model, not rounded away.",
  },
];

export default function SecurityPage() {
  return (
    <div className="st">
      <section className="site-container site-section tight">
        <PageEcho en="security" es="seguridad" jp="セキュリティ" sc="安全" />
        <h1 className="site-h2" style={{ maxWidth: 720 }}>
          Containment and accountability are the product.
        </h1>
        <p className="site-lead">
          Hand an agent a repository and a credential, and still be able to
          answer — afterwards, from records that can&apos;t be rewritten —
          exactly what it did and why it was allowed to. Everything below is
          implemented in the open;{" "}
          <Link href="/docs/security">the security model</Link> and the{" "}
          <a
            href={`${REPO}/blob/main/docs/hosted/threat-model.md`}
            target="_blank"
            rel="noreferrer"
          >
            threat model ↗
          </a>{" "}
          carry the detail.
        </p>
      </section>

      <section className="site-band">
        <div className="site-container site-section tight">
          <div className="site-kicker">posture</div>
          <h2 className="site-h2">Six load-bearing properties.</h2>
          <div className="features" style={{ marginTop: 26 }}>
            {POSTURE.map((p) => (
              <article className="feature" key={p.t}>
                <h3 className="feature-t">{p.t}</h3>
                <p className="feature-b">{p.b}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="site-container site-section tight">
        <div className="oss-grid">
          <div>
            <div className="site-kicker">responsible disclosure</div>
            <h2 className="site-h2">Security reports are the contributions we value most.</h2>
            <p className="site-p">
              <strong>Please don&apos;t open a public issue.</strong> Use
              GitHub&apos;s private vulnerability reporting, which opens a
              private thread with the maintainer, or email with{" "}
              <code>[fluidbox security]</code> in the subject (address in
              SECURITY.md). You can expect an acknowledgement within 72 hours
              and an assessment within a week — and credit in the advisory and
              changelog unless you prefer otherwise.
            </p>
            <p className="site-p">
              Highest-interest reports: sandbox escape or egress, credential
              exposure, policy or approval bypass, audit-trail integrity,
              ingress authentication, and budget bypass. fluidbox is pre-1.0:
              the latest <code>main</code> receives fixes.
            </p>
            <div className="hero-ctas" style={{ marginTop: 18 }}>
              <a
                className="btn primary"
                href={`${REPO}/security/advisories/new`}
                target="_blank"
                rel="noreferrer"
              >
                Report a vulnerability ↗
              </a>
              <a
                className="btn ghost"
                href={`${REPO}/blob/main/SECURITY.md`}
                target="_blank"
                rel="noreferrer"
              >
                Full policy ↗
              </a>
            </div>
          </div>
          <div>
            <div className="site-kicker">operator notes</div>
            <ul className="oss-list">
              <li>
                <Link href="/docs/security">
                  Security model <small>the map, with links</small>
                </Link>
              </li>
              <li>
                <a
                  href={`${REPO}/blob/main/docs/hosted/threat-model.md`}
                  target="_blank"
                  rel="noreferrer"
                >
                  Threat model <small>including residual risks</small>
                </a>
              </li>
              <li>
                <a
                  href={`${REPO}/blob/main/docs/hosted/kms-operations.md`}
                  target="_blank"
                  rel="noreferrer"
                >
                  KMS &amp; key custody runbook <small>sealing, re-seal, retirement</small>
                </a>
              </li>
              <li>
                <Link href="/docs/kubernetes">
                  Kubernetes hardening <small>zero-egress admission gate</small>
                </Link>
              </li>
            </ul>
          </div>
        </div>
      </section>
    </div>
  );
}
