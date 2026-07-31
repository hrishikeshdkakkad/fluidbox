import type { Metadata } from "next";
import Link from "next/link";

const REPO = "https://github.com/hrishikeshdkakkad/fluidbox";

export const metadata: Metadata = {
  title: "Open source",
  description:
    "fluidbox's open-source model: MIT license, what ships in the repository, what you can self-host with Docker or Kubernetes, how to contribute, and where the hosted offering begins.",
  alternates: { canonical: "/open-source" },
};

const IN_THE_BOX = `crates/fluidbox-core       policy engine · state machine · RunSpec · redaction
crates/fluidbox-server     /v1 API · gate · approvals · broker · facade · SSE
crates/fluidbox-db         Postgres repositories · migrations · RLS floor
crates/fluidbox-provider   sandbox lifecycles (Docker · Kubernetes)
crates/fluidbox-cli        drive runs from the terminal
images/                    both runner images + the shared runner contract
apps/web                   dashboard · this site · the docs you're reading
deploy/                    compose stacks · Helm chart (OCI-published)
docs/                      guides · OpenAPI 3.1 · threat model · runbooks
scripts/                   the e2e acceptance suites (real sandboxes)`;

export default function OpenSourcePage() {
  return (
    <>
      <section className="site-container site-section tight">
        <div className="site-kicker">open source</div>
        <h1 className="site-h2" style={{ maxWidth: 720 }}>
          Governance infrastructure only earns trust when you can read it.
        </h1>
        <p className="site-lead">
          fluidbox decides what AI agents may do with your repositories and
          credentials. That is not a product category where &quot;trust
          us&quot; works — the policy engine, the sandbox contract, the
          credential custody, and the audit ledger are all MIT-licensed and in
          one repository, together with the threat model that critiques them.
        </p>
        <div className="hero-ctas" style={{ marginTop: 18 }}>
          <a className="btn primary" href={REPO} target="_blank" rel="noreferrer">
            View the repository ↗
          </a>
          <a className="btn ghost" href={`${REPO}/blob/main/LICENSE`} target="_blank" rel="noreferrer">
            MIT license ↗
          </a>
        </div>
      </section>

      <section className="site-band">
        <div className="site-container site-section tight">
          <div className="site-kicker">what&apos;s in the repository</div>
          <h2 className="site-h2">The repository is the product.</h2>
          <p className="site-lead">
            100% Rust backend, presentation-only dashboard, any direct-connection
            Postgres. No enterprise fork, no held-back core.
          </p>
          <pre className="feature-code" style={{ marginTop: 22, maxWidth: 760, fontSize: 12 }}>
            {IN_THE_BOX}
          </pre>
        </div>
      </section>

      <section className="site-container site-section tight">
        <div className="oss-grid">
          <div>
            <div className="site-kicker">self-hosting</div>
            <h2 className="site-h2">Run it where your code already lives.</h2>
            <p className="site-p">
              The <Link href="/docs/docker">Docker eval stack</Link> is one
              compose command against published images. The{" "}
              <Link href="/docs/kubernetes">Helm chart</Link> is the
              production shape — sandboxes as Jobs with admission-gated
              deny-all egress, the runner contract on a separate listener. The
              multi-user hosted posture (per-org SSO, tenant isolation with a
              row-level-security floor, KMS envelope sealing) ships in the
              same repository behind explicit flags, with{" "}
              <a
                href={`${REPO}/blob/main/docs/hosted/rollout-gates.md`}
                target="_blank"
                rel="noreferrer"
              >
                documented rollout gates ↗
              </a>{" "}
              instead of marketing claims.
            </p>
            <p className="site-p">
              A hosted fluidbox offering will be the same open control plane,
              operated for you — early access, not for sale yet. See{" "}
              <Link href="/pricing">pricing</Link> for the honest version.
            </p>
          </div>
          <div>
            <div className="site-kicker">contribute</div>
            <ul className="oss-list">
              <li>
                <a href={`${REPO}/blob/main/CONTRIBUTING.md`} target="_blank" rel="noreferrer">
                  Contributing guide <small>fresh clone → merged PR</small>
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
                <a href={`${REPO}/blob/main/ROADMAP.md`} target="_blank" rel="noreferrer">
                  Public roadmap <small>and PLAN.md, the design doc</small>
                </a>
              </li>
              <li>
                <a href={`${REPO}/blob/main/SECURITY.md`} target="_blank" rel="noreferrer">
                  Security policy <small>private disclosure, 72h ack</small>
                </a>
              </li>
              <li>
                <Link href="/changelog">
                  Changelog <small>what shipped, when, and why</small>
                </Link>
              </li>
            </ul>
          </div>
        </div>
      </section>

      <section className="site-band">
        <div className="site-container site-section tight">
          <div className="site-kicker">ground rules</div>
          <h2 className="site-h2">Locked decisions, written down.</h2>
          <p className="site-lead">
            The backend is 100% Rust — the only sanctioned non-Rust code is the
            agent payload inside sandbox images. The dashboard renders
            decisions; it never makes them. PLAN.md&apos;s convergence
            invariants — frozen RunSpecs, append-only history, the
            always-wired permission callback, redaction-enforced ledger,
            credential inversion — govern every change, including yours.
          </p>
          <p className="try-note">
            Before proposing architecture:{" "}
            <a href={`${REPO}/blob/main/PLAN.md`} target="_blank" rel="noreferrer">
              PLAN.md ↗
            </a>{" "}
            ·{" "}
            <a href={`${REPO}/blob/main/CODE_OF_CONDUCT.md`} target="_blank" rel="noreferrer">
              Code of conduct ↗
            </a>
          </p>
        </div>
      </section>
    </>
  );
}
