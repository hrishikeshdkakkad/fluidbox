import Link from "next/link";
import { GUIDES, PLANES_MD } from "./generated/content";
import { API_VERSION, OPERATION_COUNT } from "./generated/reference";
import { MarkdownView } from "./MarkdownView";

// The developer hub. Everything on this page is generated from docs/ at the
// repo root (just docs-sync) — author there, never here.
export default function DeveloperHome() {
  return (
    <div className="docs-columns">
      <div className="docs-article">
        <header className="docs-hero">
          <div className="docs-hero-kicker">fluidbox · developer documentation</div>
          <h1 className="docs-hero-title">
            Build against the
            <br />
            control plane.
          </h1>
          <p className="docs-lead">
            Run AI coding agents in governed, disposable sandboxes — and integrate the runs, the
            approvals, and the audit trail into your own systems.
          </p>
          <div className="docs-hero-actions">
            <Link className="btn" href="/developer/quickstart">
              Quickstart →
            </Link>
            <Link className="btn ghost" href="/developer/reference">
              API reference
            </Link>
            <a className="btn ghost" href="/developer/openapi.yaml" download>
              OpenAPI 3.1 ↓
            </a>
          </div>
          <div className="docs-hero-meta">
            <span>
              <strong>{OPERATION_COUNT}</strong> operations
            </span>
            <span className="docs-hero-dot" aria-hidden />
            <span>
              spec <strong>v{API_VERSION}</strong>
            </span>
            <span className="docs-hero-dot" aria-hidden />
            <span>
              <strong>{GUIDES.length}</strong> guides
            </span>
          </div>
        </header>

        <div className="docs-hub-grid">
          {GUIDES.map((g, i) => (
            <Link key={g.slug} href={`/developer/${g.slug}`} className="docs-hub-card">
              <div className="docs-hub-kicker">
                {String(i + 1).padStart(2, "0")} · Guide
              </div>
              <div className="docs-hub-title">{g.title}</div>
              <p className="docs-hub-blurb">{g.blurb}</p>
            </Link>
          ))}
          <Link href="/developer/reference" className="docs-hub-card docs-hub-card-wide">
            <div className="docs-hub-kicker">Reference</div>
            <div className="docs-hub-title">Every endpoint, four planes</div>
            <p className="docs-hub-blurb">
              Public API, runner contract, operator, and ingress — {OPERATION_COUNT} operations
              generated from the same OpenAPI description you can download above.
            </p>
          </Link>
        </div>

        <section className="docs-planes">
          <h2 className="docs-section-title">The four planes</h2>
          {/* Rendered from docs/index.md via docs-sync — the table lives there,
              once. Author in docs/, never here. */}
          <MarkdownView md={PLANES_MD} />
        </section>
      </div>
    </div>
  );
}
