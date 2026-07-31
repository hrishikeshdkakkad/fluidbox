import type { Metadata } from "next";
import Link from "next/link";
import { GUIDES, PLANES_MD } from "./generated/content";
import { API_VERSION, OPERATION_COUNT } from "./generated/reference";
import { MarkdownView } from "./MarkdownView";
import { NAV_GROUPS } from "./nav";

export const metadata: Metadata = {
  description:
    "Documentation for fluidbox, the open-source control plane for governed AI agents: getting started, concepts, governance, deployment, and the full API reference.",
  alternates: { canonical: "/docs" },
};

// The docs hub. Everything on this page is generated from docs/ at the repo
// root (just docs-sync) — author there, never here.
export default function DocsHome() {
  return (
    <div className="docs-columns">
      <div className="docs-article">
        <header className="docs-hero">
          <div className="docs-hero-kicker">fluidbox · documentation</div>
          <h1 className="docs-hero-title">
            Build against the
            <br />
            control plane.
          </h1>
          <p className="docs-lead">
            Run AI agents in governed, disposable sandboxes — and integrate the runs, the
            approvals, and the audit trail into your own systems.
          </p>
          <div className="docs-hero-actions">
            <Link className="btn" href="/docs/getting-started">
              Getting started →
            </Link>
            <Link className="btn ghost" href="/docs/api/reference">
              API reference
            </Link>
            <a className="btn ghost" href="/docs/openapi.yaml" download>
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
              <strong>{NAV_GROUPS.reduce((n, g) => n + g.links.length, 0)}</strong> pages
            </span>
          </div>
        </header>

        {NAV_GROUPS.map((group) => (
          <section key={group.name} className="docs-hub-section">
            <h2 className="docs-section-title">{group.name}</h2>
            <div className="docs-hub-grid">
              {group.links.map((link) => (
                <Link key={link.href} href={link.href} className="docs-hub-card">
                  <div className="docs-hub-kicker">{group.name}</div>
                  <div className="docs-hub-title">{link.title}</div>
                  <p className="docs-hub-blurb">{blurbFor(link.href)}</p>
                </Link>
              ))}
            </div>
          </section>
        ))}

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

function blurbFor(href: string): string {
  const slug = href.replace("/docs/", "");
  if (slug === "api/reference") {
    return `Every endpoint across the four planes — ${OPERATION_COUNT} operations generated from the same OpenAPI description you can download above.`;
  }
  return GUIDES.find((g) => g.slug === slug)?.blurb ?? "";
}
