import Link from "next/link";

const REPO = "https://github.com/hrishikeshdkakkad/fluidbox";

const COLUMNS: { title: string; links: { href: string; label: string; external?: boolean }[] }[] = [
  {
    title: "Product",
    links: [
      { href: "/product", label: "Overview" },
      { href: "/pricing", label: "Pricing" },
      { href: "/changelog", label: "Changelog" },
      { href: "/app", label: "Dashboard" },
    ],
  },
  {
    title: "Documentation",
    links: [
      { href: "/docs/getting-started", label: "Getting started" },
      { href: "/docs/concepts", label: "Concepts" },
      { href: "/docs/api", label: "API" },
      { href: "/docs/kubernetes", label: "Kubernetes" },
    ],
  },
  {
    title: "Project",
    links: [
      { href: REPO, label: "GitHub", external: true },
      { href: `${REPO}/blob/main/ROADMAP.md`, label: "Roadmap", external: true },
      { href: `${REPO}/blob/main/CONTRIBUTING.md`, label: "Contributing", external: true },
      {
        href: `${REPO}/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22`,
        label: "Good first issues",
        external: true,
      },
    ],
  },
  {
    title: "Trust",
    links: [
      { href: "/security", label: "Security" },
      { href: `${REPO}/blob/main/SECURITY.md`, label: "Disclosure policy", external: true },
      { href: `${REPO}/blob/main/LICENSE`, label: "MIT license", external: true },
      { href: `${REPO}/blob/main/CODE_OF_CONDUCT.md`, label: "Code of conduct", external: true },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="site-container">
        <div className="site-footer-grid">
          <div className="site-footer-brand">
            <span className="wordmark">fluidbox</span>
            <p>
              The open-source control plane for governed AI agents. Run agents
              without giving them God&nbsp;mode.
            </p>
          </div>
          {COLUMNS.map((col) => (
            <nav key={col.title} aria-label={col.title}>
              <div className="site-footer-title">{col.title}</div>
              <ul>
                {col.links.map((l) =>
                  l.external ? (
                    <li key={l.label}>
                      <a href={l.href} target="_blank" rel="noreferrer">
                        {l.label} ↗
                      </a>
                    </li>
                  ) : (
                    <li key={l.label}>
                      <Link href={l.href}>{l.label}</Link>
                    </li>
                  )
                )}
              </ul>
            </nav>
          ))}
        </div>
        <div className="site-footer-bottom">
          <span>fluidbox — MIT licensed, built in the open.</span>
          <a href={REPO} target="_blank" rel="noreferrer">
            github.com/hrishikeshdkakkad/fluidbox
          </a>
        </div>
      </div>
    </footer>
  );
}
