import { SectionReveal } from "./components/SectionReveal";
import { SiteHeader } from "./components/SiteHeader";
import { SiteFooter } from "./components/SiteFooter";

// The public-surface route group: marketing pages, /docs, /changelog — one
// shared chrome (header + footer), no session, no authenticated calls. The
// dashboard under /app mounts its own shell instead.
export default function SiteLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="site-page">
      <a className="skip-link" href="#content">
        Skip to content
      </a>
      <SiteHeader />
      <main id="content" className="site-main">
        {children}
      </main>
      <SectionReveal />
      <SiteFooter />
    </div>
  );
}
