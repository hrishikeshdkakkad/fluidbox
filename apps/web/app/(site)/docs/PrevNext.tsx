import Link from "next/link";
import { prevNext } from "./nav";

// Foot-of-page pagination: where you came from, where to go next.
export function PrevNext({ href }: { href: string }) {
  const { prev, next } = prevNext(href);
  if (!prev && !next) return null;
  return (
    <nav className="docs-pagenav" aria-label="Pagination">
      {prev ? (
        <Link href={prev.href} className="docs-pagenav-card">
          <span className="docs-pagenav-dir">← Previous</span>
          <span className="docs-pagenav-title">{prev.title}</span>
        </Link>
      ) : (
        <span />
      )}
      {next ? (
        <Link href={next.href} className="docs-pagenav-card next">
          <span className="docs-pagenav-dir">Next →</span>
          <span className="docs-pagenav-title">{next.title}</span>
        </Link>
      ) : (
        <span />
      )}
    </nav>
  );
}
