import Link from "next/link";
import { outline, parseMarkdown } from "../../lib/markdown";
import type { Guide } from "./generated/content";
import { MarkdownView } from "./MarkdownView";
import { docLink, GITHUB_EDIT_BASE, hrefFor } from "./nav";
import { PrevNext } from "./PrevNext";
import { TocSpy } from "./TocSpy";

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000";

// The one guide-page shape, shared by the [slug] segment and the literal
// /docs/api landing: breadcrumbs, article, edit-upstream link, pagination,
// on-page TOC, and the structured data search engines read.
export function GuideArticle({ guide }: { guide: Guide }) {
  const href = hrefFor(guide.slug);
  const link = docLink(href);
  const toc = outline(parseMarkdown(guide.md));

  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "TechArticle",
        headline: guide.title,
        description: guide.blurb,
        url: `${SITE_URL}${href}`,
        isPartOf: { "@type": "WebSite", name: "fluidbox", url: SITE_URL },
      },
      {
        "@type": "BreadcrumbList",
        itemListElement: [
          { "@type": "ListItem", position: 1, name: "Docs", item: `${SITE_URL}/docs` },
          ...(link
            ? [{ "@type": "ListItem", position: 2, name: link.group }]
            : []),
          {
            "@type": "ListItem",
            position: link ? 3 : 2,
            name: guide.title,
            item: `${SITE_URL}${href}`,
          },
        ],
      },
    ],
  };

  return (
    <div className="docs-columns">
      <article className="docs-article">
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        <div className="docs-crumbs">
          <Link href="/docs">Docs</Link>
          <span aria-hidden>/</span>
          <span>{link?.group ?? "Guides"}</span>
        </div>
        <h1 className="docs-title">{guide.title}</h1>
        <MarkdownView md={guide.md} />
        <div className="docs-edit">
          <a
            href={`${GITHUB_EDIT_BASE}${guide.file}`}
            target="_blank"
            rel="noreferrer"
          >
            Edit this page on GitHub ↗
          </a>
        </div>
        <PrevNext href={href} />
      </article>
      <TocSpy items={toc} />
    </div>
  );
}
