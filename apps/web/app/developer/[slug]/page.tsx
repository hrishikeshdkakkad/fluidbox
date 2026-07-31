import Link from "next/link";
import { notFound } from "next/navigation";
import { outline, parseMarkdown } from "../../lib/markdown";
import { GUIDES } from "../generated/content";
import { MarkdownView } from "../MarkdownView";
import { docLink } from "../nav";
import { PrevNext } from "../PrevNext";
import { TocSpy } from "../TocSpy";

// One guide. Content is generated from docs/guides/ (just docs-sync); the
// static params make every guide a build-time page — nothing dynamic here.
export function generateStaticParams() {
  return GUIDES.map((g) => ({ slug: g.slug }));
}

export default async function GuidePage({ params }: PageProps<"/developer/[slug]">) {
  const { slug } = await params;
  const guide = GUIDES.find((g) => g.slug === slug);
  if (!guide) notFound();

  const href = `/developer/${guide.slug}`;
  const link = docLink(href);
  const toc = outline(parseMarkdown(guide.md));

  return (
    <div className="docs-columns">
      <article className="docs-article">
        <div className="docs-crumbs">
          <Link href="/developer">Docs</Link>
          <span aria-hidden>/</span>
          <span>{link?.group ?? "Guides"}</span>
        </div>
        <h1 className="docs-title">{guide.title}</h1>
        <MarkdownView md={guide.md} />
        <PrevNext href={href} />
      </article>
      <TocSpy items={toc} />
    </div>
  );
}
