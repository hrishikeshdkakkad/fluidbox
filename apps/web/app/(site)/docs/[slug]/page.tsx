import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { GUIDES } from "../generated/content";
import { GuideArticle } from "../GuideArticle";
import { hrefFor } from "../nav";

// One guide. Content is generated from docs/guides/ (just docs-sync); the
// static params make every guide a build-time page — nothing dynamic here.
// `api` is deliberately absent: the literal /docs/api route serves that
// guide (same URL, same article shape) so the API section can own its
// subtree (/docs/api/reference lives under it).
export function generateStaticParams() {
  return GUIDES.filter((g) => g.slug !== "api").map((g) => ({ slug: g.slug }));
}

export const dynamicParams = false;

export async function generateMetadata({
  params,
}: PageProps<"/docs/[slug]">): Promise<Metadata> {
  const { slug } = await params;
  const guide = GUIDES.find((g) => g.slug === slug);
  if (!guide) return {};
  return {
    title: guide.title,
    description: guide.blurb,
    alternates: { canonical: hrefFor(guide.slug) },
    openGraph: {
      title: `${guide.title} · fluidbox docs`,
      description: guide.blurb,
      type: "article",
      url: hrefFor(guide.slug),
    },
  };
}

export default async function GuidePage({ params }: PageProps<"/docs/[slug]">) {
  const { slug } = await params;
  const guide = GUIDES.find((g) => g.slug === slug && g.slug !== "api");
  if (!guide) notFound();
  return <GuideArticle guide={guide} />;
}
