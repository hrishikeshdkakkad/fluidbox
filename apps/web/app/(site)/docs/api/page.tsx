import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { GUIDES } from "../generated/content";
import { GuideArticle } from "../GuideArticle";

// The API section landing (/docs/api): the api guide rendered through the
// standard article shape, sitting above /docs/api/reference and next to the
// static /docs/api.html + /docs/openapi.yaml assets it links.
const guide = GUIDES.find((g) => g.slug === "api");

export const metadata: Metadata = guide
  ? {
      title: guide.title,
      description: guide.blurb,
      alternates: { canonical: "/docs/api" },
      openGraph: {
        title: `${guide.title} · fluidbox docs`,
        description: guide.blurb,
        type: "article",
        url: "/docs/api",
      },
    }
  : {};

export default function ApiOverviewPage() {
  if (!guide) notFound();
  return <GuideArticle guide={guide} />;
}
