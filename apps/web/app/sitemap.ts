import type { MetadataRoute } from "next";
import { DOC_LINKS } from "./(site)/docs/nav";

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000";

// Public, indexable surface only. The application (/app), the auth legs, and
// the API proxy are deliberately absent — robots.ts disallows them and the
// /app layout carries noindex metadata besides.
export default function sitemap(): MetadataRoute.Sitemap {
  const marketing = ["", "/product", "/open-source", "/security", "/changelog", "/pricing"];
  const docs = ["/docs", ...DOC_LINKS.map((l) => l.href)];
  return [...marketing, ...docs].map((path) => ({
    url: `${SITE_URL}${path}`,
    changeFrequency: path === "/changelog" ? "weekly" : "monthly",
    priority: path === "" ? 1 : path.startsWith("/docs") ? 0.7 : 0.8,
  }));
}
