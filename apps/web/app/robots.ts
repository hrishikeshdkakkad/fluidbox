import type { MetadataRoute } from "next";

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000";

// The public surface indexes; the operational surface never does. This is
// one half of the statement — the /app layout and /login page also carry
// robots noindex metadata, so a crawler that ignores robots.txt still gets
// the per-page answer.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: ["/app", "/api/", "/login", "/callback", "/sign-in", "/sign-up"],
      },
    ],
    sitemap: `${SITE_URL}/sitemap.xml`,
  };
}
