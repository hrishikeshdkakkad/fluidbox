import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import "./geist.css";
import { webMode } from "./lib/proxy-auth";
import { THEME_INIT_SCRIPT } from "./lib/theme";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

/** Browser-facing base URL for canonical/OG metadata. Local default keeps
 *  dev builds working; deployments set NEXT_PUBLIC_SITE_URL. */
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "fluidbox — the open-source control plane for governed AI agents",
    template: "%s · fluidbox",
  },
  description:
    "Run AI agents without giving them God mode. Isolated sandboxes, server-side tool policy, human approval gates, budgets, and append-only audit receipts.",
  openGraph: {
    siteName: "fluidbox",
    type: "website",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "fluidbox — run AI agents without giving them God mode" }],
  },
  twitter: {
    card: "summary_large_image",
    images: ["/og.png"],
  },
};

export const viewport: Viewport = {
  colorScheme: "dark light",
  themeColor: "#111318",
};

// Static deployment configuration (see the proxy route): `sso` turns on the
// hosted session shell + login redirects; anything else is today's admin shell.
// Stamped onto <html data-web-mode> so client code (api.ts) is mode-aware
// without a second env var.
const WEB_MODE = webMode(process.env.FLUIDBOX_WEB_MODE);

// The root layout is chrome-free since the 2026-07-30 public-site split: the
// marketing/docs group ((site)/layout.tsx) and the dashboard (app/layout.tsx)
// each mount their own shells. Only fonts, theme, and global CSS live here.
export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable}`}
      data-theme="dark"
      data-web-mode={WEB_MODE}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
