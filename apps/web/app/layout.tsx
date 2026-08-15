import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, Inter, Noto_Sans_JP, Noto_Sans_SC } from "next/font/google";
import "./globals.css";
import "./kernel.css";
import { webMode } from "./lib/proxy-auth";
import { SESSION_HINT_INIT_SCRIPT } from "./lib/session-hint";
import { THEME_INIT_SCRIPT } from "./lib/theme";

// The kernel.sh type stack: Inter for everything, IBM Plex Mono for code and
// labels, Noto JP/SC only for the decorative multilingual title echoes.
const interSans = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  weight: ["300", "400", "500"],
  subsets: ["latin"],
});

const notoJp = Noto_Sans_JP({
  variable: "--font-noto-jp",
  weight: ["300"],
  subsets: ["latin"],
  preload: false,
});

const notoSc = Noto_Sans_SC({
  variable: "--font-noto-sc",
  weight: ["300"],
  subsets: ["latin"],
  preload: false,
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
  colorScheme: "light dark",
  themeColor: "#f2f0e7",
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
      className={`${interSans.variable} ${plexMono.variable} ${notoJp.variable} ${notoSc.variable}`}
      data-theme="light"
      data-web-mode={WEB_MODE}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
        {/* Stamps data-session before first paint, the same way the theme is
            stamped. This is what lets the STATICALLY generated marketing pages
            show a signed-in header with no flash — see lib/session-hint. */}
        <script dangerouslySetInnerHTML={{ __html: SESSION_HINT_INIT_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
