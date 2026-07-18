import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import "./geist.css";
import { Sidebar } from "./components/Sidebar";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: {
    default: "fluidbox — control plane",
    template: "%s · fluidbox",
  },
  description: "Run AI coding agents in governed, disposable sandboxes.",
};

export const viewport: Viewport = {
  colorScheme: "dark",
  themeColor: "#000000",
};

// Static deployment configuration (see the proxy route): `sso` turns on the
// hosted session shell + login redirects; anything else is today's admin shell.
// Stamped onto <html data-web-mode> so client code (api.ts) is mode-aware
// without a second env var, and passed to the shell so it renders session UI.
const WEB_MODE = process.env.FLUIDBOX_WEB_MODE === "sso" ? "sso" : "admin";

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} dark dark-theme`}
      data-web-mode={WEB_MODE}
    >
      <body>
        <div className="shell">
          <Sidebar mode={WEB_MODE} />
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
