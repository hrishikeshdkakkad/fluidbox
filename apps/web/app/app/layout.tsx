import type { Metadata } from "next";
import { Roboto, Roboto_Mono } from "next/font/google";
import { AuthKitProvider } from "@workos-inc/authkit-nextjs/components";
import "./material.css";
import { RouteFocus } from "../components/RouteFocus";
import { Sidebar, type WorkosSessionBadge } from "../components/Sidebar";
import { webMode } from "../lib/proxy-auth";
import { webAuthMode } from "../lib/web-auth";
import { signOutAction } from "./actions";

// The authenticated application shell. Everything under /app/* renders inside
// this chrome; the masthead's background polls (/approvals, /auth/me) belong
// here and only here — public routes carry their own chrome and never call
// authenticated APIs.
//
// The operational surface is never indexed: robots metadata here plus the
// robots.txt disallow are the two halves of that statement.
export const metadata: Metadata = {
  title: {
    // The root template appends "· fluidbox"; section layouts (Agents,
    // Settings, …) override through this template.
    default: "Overview",
    template: "%s · fluidbox",
  },
  robots: { index: false, follow: false },
};

// Deployment configuration can differ between build and runtime (the Docker
// image is built once, configured per environment). Rendering per request
// keeps the workos defense-in-depth check and the session UI on the RUNTIME
// configuration instead of whatever the build machine had; these pages are
// client-driven shells, so nothing meaningful was static here anyway.
export const dynamic = "force-dynamic";

const WEB_MODE = webMode(process.env.FLUIDBOX_WEB_MODE);
const AUTH = webAuthMode(process.env.FLUIDBOX_WEB_AUTH);

// The Material skin's faces (material.css --font-sans/--font-mono). Loaded on
// the app segment so the public site never pays for them; next/font
// self-hosts, so nothing is fetched at runtime.
const gemSans = Roboto({
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  variable: "--font-gem-app",
  display: "swap",
});
const gemMono = Roboto_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-gem-mono",
  display: "swap",
});

export default async function AppLayout({ children }: LayoutProps<"/app">) {
  // Defense in depth behind proxy.ts: any document request that reaches this
  // segment in workos mode re-validates the session server-side and redirects
  // to AuthKit when it is missing or expired. Also the (only) source of the
  // session badge — the client never derives auth state.
  let workosSession: WorkosSessionBadge | null = null;
  if (AUTH === "workos") {
    const { withAuth } = await import("@workos-inc/authkit-nextjs");
    const { user, organizationId } = await withAuth({ ensureSignedIn: true });
    const name = [user.firstName, user.lastName].filter(Boolean).join(" ");
    workosSession = {
      label: name || organizationId || "Signed in",
      email: user.email,
    };
  }

  const shell = (
    <div className={`shell ${gemSans.variable} ${gemMono.variable}`}>
      {/* First focusable element on the page; tabIndex on main makes the
          fragment target reliably take focus in every browser. RouteFocus
          handles the CLIENT-navigation half of the same contract. */}
      <a className="skip-link" href="#content">
        Skip to content
      </a>
      <Sidebar mode={WEB_MODE} workosSession={workosSession} signOut={signOutAction} />
      <main className="main" id="content" tabIndex={-1}>
        <RouteFocus />
        {children}
      </main>
    </div>
  );

  // AuthKitProvider carries client-side auth state (useAuth) for the app
  // subtree. Scoped here rather than the root layout on purpose: public
  // marketing/docs pages must not mount auth context, and every conceivable
  // useAuth consumer lives under /app. Not rendered in `none` mode, where
  // its background session endpoints have no configuration to talk to.
  return AUTH === "workos" ? <AuthKitProvider>{shell}</AuthKitProvider> : shell;
}
