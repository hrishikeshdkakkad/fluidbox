import { redirect } from "next/navigation";
import { webMode } from "../lib/proxy-auth";
import LoginForm from "./login-form";

// Evaluate per request (not at build): the mode is read from the runtime env,
// exactly like the proxy route, so a build produced in one mode never bakes a
// stale redirect for a deployment configured in the other.
export const dynamic = "force-dynamic";

/**
 * Server boundary for /login. In admin (single-tenant / local) mode there is NO
 * login UI — the operator authenticates with the admin token — so /login
 * redirects to "/" server-side, before any client code loads. In sso mode it
 * renders the neutral org-entry form. The mode is deployment config
 * (FLUIDBOX_WEB_MODE), read here in a server component; the form itself stays a
 * client component.
 */
export default function LoginPage() {
  if (webMode(process.env.FLUIDBOX_WEB_MODE) === "admin") {
    redirect("/");
  }
  return <LoginForm />;
}
