import { redirect } from "next/navigation";
import { APP_HOME } from "../lib/auth-gate";
import { webAuthMode } from "../lib/web-auth";

// Sign-up twin of /sign-in: the AuthKit hosted page opens on its sign-up
// screen. Outside workos mode there is no self-serve signup — hand off to
// /app and let the deployment's gate decide.
export async function GET() {
  if (webAuthMode(process.env.FLUIDBOX_WEB_AUTH) === "workos") {
    const { getSignUpUrl } = await import("@workos-inc/authkit-nextjs");
    redirect(await getSignUpUrl({ returnTo: APP_HOME }));
  }
  redirect(APP_HOME);
}
