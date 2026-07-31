"use server";

import { webAuthMode } from "../lib/web-auth";

/** Sign out of the WorkOS web-tier session. A POST server action on purpose —
 *  never a GET route: link prefetch must not log people out, and a GET with a
 *  side effect is CSRF-exposable. The browser lands on the Logout URI
 *  registered for the environment (the site root). No-op outside workos mode
 *  (the dashboard renders no sign-out control there). */
export async function signOutAction(): Promise<void> {
  if (webAuthMode(process.env.FLUIDBOX_WEB_AUTH) !== "workos") return;
  const { signOut } = await import("@workos-inc/authkit-nextjs");
  await signOut();
}
