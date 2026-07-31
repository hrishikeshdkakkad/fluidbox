import type { NextRequest } from "next/server";
import { APP_HOME } from "../lib/auth-gate";
import { webAuthMode } from "../lib/web-auth";

// WorkOS AuthKit callback (FLUIDBOX_WEB_AUTH=workos): exchanges the code,
// seals the session cookie, and returns the browser to the path recorded at
// sign-in (deep links survive the round trip; APP_HOME is the fallback).
//
// The SDK import is lazy and the mode is checked per request so deployments
// without WorkOS never load the SDK — in `none` mode this route simply does
// not exist. Registered redirect URI: <origin>/callback (see .env.example).
export async function GET(request: NextRequest) {
  if (webAuthMode(process.env.FLUIDBOX_WEB_AUTH) !== "workos") {
    return new Response("Not found", { status: 404 });
  }
  const { handleAuth } = await import("@workos-inc/authkit-nextjs");
  return handleAuth({ returnPathname: APP_HOME })(request);
}
