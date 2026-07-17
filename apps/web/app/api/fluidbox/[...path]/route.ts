// Same-origin proxy to the fluidbox control plane. The admin token is
// injected server-side and never reaches the browser. Handles JSON and SSE.

const API = process.env.FLUIDBOX_API_URL || "http://127.0.0.1:8787";
const TOKEN = process.env.FLUIDBOX_ADMIN_TOKEN || "";

export const dynamic = "force-dynamic";

async function forward(req: Request, path: string[]) {
  const url = new URL(req.url);
  const target = `${API}/v1/${path.join("/")}${url.search}`;

  const headers: Record<string, string> = {
    authorization: `Bearer ${TOKEN}`,
  };
  const ct = req.headers.get("content-type");
  if (ct) headers["content-type"] = ct;
  const lastEventId = req.headers.get("last-event-id");
  if (lastEventId) headers["last-event-id"] = lastEventId;
  const accept = req.headers.get("accept");
  if (accept) headers["accept"] = accept;

  const init: RequestInit = { method: req.method, headers };
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = await req.text();
  }

  const upstream = await fetch(target, init);

  // Stream SSE through untouched.
  const upstreamCt = upstream.headers.get("content-type") || "";
  if (upstreamCt.includes("event-stream")) {
    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-cache, no-transform",
        connection: "keep-alive",
      },
    });
  }

  const body = await upstream.text();
  return new Response(body, {
    status: upstream.status,
    headers: { "content-type": upstreamCt || "application/json" },
  });
}

type Ctx = { params: Promise<{ path: string[] }> };

export async function GET(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function POST(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function PUT(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
export async function DELETE(req: Request, ctx: Ctx) {
  return forward(req, (await ctx.params).path);
}
