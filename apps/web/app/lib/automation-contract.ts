/** Pure integration-contract helpers shared by the composer preview, the
 *  one-time secrets modal, and the durable automation detail page. Keeping
 *  them here (tested, presentation-free) is what lets three surfaces render
 *  the SAME contract without drifting. */

/** Placeholders the platform fills in itself, per trigger kind. Anything
 *  else is the caller's (api kind) or refused at save (schedule/event fire
 *  with no caller). The event list mirrors connectors/github.rs
 *  sample_context() — keep them in lockstep. */
export const SYSTEM_VARIABLES: Record<string, string[]> = {
  schedule: ["fire_time"],
  event: [
    "repository", "pr_number", "pr_title", "pr_url", "pr_author",
    "head_sha", "head_ref", "base_sha", "base_ref", "action", "event", "fork",
  ],
  api: [],
};

export function templateVariables(template: string | null): string[] {
  if (!template) return [];
  const found = new Set<string>();
  for (const match of template.matchAll(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g)) {
    found.add(match[1]);
  }
  return [...found];
}

export function classifyVariables(
  kind: string,
  template: string | null
): { caller: string[]; system: string[]; invalid: string[] } {
  const systemNames = SYSTEM_VARIABLES[kind] ?? [];
  const declared = templateVariables(template);
  const system = declared.filter((name) => systemNames.includes(name));
  const rest = declared.filter((name) => !systemNames.includes(name));
  // schedule/event fire with no caller: an unknown placeholder can never be
  // filled and the server refuses it at save — that's an error, not a
  // caller variable.
  const noCaller = kind === "schedule" || kind === "event";
  return {
    system,
    caller: noCaller ? [] : rest,
    invalid: noCaller ? rest : [],
  };
}

export function contextExample(caller: string[]): string {
  if (caller.length === 0) return "{}";
  return `{"context": {${caller.map((name) => `"${name}": "…"`).join(", ")}}}`;
}

/** token null → the durable view: the secret is the caller's to hold, so
 *  the curl reads it from the environment — double quotes, or the shell
 *  ships the literal dollar text. hasTemplate false → the automation has no
 *  stored template (override-only), so invoke REQUIRES a task in the body. */
export function buildCurl(opts: {
  invokeUrl: string;
  token: string | null;
  caller: string[];
  hasTemplate: boolean;
}): string {
  const auth = opts.token
    ? `  -H 'Authorization: Bearer ${opts.token}' \\`
    : `  -H "Authorization: Bearer \${FLUIDBOX_TRIGGER_TOKEN}" \\`;
  const body = opts.hasTemplate
    ? contextExample(opts.caller)
    : `{"task": "…what this invocation should do…"}`;
  return [
    `curl -X POST '${opts.invokeUrl}' \\`,
    auth,
    `  -H 'Content-Type: application/json' \\`,
    `  -H 'Idempotency-Key: <your-unique-key>' \\`,
    `  -d '${body}'`,
  ].join("\n");
}
