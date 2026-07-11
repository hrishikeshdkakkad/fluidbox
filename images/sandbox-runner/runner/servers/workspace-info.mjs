// fluidbox workspace-info — the packaged SANDBOX-class MCP server (design
// §8.3 class 1): a stdio subprocess inside the sandbox, credential-free by
// construction, contained by the container. It only ever reads the mounted
// workspace; no network, no secrets, no writes. Bundles reference it as
//   { class: "sandbox", command: "node",
//     args: ["/opt/fluidbox-runner/servers/workspace-info.mjs"], ... }
// with its tools DECLARED in the bundle (sandbox photographs are declared,
// not discovered) — the gate denies anything outside that declaration.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import fs from "node:fs";
import path from "node:path";

const WORKSPACE = process.env.FLUIDBOX_WORKSPACE || "/workspace";
const MAX_FILES = 20000;
const MAX_FILE_BYTES = 1024 * 1024;

function* walk(dir, budget) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (budget.files >= MAX_FILES) return;
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full, budget);
    } else if (entry.isFile()) {
      budget.files += 1;
      yield full;
    }
  }
}

function fileCount() {
  const budget = { files: 0 };
  let bytes = 0;
  for (const f of walk(WORKSPACE, budget)) {
    try {
      bytes += fs.statSync(f).size;
    } catch {
      /* raced deletion — counts stay approximate */
    }
  }
  return { files: budget.files, bytes };
}

function grepCount(pattern) {
  const budget = { files: 0 };
  let matches = 0;
  let filesWithMatch = 0;
  for (const f of walk(WORKSPACE, budget)) {
    let text;
    try {
      const stat = fs.statSync(f);
      if (stat.size > MAX_FILE_BYTES) continue;
      text = fs.readFileSync(f, "utf8");
    } catch {
      continue;
    }
    let inFile = 0;
    for (const line of text.split("\n")) {
      if (line.includes(pattern)) inFile += 1;
    }
    if (inFile > 0) {
      matches += inFile;
      filesWithMatch += 1;
    }
  }
  return { matches, files_with_match: filesWithMatch };
}

const TOOLS = [
  {
    name: "workspace_file_count",
    description:
      "Count the files (and total bytes) in the run's workspace. Reads the mounted /workspace only.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "workspace_grep_count",
    description:
      "Count lines in workspace files containing a plain-text pattern (no regex). Reads the mounted /workspace only.",
    inputSchema: {
      type: "object",
      properties: { pattern: { type: "string", description: "plain substring to count" } },
      required: ["pattern"],
      additionalProperties: false,
    },
  },
];

const server = new Server(
  { name: "fluidbox-workspace-info", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  try {
    if (name === "workspace_file_count") {
      return { content: [{ type: "text", text: JSON.stringify(fileCount()) }] };
    }
    if (name === "workspace_grep_count") {
      const pattern = String(args?.pattern ?? "");
      if (!pattern) {
        return { content: [{ type: "text", text: "pattern is required" }], isError: true };
      }
      return { content: [{ type: "text", text: JSON.stringify(grepCount(pattern)) }] };
    }
    return { content: [{ type: "text", text: `unknown tool '${name}'` }], isError: true };
  } catch (e) {
    return { content: [{ type: "text", text: String(e?.message || e) }], isError: true };
  }
});

await server.connect(new StdioServerTransport());
