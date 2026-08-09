#!/usr/bin/env node
// Regenerates the public /docs content from docs/ at the repo root, plus the
// /changelog module from CHANGELOG.md.
//
//   node scripts/sync-developer-docs.mjs          (or: just docs-sync)
//
// docs/ is the source of truth (authored for the Redocly toolchain and linted
// by `just docs-lint`); the web app renders a generated COPY so the build
// stays self-contained — no fs reads at request time, no markdown dependency,
// no Redocly license, and no repo files outside apps/web at Docker build time
// (deploy/web.Dockerfile's context is apps/web alone — this constraint is why
// generated modules exist). The generated modules are checked in: a missing
// regeneration shows up as a diff, not as a broken page.
//
// Outputs:
//   app/(site)/docs/generated/content.ts    guide markdown as string exports
//   app/(site)/docs/generated/reference.ts  slim operation index from the spec
//   app/(site)/docs/generated/search.ts     per-section full-text search index
//   app/(site)/docs/generated/changelog.ts  parsed CHANGELOG.md releases
//   public/docs/openapi.yaml                the full spec, downloadable
//   public/docs/api.html                    the full Redoc reference (schemas,
//                                           examples), one static page

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Pinned: `latest` in a build path means a Redocly release can change lint
// results or the bundled output under us. Keep in sync with the justfile.
const REDOCLY = "@redocly/cli@2.41.2";

const webRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(webRoot, "..", "..");
const docsRoot = join(repoRoot, "docs");
const outDir = join(webRoot, "app", "(site)", "docs", "generated");
const publicDir = join(webRoot, "public", "docs");

// ---------------------------------------------------------------- guides --
// EVERY file in docs/guides/ must be listed: guides cross-link each other by
// `<slug>.md`, and the MarkdownView href rewriter maps those onto /docs/<slug>
// routes — an unlisted guide turns each of those links into a 404 (a check
// below refuses). Presentation order/grouping lives app-side in nav.ts.
const GUIDES = [
  { slug: "getting-started", file: "guides/getting-started.md", title: "Getting started" },
  { slug: "concepts", file: "guides/concepts.md", title: "Concepts" },
  { slug: "agents", file: "guides/agents.md", title: "Agents & revisions" },
  { slug: "runs", file: "guides/runs.md", title: "Runs & the timeline" },
  { slug: "triggers", file: "guides/triggers.md", title: "Triggers & schedules" },
  { slug: "governance", file: "guides/governance.md", title: "The permission gate" },
  { slug: "policies", file: "guides/policies.md", title: "Policies" },
  { slug: "approvals", file: "guides/approvals.md", title: "Approvals" },
  { slug: "capabilities", file: "guides/capabilities.md", title: "Capabilities" },
  { slug: "docker", file: "guides/docker.md", title: "Docker" },
  { slug: "kubernetes", file: "guides/kubernetes.md", title: "Kubernetes" },
  { slug: "security", file: "guides/security.md", title: "Security model" },
  { slug: "runner-contract", file: "guides/runner-contract.md", title: "Building a harness" },
  { slug: "authentication", file: "guides/authentication.md", title: "Authentication" },
  { slug: "api", file: "guides/api.md", title: "API overview" },
];

// The hub card shows plain text, so inline markdown is stripped rather than
// rendered: keep the words, drop the markers.
const stripInline = (s) =>
  s
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\*([^*\s][^*]*)\*/g, "$1")
    .replace(/`([^`]*)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");

const guides = GUIDES.map(({ slug, file, title }) => {
  const md = readFileSync(join(docsRoot, file), "utf8");
  // Drop the H1 (the page renders its own header) and pull the first
  // paragraph as the hub-card blurb / meta description.
  const body = md.replace(/^#\s+.*\n+/, "");
  const firstPara = stripInline(body.split(/\n\n/)[0].replace(/\n/g, " ").trim());
  return { slug, title, file: `docs/${file}`, blurb: firstPara, md: body };
});

// Refuse to generate a 404: every same-folder .md cross-link in a synced
// guide (or the hub's index.md) must resolve to a listed slug.
{
  const known = new Set(guides.map((g) => g.slug));
  const sources = [
    ...GUIDES.map((g) => ({ name: g.file, md: readFileSync(join(docsRoot, g.file), "utf8") })),
    { name: "index.md", md: readFileSync(join(docsRoot, "index.md"), "utf8") },
  ];
  for (const { name, md } of sources) {
    for (const m of md.matchAll(/\]\((?:\.\/)?(?:guides\/)?([a-z-]+)\.md(?:#[^)]*)?\)/g)) {
      if (!known.has(m[1])) {
        throw new Error(`${name} links to ${m[1]}.md, which is not in GUIDES — add it or the link 404s`);
      }
    }
  }
}

// The hub's "four planes" panel renders this section straight out of
// docs/index.md so the table exists in exactly one place. `---` rules delimit
// the sections there; the heading is dropped (the panel has its own title).
const indexMd = readFileSync(join(docsRoot, "index.md"), "utf8");
const planesHeading = "## The four planes";
const planesStart = indexMd.indexOf(planesHeading);
if (planesStart === -1) {
  throw new Error('docs/index.md no longer has a "## The four planes" section');
}
const planesRest = indexMd.slice(planesStart + planesHeading.length);
const planesEnd = planesRest.search(/\n---|\n## /);
const planesMd = (planesEnd === -1 ? planesRest : planesRest.slice(0, planesEnd)).trim();

// ---------------------------------------------------------------- search --
// One entry per heading-delimited section (plus the intro before the first
// heading). Anchors are NOT computed here: the client derives them with the
// SAME slugify the renderer uses (lib/markdown.ts), so index and page can
// never drift. Text is flattened to plain lowercase-searchable prose; code
// fences are kept (people search for flags and env vars) but fence markers
// and table pipes are dropped.
const searchSections = [];
for (const g of guides) {
  const lines = g.md.split("\n");
  let heading = null; // null = the intro section
  let buf = [];
  const flush = () => {
    const text = stripInline(
      buf
        .join(" ")
        .replace(/```\S*/g, " ")
        .replace(/\|/g, " ")
        .replace(/\s+/g, " ")
        .trim()
    );
    if (text || heading) {
      searchSections.push({
        slug: g.slug,
        title: g.title,
        heading: heading ?? "",
        text: text.slice(0, 1200),
      });
    }
    buf = [];
  };
  for (const line of lines) {
    const h = line.match(/^(#{2,3})\s+(.*)$/);
    if (h) {
      flush();
      heading = h[2].replace(/\s+#*\s*$/, "");
    } else {
      buf.push(line);
    }
  }
  flush();
}

// ------------------------------------------------------------- changelog --
// CHANGELOG.md → one entry per `## ` release heading. The preamble above the
// first release is dropped (the page carries its own intro); each entry keeps
// its body as markdown for MarkdownView.
const changelogMd = readFileSync(join(repoRoot, "CHANGELOG.md"), "utf8");
const releases = [];
{
  const parts = changelogMd.split(/^## /m).slice(1); // drop preamble
  for (const part of parts) {
    const nl = part.indexOf("\n");
    const headline = part.slice(0, nl).trim();
    const body = part.slice(nl + 1).trim();
    // Two heading shapes coexist: hand-written "[0.3.0] — 2026-07-24" /
    // "[Unreleased]", and release-please's linked "[0.6.0](compare-url)
    // (2026-08-05)". Both must yield a bare version + date, never raw
    // markdown in the version slot.
    const linked = headline.match(/^\[([^\]]+)\]\([^)]*\)\s*\(([^)]*)\)\s*$/);
    const plain = headline.match(/^\[([^\]]+)\](?:\s*[—-]\s*(.*))?$/);
    const m = linked ?? plain;
    const version = m ? m[1] : headline;
    const date = m && m[2] ? m[2].trim() : null;
    releases.push({ version, date, md: body });
  }
  if (releases.length === 0) {
    throw new Error("CHANGELOG.md yielded zero releases — parser or file moved");
  }
}

// ------------------------------------------------------------- reference --
// Bundle the spec to JSON with the same CLI that lints it, so $refs resolve
// identically to the published reference.
const bundled = JSON.parse(
  execFileSync(
    "npx",
    ["--yes", REDOCLY, "bundle", "api/openapi.yaml", "--ext", "json"],
    { cwd: docsRoot, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }
  )
);

const tagMeta = new Map((bundled.tags ?? []).map((t) => [t.name, t.description ?? ""]));
const METHODS = ["get", "put", "post", "delete", "patch"];

const opsByTag = new Map();
for (const [path, item] of Object.entries(bundled.paths ?? {})) {
  for (const method of METHODS) {
    const op = item[method];
    if (!op) continue;
    const tag = op.tags?.[0] ?? "Other";
    if (!opsByTag.has(tag)) opsByTag.set(tag, []);
    // Operation-level security wins over the document default (adminToken).
    const security = (op.security ?? bundled.security ?? [])
      .flatMap((s) => Object.keys(s))
      .filter((v, i, a) => a.indexOf(v) === i);
    opsByTag.get(tag).push({
      id: op.operationId,
      method: method.toUpperCase(),
      path,
      summary: op.summary ?? "",
      description: op.description ?? "",
      security,
      public: (op.security ?? []).length === 0 && op.security !== undefined,
    });
  }
}

const groups = (bundled["x-tagGroups"] ?? []).map((g) => ({
  name: g.name,
  tags: g.tags
    .filter((t) => opsByTag.has(t))
    .map((t) => ({
      name: t,
      description: tagMeta.get(t) ?? "",
      operations: opsByTag.get(t),
    })),
}));

const opCount = [...opsByTag.values()].reduce((n, ops) => n + ops.length, 0);
const grouped = groups.flatMap((g) => g.tags).reduce((n, t) => n + t.operations.length, 0);
if (grouped !== opCount) {
  throw new Error(
    `tag groups cover ${grouped} of ${opCount} operations — a tag is missing from x-tagGroups`
  );
}

// ----------------------------------------------------------------- write --
mkdirSync(outDir, { recursive: true });
mkdirSync(publicDir, { recursive: true });

const banner = `// GENERATED by scripts/sync-developer-docs.mjs — do not edit.
// Source of truth: docs/ at the repo root. Regenerate with \`just docs-sync\`.
`;

writeFileSync(
  join(outDir, "content.ts"),
  `${banner}
export type Guide = {
  slug: string;
  title: string;
  /** Repo-relative source path — feeds the "Edit this page on GitHub" link. */
  file: string;
  blurb: string;
  md: string;
};

export const GUIDES: Guide[] = ${JSON.stringify(guides, null, 2)};

/** The "four planes" section of docs/index.md — intro, table, and the
 *  Kubernetes note — rendered verbatim on the docs hub. */
export const PLANES_MD: string = ${JSON.stringify(planesMd)};
`
);

writeFileSync(
  join(outDir, "search.ts"),
  `${banner}
/** One heading-delimited section of a guide. \`heading\` is "" for the intro
 *  before the first heading; anchors are derived client-side with the same
 *  slugify the renderer uses. */
export type SearchSection = { slug: string; title: string; heading: string; text: string };

export const SEARCH_SECTIONS: SearchSection[] = ${JSON.stringify(searchSections, null, 1)};
`
);

writeFileSync(
  join(outDir, "changelog.ts"),
  `${banner}
export type Release = { version: string; date: string | null; md: string };

export const RELEASES: Release[] = ${JSON.stringify(releases, null, 2)};
`
);

writeFileSync(
  join(outDir, "reference.ts"),
  `${banner}
export type Operation = {
  id: string;
  method: string;
  path: string;
  summary: string;
  description: string;
  security: string[];
  public: boolean;
};
export type TagSection = { name: string; description: string; operations: Operation[] };
export type TagGroup = { name: string; tags: TagSection[] };

export const API_TITLE = ${JSON.stringify(bundled.info?.title ?? "API")};
export const API_VERSION = ${JSON.stringify(bundled.info?.version ?? "")};
export const OPERATION_COUNT = ${opCount};
export const GROUPS: TagGroup[] = ${JSON.stringify(groups, null, 2)};
`
);

copyFileSync(join(docsRoot, "api", "openapi.yaml"), join(publicDir, "openapi.yaml"));

// The full reference — request/response schemas, examples — as one static
// Redoc page. Served at /docs/api.html; the in-app browser links to it.
execFileSync(
  "npx",
  ["--yes", REDOCLY, "build-docs", "api/openapi.yaml", "-o", join(publicDir, "api.html")],
  { cwd: docsRoot, stdio: ["ignore", "inherit", "inherit"] }
);

console.log(
  `synced ${guides.length} guides, ${searchSections.length} search sections, ` +
    `${releases.length} changelog entries, ${opCount} operations across ${groups.length} groups`
);
