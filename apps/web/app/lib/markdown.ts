// A deliberately small markdown tokenizer for the in-app developer docs.
//
// The source of truth for the docs is docs/ at the repo root (authored for the
// Redocly toolchain); scripts/sync-developer-docs.mjs copies the guides into a
// generated module and THIS parser renders them natively so the dashboard
// needs no markdown dependency and no Redocly license at runtime.
//
// Scope is exactly what the guides use — headings, paragraphs, fenced code,
// tables, lists, blockquotes, rules — plus inline code/bold/links. It is a
// pure function so it carries unit tests (vitest is node-env only; see
// vitest.config.ts for why component logic lives in lib/).

export type Inline =
  | { kind: "text"; text: string }
  | { kind: "code"; text: string }
  | { kind: "strong"; text: string }
  | { kind: "em"; text: string }
  | { kind: "link"; text: string; href: string };

export type Block =
  | { kind: "heading"; level: number; text: string; id: string }
  | { kind: "paragraph"; inline: Inline[] }
  | { kind: "code"; lang: string; text: string }
  | { kind: "list"; ordered: boolean; items: Inline[][] }
  | { kind: "quote"; inline: Inline[] }
  | { kind: "table"; header: Inline[][]; rows: Inline[][][] }
  | { kind: "rule" };

/** Stable anchor id for a heading (matches the GitHub convention closely
 *  enough for our own intra-doc links). */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/`/g, "")
    .replace(/[^a-z0-9_\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");
}

/** Parse inline markdown: `code`, **strong**, *em*, [text](href). Code spans
 *  win over everything (their content is literal); the rest cannot nest. */
export function parseInline(src: string): Inline[] {
  const out: Inline[] = [];
  // Tokenize code spans first so `**not bold**` inside backticks stays literal.
  const parts = src.split(/(`[^`]*`)/g);
  for (const part of parts) {
    if (part === "") continue;
    if (part.startsWith("`") && part.endsWith("`") && part.length >= 2) {
      out.push({ kind: "code", text: part.slice(1, -1) });
      continue;
    }
    // Non-code text: links, then bold, then em.
    let rest = part;
    const pattern = /\[([^\]]+)\]\(([^)\s]+)\)|\*\*([^*]+)\*\*|\*([^*\s][^*]*)\*/;
    for (;;) {
      const m = rest.match(pattern);
      if (!m || m.index === undefined) {
        if (rest) out.push({ kind: "text", text: rest });
        break;
      }
      if (m.index > 0) out.push({ kind: "text", text: rest.slice(0, m.index) });
      if (m[1] !== undefined && m[2] !== undefined) {
        out.push({ kind: "link", text: m[1], href: m[2] });
      } else if (m[3] !== undefined) {
        out.push({ kind: "strong", text: m[3] });
      } else if (m[4] !== undefined) {
        out.push({ kind: "em", text: m[4] });
      }
      rest = rest.slice(m.index + m[0].length);
    }
  }
  return out;
}

function splitRow(line: string): string[] {
  // "| a | b |" → ["a", "b"]. Escaped pipes are not used in our docs.
  return line
    .replace(/^\s*\|/, "")
    .replace(/\|\s*$/, "")
    .split("|")
    .map((c) => c.trim());
}

const isTableDivider = (line: string) =>
  /^\s*\|?\s*:?-{3,}/.test(line) && /^[\s|:-]+$/.test(line);

/** Parse a markdown document into blocks. Unknown constructs degrade to
 *  paragraphs rather than throwing — the docs render, worst case unstyled. */
export function parseMarkdown(src: string): Block[] {
  const lines = src.replace(/\r\n/g, "\n").split("\n");
  const blocks: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim() === "") {
      i += 1;
      continue;
    }

    // Fenced code. The closing fence is required; an unterminated fence
    // swallows to EOF, which is the least surprising recovery.
    const fence = line.match(/^```(\S*)\s*$/);
    if (fence) {
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) {
        body.push(lines[i]);
        i += 1;
      }
      i += 1; // consume the closing fence (or EOF)
      blocks.push({ kind: "code", lang: fence[1] ?? "", text: body.join("\n") });
      continue;
    }

    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      const text = heading[2].replace(/\s+#*\s*$/, "");
      blocks.push({
        kind: "heading",
        level: heading[1].length,
        text,
        id: slugify(text),
      });
      i += 1;
      continue;
    }

    if (/^(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      blocks.push({ kind: "rule" });
      i += 1;
      continue;
    }

    if (/^\s*>/.test(line)) {
      const quoted: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) {
        quoted.push(lines[i].replace(/^\s*>\s?/, ""));
        i += 1;
      }
      blocks.push({ kind: "quote", inline: parseInline(quoted.join(" ")) });
      continue;
    }

    // Table: a header row immediately followed by a divider row.
    if (line.includes("|") && i + 1 < lines.length && isTableDivider(lines[i + 1])) {
      const header = splitRow(line).map(parseInline);
      i += 2;
      const rows: Inline[][][] = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim() !== "") {
        rows.push(splitRow(lines[i]).map(parseInline));
        i += 1;
      }
      blocks.push({ kind: "table", header, rows });
      continue;
    }

    const listMatch = line.match(/^(\s*)([-*]|\d+\.)\s+/);
    if (listMatch) {
      const ordered = /\d/.test(listMatch[2]);
      const items: Inline[][] = [];
      while (i < lines.length) {
        const m = lines[i].match(/^(\s*)([-*]|\d+\.)\s+(.*)$/);
        if (!m) break;
        // Continuation lines (indented, non-list) belong to the current item.
        let item = m[3];
        i += 1;
        while (
          i < lines.length &&
          lines[i].trim() !== "" &&
          !lines[i].match(/^(\s*)([-*]|\d+\.)\s+/) &&
          /^\s{2,}/.test(lines[i])
        ) {
          item += ` ${lines[i].trim()}`;
          i += 1;
        }
        items.push(parseInline(item));
      }
      blocks.push({ kind: "list", ordered, items });
      continue;
    }

    // Paragraph: consume until a blank line or a structural opener.
    const para: string[] = [line];
    i += 1;
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !/^(#{1,6})\s/.test(lines[i]) &&
      !/^```/.test(lines[i]) &&
      !/^\s*>/.test(lines[i]) &&
      !lines[i].match(/^(\s*)([-*]|\d+\.)\s+/) &&
      !(lines[i].includes("|") && i + 1 < lines.length && isTableDivider(lines[i + 1]))
    ) {
      para.push(lines[i]);
      i += 1;
    }
    blocks.push({ kind: "paragraph", inline: parseInline(para.join(" ")) });
  }

  return blocks;
}

/** The h2 outline of a document — feeds the on-page table of contents. */
export function outline(blocks: Block[]): { id: string; text: string }[] {
  return blocks
    .filter((b): b is Extract<Block, { kind: "heading" }> => b.kind === "heading")
    .filter((h) => h.level === 2)
    .map((h) => ({ id: h.id, text: h.text }));
}
