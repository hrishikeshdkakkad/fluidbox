import { describe, expect, it } from "vitest";
import { outline, parseInline, parseMarkdown, slugify } from "./markdown";

describe("parseInline", () => {
  it("passes plain text through", () => {
    expect(parseInline("hello world")).toEqual([{ kind: "text", text: "hello world" }]);
  });

  it("parses code, strong, em, and links", () => {
    expect(parseInline("run `just dev` **now** on [docs](/developer) *soon*")).toEqual([
      { kind: "text", text: "run " },
      { kind: "code", text: "just dev" },
      { kind: "text", text: " " },
      { kind: "strong", text: "now" },
      { kind: "text", text: " on " },
      { kind: "link", text: "docs", href: "/developer" },
      { kind: "text", text: " " },
      { kind: "em", text: "soon" },
    ]);
  });

  it("keeps markdown inside code spans literal", () => {
    expect(parseInline("`**not bold**`")).toEqual([{ kind: "code", text: "**not bold**" }]);
  });

  it("does not treat a bare asterisk pair across words as emphasis greedily", () => {
    // "a * b * c" — the em pattern requires a non-space after the opener.
    expect(parseInline("a * b")).toEqual([{ kind: "text", text: "a * b" }]);
  });
});

describe("parseMarkdown", () => {
  it("parses headings with stable ids", () => {
    const blocks = parseMarkdown("## The permission gate");
    expect(blocks).toEqual([
      { kind: "heading", level: 2, text: "The permission gate", id: "the-permission-gate" },
    ]);
  });

  it("parses fenced code and keeps its content verbatim", () => {
    const blocks = parseMarkdown("```bash\ncurl -s $URL | jq .\n\n# comment\n```");
    expect(blocks).toEqual([
      { kind: "code", lang: "bash", text: "curl -s $URL | jq .\n\n# comment" },
    ]);
  });

  it("recovers from an unterminated fence by swallowing to EOF", () => {
    const blocks = parseMarkdown("```\nabc");
    expect(blocks).toEqual([{ kind: "code", lang: "", text: "abc" }]);
  });

  it("parses tables", () => {
    const blocks = parseMarkdown("| a | b |\n| --- | --- |\n| 1 | `x` |");
    expect(blocks).toEqual([
      {
        kind: "table",
        header: [[{ kind: "text", text: "a" }], [{ kind: "text", text: "b" }]],
        rows: [[[{ kind: "text", text: "1" }], [{ kind: "code", text: "x" }]]],
      },
    ]);
  });

  it("parses lists with continuation lines", () => {
    const blocks = parseMarkdown("- first line\n  continued here\n- second");
    expect(blocks).toEqual([
      {
        kind: "list",
        ordered: false,
        items: [
          [{ kind: "text", text: "first line continued here" }],
          [{ kind: "text", text: "second" }],
        ],
      },
    ]);
  });

  it("parses ordered lists", () => {
    const blocks = parseMarkdown("1. one\n2. two");
    expect(blocks[0]).toMatchObject({ kind: "list", ordered: true });
  });

  it("merges blockquote lines", () => {
    const blocks = parseMarkdown("> first\n> second");
    expect(blocks).toEqual([
      {
        kind: "quote",
        inline: [{ kind: "text", text: "first second" }],
      },
    ]);
  });

  it("joins wrapped paragraph lines and stops at structure", () => {
    const blocks = parseMarkdown("one\ntwo\n\n## next");
    expect(blocks).toEqual([
      { kind: "paragraph", inline: [{ kind: "text", text: "one two" }] },
      { kind: "heading", level: 2, text: "next", id: "next" },
    ]);
  });

  it("parses a horizontal rule", () => {
    expect(parseMarkdown("---")).toEqual([{ kind: "rule" }]);
  });

  it("does not confuse a rule with a table divider", () => {
    // A divider only counts when the previous line is a table header.
    const blocks = parseMarkdown("| just | text |\n\nplain");
    expect(blocks[0].kind).toBe("paragraph");
  });
});

describe("slugify", () => {
  it("matches the anchor convention", () => {
    expect(slugify("Four tokens, not one")).toBe("four-tokens-not-one");
    expect(slugify("The `go_url` leg")).toBe("the-go_url-leg");
  });
});

describe("outline", () => {
  it("lists h2s only", () => {
    const blocks = parseMarkdown("# t\n\n## a\n\n### deep\n\n## b");
    expect(outline(blocks)).toEqual([
      { id: "a", text: "a" },
      { id: "b", text: "b" },
    ]);
  });
});
