import { codeToHtml } from "shiki";
import { CopyButton } from "./CopyButton";
import { MermaidBlock } from "./MermaidBlock";

// Server-side syntax highlighting for docs code fences. Every docs page is
// static, so shiki runs at build time — nothing ships to the client except
// the colored markup (and the copy button). Dual-theme: the dashboard
// defaults to dark (app/layout.tsx sets data-theme="dark"), so dark is the
// inline color and the light values ride --shiki-light variables that
// globals.css switches on under html[data-theme="light"].
export async function CodeBlock({ lang, text }: { lang: string; text: string }) {
  if (lang === "mermaid") {
    return <MermaidBlock text={text} />;
  }

  let html: string | null = null;
  if (lang && lang !== "text") {
    try {
      html = await codeToHtml(text, {
        lang,
        themes: { light: "github-light", dark: "github-dark" },
        defaultColor: "dark",
      });
    } catch {
      // Unknown grammar — fall through to the plain block.
    }
  }

  return (
    <div className="docs-code">
      {html !== null ? (
        <div data-lang={lang} dangerouslySetInnerHTML={{ __html: html }} />
      ) : (
        <pre data-lang={lang || undefined}>
          <code>{text}</code>
        </pre>
      )}
      <CopyButton text={text} />
    </div>
  );
}
