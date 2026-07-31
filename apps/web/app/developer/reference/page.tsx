import Link from "next/link";
import { MarkdownView } from "../MarkdownView";
import { API_VERSION, GROUPS, OPERATION_COUNT, type Operation } from "../generated/reference";
import { PrevNext } from "../PrevNext";

// The in-app API reference: a browsable operation index generated from
// docs/api/openapi.yaml (just docs-sync). Deliberately slim — summaries and
// descriptions render here; full request/response schemas and examples live
// in the Redoc-built /developer/api.html (same bundle), and the raw spec
// stays downloadable for generators and agents.

const METHOD_ORDER: Record<string, number> = { GET: 0, POST: 1, PATCH: 2, PUT: 3, DELETE: 4 };

function OpRow({ op }: { op: Operation }) {
  return (
    <details className="docs-op" id={op.id}>
      <summary>
        <span className={`docs-method docs-method-${op.method.toLowerCase()}`}>{op.method}</span>
        <code className="docs-path">{op.path}</code>
        <span className="docs-op-summary">{op.summary}</span>
      </summary>
      <div className="docs-op-body">
        {op.public ? (
          <p className="docs-op-auth">
            No bearer credential — see the description for what authenticates this call.
          </p>
        ) : (
          op.security.length > 0 && (
            <p className="docs-op-auth">
              Auth: {op.security.map((s) => <code key={s}>{s}</code>)}
            </p>
          )
        )}
        {op.description ? (
          <MarkdownView md={op.description} />
        ) : (
          <p className="note">No further description.</p>
        )}
      </div>
    </details>
  );
}

export default function ReferencePage() {
  return (
    <div className="docs-columns">
      <article className="docs-article docs-reference">
        <div className="docs-crumbs">
          <Link href="/developer">Docs</Link>
          <span aria-hidden>/</span>
          <span>Reference</span>
        </div>
        <h1 className="docs-title">API reference</h1>
        <p className="docs-lead">
          {OPERATION_COUNT} operations · v{API_VERSION} · generated from the OpenAPI description.
          Request and response schemas live in the{" "}
          <a href="/developer/api.html">full reference</a>; the{" "}
          <a href="/developer/openapi.yaml" download>
            raw spec
          </a>{" "}
          is what a generator or agent wants.
        </p>
        {GROUPS.map((group) => (
          <section key={group.name} className="docs-ref-group">
            <h2 id={anchor(group.name)}>
              <a href={`#${anchor(group.name)}`}>{group.name}</a>
            </h2>
            {group.tags.map((tag) => (
              <section key={tag.name} className="panel pad docs-ref-tag">
                <h3 id={anchor(tag.name)}>
                  <a href={`#${anchor(tag.name)}`}>{tag.name}</a>
                </h3>
                {tag.description && <MarkdownView md={tag.description} />}
                {[...tag.operations]
                  .sort(
                    (a, b) =>
                      a.path.localeCompare(b.path) ||
                      (METHOD_ORDER[a.method] ?? 9) - (METHOD_ORDER[b.method] ?? 9)
                  )
                  .map((op) => (
                    <OpRow key={op.id} op={op} />
                  ))}
              </section>
            ))}
          </section>
        ))}
        <PrevNext href="/developer/reference" />
      </article>
      <nav className="docs-toc" aria-label="Sections">
        <div className="docs-toc-title">Planes</div>
        {GROUPS.map((g) => (
          <div key={g.name} className="docs-toc-group">
            <a href={`#${anchor(g.name)}`}>{g.name}</a>
            {g.tags.map((t) => (
              <a key={t.name} className="docs-toc-sub" href={`#${anchor(t.name)}`}>
                {t.name}
              </a>
            ))}
          </div>
        ))}
      </nav>
    </div>
  );
}

function anchor(name: string): string {
  return name.toLowerCase().replace(/\s+/g, "-");
}
