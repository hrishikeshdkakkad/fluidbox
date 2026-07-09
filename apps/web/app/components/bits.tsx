import React from "react";

export function Pill({ status }: { status: string }) {
  const label = status.replace(/_/g, " ");
  return (
    <span className={`pill ${status}`}>
      <span className="dot" />
      {label}
    </span>
  );
}

export function AutoPill({ autonomy }: { autonomy: string }) {
  return <span className={`autopill ${autonomy}`}>{autonomy}</span>;
}

export function short(id: string, n = 8): string {
  return id.slice(0, n);
}

export function PageHead({
  eyebrow,
  title,
  sub,
  right,
}: {
  eyebrow: string;
  title: string;
  sub?: string;
  right?: React.ReactNode;
}) {
  return (
    <div className="pagehead">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1 className="title">{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {right}
    </div>
  );
}

/** Render a unified diff with add/del/hunk coloring. */
export function DiffView({ content }: { content: string }) {
  if (!content || content === "(no changes)") {
    return <div className="empty">no file changes</div>;
  }
  const lines = content.split("\n");
  return (
    <div className="diff">
      {lines.map((ln, i) => {
        let cls = "ln";
        if (ln.startsWith("+") && !ln.startsWith("+++")) cls += " add";
        else if (ln.startsWith("-") && !ln.startsWith("---")) cls += " del";
        else if (ln.startsWith("diff ") || ln.startsWith("index ") || ln.startsWith("+++") || ln.startsWith("---"))
          cls += " hdr";
        else if (ln.startsWith("@@")) cls += " at";
        return (
          <div key={i} className={cls}>
            {ln || " "}
          </div>
        );
      })}
    </div>
  );
}
