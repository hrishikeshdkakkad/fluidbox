"use client";

import { useEffect, useState } from "react";
import { apiGet } from "../lib/api";
import { PageHead } from "../components/bits";

export default function Settings() {
  const [ready, setReady] = useState<{ db: boolean; docker: boolean } | null>(null);

  useEffect(() => {
    apiGet<{ db: boolean; docker: boolean }>("/health/ready")
      .then(setReady)
      .catch(() => setReady(null));
  }, []);

  return (
    <>
      <PageHead eyebrow="system" title="Settings" sub="Control-plane health and connection facts." />

      <div className="panel pad" style={{ maxWidth: 560 }}>
        <div className="sectitle" style={{ marginTop: 0 }}>
          health
        </div>
        <Health label="Database (Neon Postgres)" ok={ready?.db ?? false} />
        <Health label="Sandbox runtime (Docker)" ok={ready?.docker ?? false} />

        <div className="sectitle">security model</div>
        <ul style={{ margin: 0, paddingLeft: 18, color: "var(--ink-dim)", fontSize: 13.5, lineHeight: 1.9 }}>
          <li>The admin token lives only server-side; the browser proxies through it.</li>
          <li>Sandboxes hold only a per-session token — never a provider key.</li>
          <li>The real model key lives only in the LiteLLM gateway.</li>
          <li>The ledger stores digests + usage, never raw prompts or secrets.</li>
        </ul>
      </div>
    </>
  );
}

function Health({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="spread" style={{ padding: "9px 0", borderBottom: "1px solid var(--line-soft)" }}>
      <span style={{ fontSize: 13.5 }}>{label}</span>
      <span className="pill" style={{ color: ok ? "var(--good)" : "var(--danger)", borderColor: ok ? "#275a3f" : "#6b302a" }}>
        <span className="dot" />
        {ok ? "connected" : "down"}
      </span>
    </div>
  );
}
