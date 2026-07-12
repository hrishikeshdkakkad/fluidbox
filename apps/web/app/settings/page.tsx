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
      <PageHead title="Settings" sub="Control-plane health and how credentials are handled." />

      <div className="panel pad" style={{ maxWidth: 560 }}>
        <div className="sectitle" style={{ marginTop: 0 }}>
          Health
        </div>
        <Health label="Database (Neon Postgres)" ok={ready?.db ?? false} />
        <Health label="Sandbox runtime (Docker)" ok={ready?.docker ?? false} />

        <div className="sectitle">Security model</div>
        <ul style={{ margin: 0, paddingLeft: 18, color: "var(--ink-2)", fontSize: 13, lineHeight: 1.9 }}>
          <li>The admin token lives only server-side; the browser proxies through it.</li>
          <li>Sandboxes hold only a per-session token — never a provider key.</li>
          <li>The real model key lives only in the LiteLLM gateway.</li>
          <li>The ledger stores digests and usage, never raw prompts or secrets.</li>
        </ul>
      </div>
    </>
  );
}

function Health({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="spread" style={{ padding: "9px 0", borderBottom: "1px solid var(--border)" }}>
      <span style={{ fontSize: 13 }}>{label}</span>
      <span className={`badge ${ok ? "ok" : "err"}`}>{ok ? "connected" : "down"}</span>
    </div>
  );
}
