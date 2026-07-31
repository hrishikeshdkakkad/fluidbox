"use client";

import { useEffect, useState } from "react";
import { apiGet } from "../../lib/api";
import { PageHead } from "../../components/bits";

export default function Settings() {
  // Field names must match `health_ready` in crates/fluidbox-server/src/api.rs —
  // this generic is an unchecked assertion, not a verified contract.
  const [ready, setReady] = useState<{ db: boolean; provider_ok: boolean } | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");

  useEffect(() => {
    apiGet<{ db: boolean; provider_ok: boolean }>("/health/ready")
      .then((response) => {
        setReady(response);
        setStatus("ready");
      })
      .catch(() => setStatus("error"));
  }, []);

  return (
    <>
      <PageHead title="Settings" sub="Control-plane health and how credentials are handled." />

      <div className="panel pad" style={{ maxWidth: 560 }}>
        <div className="sectitle" style={{ marginTop: 0 }}>
          Health
        </div>
        {status === "error" && (
          <p className="note">Health status is unavailable; no component is being reported down from a failed read.</p>
        )}
        <Health label="Database (Neon Postgres)" status={status} ok={ready?.db} />
        <Health label="Sandbox runtime (Docker)" status={status} ok={ready?.provider_ok} />

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

function Health({
  label,
  ok,
  status,
}: {
  label: string;
  /** `undefined` = the read succeeded but said nothing about this component. */
  ok: boolean | undefined;
  status: "loading" | "ready" | "error";
}) {
  // TODO(you): decide how a successful read that OMITS this component should render.
  // Today `undefined` falls through to "down"/err — the same output as an observed
  // failure — which is what made the Docker row lie when the API renamed the field.
  const labelText = status === "loading" ? "checking" : status === "error" ? "unavailable" : ok ? "connected" : "down";
  const badgeTone = status === "ready" ? (ok ? "ok" : "err") : "warn";
  return (
    <div className="spread" style={{ padding: "9px 0", borderBottom: "1px solid var(--border)" }}>
      <span style={{ fontSize: 13 }}>{label}</span>
      <span className={`badge ${badgeTone}`}>{labelText}</span>
    </div>
  );
}
