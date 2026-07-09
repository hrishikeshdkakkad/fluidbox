"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { apiGet, apiPost, Approval } from "../lib/api";
import { PageHead, short } from "../components/bits";

export default function Approvals() {
  const [approvals, setApprovals] = useState<Approval[]>([]);

  const load = useCallback(async () => {
    const r = await apiGet<{ approvals: Approval[] }>("/approvals");
    setApprovals(r.approvals);
  }, []);

  useEffect(() => {
    load().catch(() => {});
    const t = setInterval(() => load().catch(() => {}), 3000);
    return () => clearInterval(t);
  }, [load]);

  const decide = async (id: string, decision: string) => {
    await apiPost(`/approvals/${id}/decision`, { decision, decided_by: "dashboard" });
    load();
  };

  return (
    <>
      <PageHead
        eyebrow="human in the loop"
        title="Approvals"
        sub="Risky tool calls pause here. Silence past the deadline auto-denies — it never means yes."
      />

      {approvals.length === 0 ? (
        <div className="panel">
          <div className="empty">inbox clear — no runs are waiting on you</div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {approvals.map((a) => (
            <div className="approval" key={a.id}>
              <span className="icon">⏸</span>
              <div className="txt">
                <div className="h">
                  {a.tool}
                  {a.risk ? ` · ${a.risk}` : ""}
                </div>
                <div className="d mono" style={{ fontSize: 13 }}>
                  {a.summary}
                </div>
                <div className="mut mono" style={{ fontSize: 11, marginTop: 4 }}>
                  session{" "}
                  <Link href={`/sessions/${a.session_id}`} className="link">
                    {short(a.session_id)}
                  </Link>{" "}
                  · expires {new Date(a.expires_at).toLocaleTimeString()}
                </div>
              </div>
              <div className="acts">
                <button className="btn human" onClick={() => decide(a.id, "approved_once")}>
                  Approve once
                </button>
                <button className="btn sm ghost" onClick={() => decide(a.id, "approved_session")}>
                  Session
                </button>
                <button className="btn sm ghost danger" onClick={() => decide(a.id, "denied")}>
                  Deny
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
