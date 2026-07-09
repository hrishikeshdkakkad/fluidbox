"use client";

import { useEffect, useState, useCallback } from "react";
import { apiGet, apiPost } from "../lib/api";
import { PageHead } from "../components/bits";

interface PolicyRow {
  id: string;
  name: string;
  version: number;
  yaml_source: string;
}

export default function Policies() {
  const [policies, setPolicies] = useState<PolicyRow[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [yaml, setYaml] = useState("");
  const [name, setName] = useState("");
  const [validity, setValidity] = useState<{ ok: boolean; msg: string } | null>(null);
  const [saved, setSaved] = useState(false);

  const load = useCallback(async () => {
    const r = await apiGet<{ policies: PolicyRow[] }>("/policies");
    setPolicies(r.policies);
    if (!selected && r.policies.length) {
      const first = r.policies[0];
      setSelected(first.id);
      setName(first.name);
      setYaml(first.yaml_source);
    }
  }, [selected]);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

  const pick = (p: PolicyRow) => {
    setSelected(p.id);
    setName(p.name);
    setYaml(p.yaml_source);
    setValidity(null);
    setSaved(false);
  };

  const validate = async () => {
    try {
      const r = await apiPost<{ valid: boolean; name: string }>("/policies/validate", { yaml });
      setValidity({ ok: true, msg: `valid · ${r.name}` });
    } catch (e) {
      setValidity({ ok: false, msg: String(e).replace(/^Error:\s*/, "") });
    }
  };

  const save = async () => {
    setSaved(false);
    try {
      await apiPost("/policies", { name, yaml });
      setValidity({ ok: true, msg: "saved — new version created" });
      setSaved(true);
      load();
    } catch (e) {
      setValidity({ ok: false, msg: String(e).replace(/^Error:\s*/, "") });
    }
  };

  return (
    <>
      <PageHead
        eyebrow="governance"
        title="Policies"
        sub="First-match-wins over tools. Fail-safe defaults: unknown tools ask a human; autonomy narrows, never widens."
      />

      <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: 18, alignItems: "start" }}>
        <div className="panel">
          <div className="rows">
            {policies.map((p) => (
              <div
                key={p.id}
                className="row"
                style={{ gridTemplateColumns: "1fr", cursor: "pointer", background: selected === p.id ? "var(--panel-hi)" : undefined }}
                onClick={() => pick(p)}
              >
                <span className="mono" style={{ color: selected === p.id ? "var(--accent)" : "var(--ink)" }}>
                  {p.name}
                  <span className="mut" style={{ marginLeft: 8, fontSize: 11 }}>
                    v{p.version}
                  </span>
                </span>
              </div>
            ))}
          </div>
        </div>

        <div>
          <textarea className="inp code" value={yaml} onChange={(e) => { setYaml(e.target.value); setSaved(false); }} spellCheck={false} />
          <div className="spread" style={{ marginTop: 12 }}>
            <div className="mono" style={{ fontSize: 12.5 }}>
              {validity && (
                <span style={{ color: validity.ok ? "var(--good)" : "var(--danger)" }}>
                  {validity.ok ? "✓ " : "✗ "}
                  {validity.msg}
                </span>
              )}
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn ghost" onClick={validate}>
                Validate
              </button>
              <button className="btn primary" onClick={save}>
                {saved ? "✓ Saved" : "Save version"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
