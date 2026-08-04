# Network Grant Dashboard UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the three sandbox network grant modes (`offline` / `approved` / `public`) configurable from the dashboard — policy ceiling, agent declaration, per-run override, and grant authorization.

**Architecture:** The backend is complete and running (v0.5.1). This is TypeScript types mirroring the Rust serde shapes, thin React components, and one small read-only Rust field. Testable logic lives in `app/lib/network.ts` (vitest); components stay presentational. The browser never decides what a policy *means* — validation rides the existing `/policies/preview` and `/policies/validate`.

**Tech Stack:** Next.js 16 (App Router), React, TypeScript, vitest, Rust/axum.

## Global Constraints

- **Branch:** `feat/cloud-m1`. It already contains `origin/main`. Do not branch off main.
- **The dashboard is presentation-only.** All policy logic stays in the Rust API. Formatting a target for display and choosing which options to enable is presentation; computing a verdict is not.
- **The server parses policy drafts STRICTLY** (`DraftNetwork` has `deny_unknown_fields`). Every TS field name must exactly match the Rust serde name, or Publish 422s.
- **`network` is `skip_serializing_if = "network_policy_is_default"`.** A policy with no network config returns **no `network` key at all**. Treat `content.network` as optional everywhere and synthesize the default.
- **Exact serde vocabulary** — copy verbatim:
  - `NetworkGrantMode`: `"offline"` | `"approved"` | `"public"` (order is the ceiling order: offline < approved < public)
  - `TargetRule` is tagged by `kind`: `"dns"` | `"cidr"`
  - `FqdnPattern` is tagged by `kind`: `"exact"` (field `name`) | `"wildcard"` (field `suffix`)
  - `PortSpec`: `{ from: number, to: number }`
  - `L4Protocol`: `"tcp"` | `"udp"` (display as `TCP` / `UDP`)
  - `NetworkPolicy`: `max_mode`, `allow`, `deny`, `require_approval`, `allow_public_with_brokered`, `max_grant_secs`
  - `NetworkRequest`: `mode`, `targets`, `duration_secs`
- **A `public` request must carry NO targets.** Core refuses the pairing as a false narrowing.
- **A `wildcard` is single-label.** `*.nvidia.com` matches `api.nvidia.com` but NOT the apex `nvidia.com` and NOT `a.b.nvidia.com`. The UI must say so.
- **Commands:** `cd apps/web && pnpm test` (vitest), `pnpm typecheck`, `pnpm build`. Rust: `cargo test -p fluidbox-server`.
- Commit messages end with the repo's two trailers (`Co-Authored-By:` / `Claude-Session:`) — copy them from any recent commit.

---

## File Structure

| File | Responsibility |
|---|---|
| `apps/web/app/lib/api.ts` (modify) | Type mirrors only. Add the six network types; make `PolicyContent.network` optional; extend the harnesses response. |
| `apps/web/app/lib/network.ts` (create) | Pure presentation helpers: the offline default, target formatting, mode labels/order. The only testable unit. |
| `apps/web/app/lib/network.test.ts` (create) | Vitest for the above. |
| `apps/web/app/components/TargetRuleEditor.tsx` (create) | One shared row editor for `TargetRule[]`. Used by Governance and the agent editor. |
| `apps/web/app/components/PolicyLimits.tsx` (modify) | Add the Network section (ceiling, targets, approval, lifetime). Its header comment already names Network. |
| `apps/web/app/app/agents/page.tsx` (modify) | Network declaration on the revision form. |
| `apps/web/app/components/RunComposer.tsx` (modify) | "Network access" block beside Guardrails. |
| `apps/web/app/app/sessions/[id]/page.tsx` (modify) | Approval card treatment for `network.grant`. |
| `crates/fluidbox-server/src/api.rs` (modify) | `list_harnesses` gains a `network` object. |
| `apps/web/app/lib/harnesses.ts` (modify) | Expose the enforcer from the catalog hook. |

---

### Task 1: Types and pure helpers

**Files:**
- Modify: `apps/web/app/lib/api.ts` (add types after `PolicyContent`, ~line 940)
- Create: `apps/web/app/lib/network.ts`
- Test: `apps/web/app/lib/network.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `NetworkGrantMode`, `PortSpec`, `FqdnPattern`, `TargetRule`, `NetworkPolicy`, `NetworkRequest` (from `api.ts`); `OFFLINE_NETWORK`, `networkOf(content)`, `describeTarget(t)`, `portsLabel(ports)`, `MODE_LABEL`, `MODE_HINT`, `MODE_ORDER` (from `network.ts`).

- [ ] **Step 1: Write the failing test**

Create `apps/web/app/lib/network.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { PolicyContent, TargetRule } from "./api";
import {
  describeTarget,
  MODE_ORDER,
  networkOf,
  OFFLINE_NETWORK,
  portsLabel,
} from "./network";

const base = { name: "p" } as unknown as PolicyContent;

describe("networkOf", () => {
  it("synthesizes the offline default when the server omitted the key", () => {
    // `network` is skip_serializing_if default on the Rust side, so an
    // untouched policy arrives with NO network key at all.
    expect(networkOf(base)).toEqual(OFFLINE_NETWORK);
    expect(networkOf(base).max_mode).toBe("offline");
    expect(networkOf(base).allow).toEqual([]);
  });

  it("returns the stored section when present", () => {
    const withNet = { ...base, network: { ...OFFLINE_NETWORK, max_mode: "public" as const } };
    expect(networkOf(withNet).max_mode).toBe("public");
  });
});

describe("portsLabel", () => {
  it("renders a single port bare and a range with a dash", () => {
    expect(portsLabel([{ from: 443, to: 443 }])).toBe("443");
    expect(portsLabel([{ from: 443, to: 444 }])).toBe("443-444");
    expect(portsLabel([{ from: 80, to: 80 }, { from: 443, to: 443 }])).toBe("80, 443");
  });

  it("says so when a rule names no ports", () => {
    expect(portsLabel([])).toBe("any port");
  });
});

describe("describeTarget", () => {
  it("renders a wildcard dns rule", () => {
    const t: TargetRule = {
      kind: "dns",
      pattern: { kind: "wildcard", suffix: "nvidia.com" },
      ports: [{ from: 443, to: 443 }],
      protocol: "tcp",
    };
    expect(describeTarget(t)).toBe("*.nvidia.com TCP 443");
  });

  it("renders an exact dns rule", () => {
    const t: TargetRule = {
      kind: "dns",
      pattern: { kind: "exact", name: "nvidia.com" },
      ports: [{ from: 443, to: 443 }],
      protocol: "tcp",
    };
    expect(describeTarget(t)).toBe("nvidia.com TCP 443");
  });

  it("renders a cidr rule", () => {
    const t: TargetRule = {
      kind: "cidr",
      cidr: "10.0.0.0/8",
      ports: [{ from: 5432, to: 5432 }],
      protocol: "udp",
    };
    expect(describeTarget(t)).toBe("10.0.0.0/8 UDP 5432");
  });
});

describe("mode ordering", () => {
  it("orders offline < approved < public, the ceiling order", () => {
    // Pinned because the selectors render in this order and a reader will
    // take the order as meaning "increasingly permissive". It does.
    expect(MODE_ORDER).toEqual(["offline", "approved", "public"]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/web && pnpm test network`
Expected: FAIL — `Failed to resolve import "./network"`.

- [ ] **Step 3: Add the types to `api.ts`**

Insert immediately after the `PolicyContent` interface (~line 940). Field names are load-bearing — the server 422s an unknown field.

```ts
// ─── Sandbox network grants ───────────────────────────────────────────────
// Structural mirrors of fluidbox-core::network. `kind` is a serde tag, not a
// convenience: TargetRule and FqdnPattern are tagged enums server-side.

export type NetworkGrantMode = "offline" | "approved" | "public";
export type L4Protocol = "tcp" | "udp";

export interface PortSpec {
  from: number;
  to: number;
}

export type FqdnPattern =
  | { kind: "exact"; name: string }
  | { kind: "wildcard"; suffix: string };

export type TargetRule =
  | { kind: "dns"; pattern: FqdnPattern; ports: PortSpec[]; protocol: L4Protocol }
  | { kind: "cidr"; cidr: string; ports: PortSpec[]; protocol: L4Protocol };

/** The `network:` section of a policy — the CEILING, never the grant. */
export interface NetworkPolicy {
  max_mode: NetworkGrantMode;
  allow: TargetRule[];
  deny: TargetRule[];
  require_approval: boolean;
  allow_public_with_brokered: boolean;
  max_grant_secs: number | null;
}

/** What an agent revision DECLARES, or a run narrows it to. */
export interface NetworkRequest {
  mode: NetworkGrantMode;
  targets: TargetRule[];
  duration_secs: number | null;
}
```

Then make the field optional on `PolicyContent` — the server omits it at default:

```ts
export interface PolicyContent {
  name: string;
  defaults: PolicyDefaults;
  egress: Egress;
  budgets: Budgets;
  approvals: ApprovalSettings;
  autonomy: AutonomySettings;
  tools: ToolRule[];
  /** Absent on any policy that never configured egress — see networkOf(). */
  network?: NetworkPolicy;
}
```

- [ ] **Step 4: Write `app/lib/network.ts`**

```ts
// Presentation helpers for sandbox network grants. Formatting and ordering
// ONLY — what a policy MEANS is resolved server-side by /policies/preview.

import { NetworkGrantMode, NetworkPolicy, PolicyContent, PortSpec, TargetRule } from "./api";

/** The fail-safe section a policy has when it has never configured egress. */
export const OFFLINE_NETWORK: NetworkPolicy = {
  max_mode: "offline",
  allow: [],
  deny: [],
  require_approval: false,
  allow_public_with_brokered: false,
  max_grant_secs: null,
};

/** The server OMITS `network` when it is at its default, so this is not a
 *  convenience — every read of the section must go through it. */
export function networkOf(content: PolicyContent): NetworkPolicy {
  return content.network ?? OFFLINE_NETWORK;
}

/** Ceiling order. A test pins this: reordering it would silently widen or
 *  narrow every comparison built on it. */
export const MODE_ORDER: NetworkGrantMode[] = ["offline", "approved", "public"];

export const MODE_LABEL: Record<NetworkGrantMode, string> = {
  offline: "Offline",
  approved: "Approved targets",
  public: "Public",
};

export const MODE_HINT: Record<NetworkGrantMode, string> = {
  offline: "No egress at all beyond the control plane. The default.",
  approved: "Exactly the targets listed below, and nothing else.",
  public: "Everything the deployment's deny wall does not forbid.",
};

export function portsLabel(ports: PortSpec[]): string {
  if (ports.length === 0) return "any port";
  return ports.map((p) => (p.from === p.to ? `${p.from}` : `${p.from}-${p.to}`)).join(", ");
}

export function describeTarget(t: TargetRule): string {
  const where =
    t.kind === "cidr"
      ? t.cidr
      : t.pattern.kind === "exact"
        ? t.pattern.name
        : `*.${t.pattern.suffix}`;
  return `${where} ${t.protocol.toUpperCase()} ${portsLabel(t.ports)}`;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd apps/web && pnpm test network && pnpm typecheck`
Expected: PASS, 8 tests. Typecheck clean.

- [ ] **Step 6: Commit**

```bash
git add apps/web/app/lib/api.ts apps/web/app/lib/network.ts apps/web/app/lib/network.test.ts
git commit -m "feat(web): type mirrors and presentation helpers for network grants"
```

---

### Task 2: The shared target editor

**Files:**
- Create: `apps/web/app/components/TargetRuleEditor.tsx`

**Interfaces:**
- Consumes: `TargetRule`, `FqdnPattern`, `L4Protocol` from `api.ts`; `describeTarget` from `network.ts`.
- Produces: `<TargetRuleEditor value={TargetRule[]} onChange={(next: TargetRule[]) => void} disabled?: boolean />`, and `EMPTY_TARGET: TargetRule`.

- [ ] **Step 1: Write the component**

```tsx
"use client";

// One row editor for TargetRule[], shared by the policy ceiling and the agent
// declaration — both edit the identical shape. Structure only: whether a
// target is REACHABLE is resolved server-side.

import { FqdnPattern, L4Protocol, TargetRule } from "../lib/api";
import { describeTarget } from "../lib/network";

export const EMPTY_TARGET: TargetRule = {
  kind: "dns",
  pattern: { kind: "wildcard", suffix: "" },
  ports: [{ from: 443, to: 443 }],
  protocol: "tcp",
};

function patternValue(p: FqdnPattern): string {
  return p.kind === "exact" ? p.name : p.suffix;
}

export function TargetRuleEditor({
  value,
  onChange,
  disabled = false,
}: {
  value: TargetRule[];
  onChange: (next: TargetRule[]) => void;
  disabled?: boolean;
}) {
  const patch = (i: number, next: TargetRule) =>
    onChange(value.map((t, n) => (n === i ? next : t)));
  const remove = (i: number) => onChange(value.filter((_, n) => n !== i));

  return (
    <div>
      {value.length === 0 && (
        <p className="helper">
          No targets. An <code>approved</code> ceiling with no targets grants nothing —
          which is what makes it inert until you add one.
        </p>
      )}

      {value.map((t, i) => (
        <div className="agent-creator-grid" key={i}>
          <label className="field">
            <span className="lab">Match</span>
            <select
              className="inp"
              disabled={disabled}
              value={t.kind === "cidr" ? "cidr" : t.pattern.kind}
              onChange={(e) => {
                const k = e.target.value;
                if (k === "cidr") patch(i, { kind: "cidr", cidr: "", ports: t.ports, protocol: t.protocol });
                else if (k === "exact")
                  patch(i, { kind: "dns", pattern: { kind: "exact", name: "" }, ports: t.ports, protocol: t.protocol });
                else
                  patch(i, { kind: "dns", pattern: { kind: "wildcard", suffix: "" }, ports: t.ports, protocol: t.protocol });
              }}
            >
              <option value="wildcard">Subdomains of…</option>
              <option value="exact">Exactly…</option>
              <option value="cidr">IP range (CIDR)</option>
            </select>
          </label>

          <label className="field">
            <span className="lab">{t.kind === "cidr" ? "CIDR" : "Host"}</span>
            <input
              className="inp mono"
              disabled={disabled}
              placeholder={t.kind === "cidr" ? "10.0.0.0/8" : "nvidia.com"}
              value={t.kind === "cidr" ? t.cidr : patternValue(t.pattern)}
              onChange={(e) => {
                const v = e.target.value.trim();
                if (t.kind === "cidr") patch(i, { ...t, cidr: v });
                else if (t.pattern.kind === "exact")
                  patch(i, { ...t, pattern: { kind: "exact", name: v } });
                else patch(i, { ...t, pattern: { kind: "wildcard", suffix: v } });
              }}
            />
          </label>

          <label className="field">
            <span className="lab">Protocol</span>
            <select
              className="inp"
              disabled={disabled}
              value={t.protocol}
              onChange={(e) => patch(i, { ...t, protocol: e.target.value as L4Protocol })}
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </label>

          <label className="field">
            <span className="lab">Ports (from)</span>
            <input
              className="inp"
              type="number"
              disabled={disabled}
              value={t.ports[0]?.from ?? 443}
              onChange={(e) => {
                const from = Number(e.target.value);
                patch(i, { ...t, ports: [{ from, to: Math.max(from, t.ports[0]?.to ?? from) }] });
              }}
            />
          </label>

          <label className="field">
            <span className="lab">Ports (to)</span>
            <input
              className="inp"
              type="number"
              disabled={disabled}
              value={t.ports[0]?.to ?? 443}
              onChange={(e) =>
                patch(i, { ...t, ports: [{ from: t.ports[0]?.from ?? 443, to: Number(e.target.value) }] })
              }
            />
          </label>

          <button type="button" className="btn ghost" disabled={disabled} onClick={() => remove(i)}>
            Remove
          </button>

          <p className="helper mono">{describeTarget(t)}</p>

          {t.kind === "dns" && t.pattern.kind === "wildcard" && (
            <p className="helper">
              A wildcard is <strong>one label</strong>: this matches{" "}
              <code>api.{t.pattern.suffix || "example.com"}</code> but NOT the bare{" "}
              <code>{t.pattern.suffix || "example.com"}</code> and NOT{" "}
              <code>a.b.{t.pattern.suffix || "example.com"}</code>. Add the apex as its own
              target if the agent needs it.
            </p>
          )}
        </div>
      ))}

      <button
        type="button"
        className="btn"
        disabled={disabled}
        onClick={() => onChange([...value, structuredClone(EMPTY_TARGET)])}
      >
        Add target
      </button>
    </div>
  );
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd apps/web && pnpm typecheck`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add apps/web/app/components/TargetRuleEditor.tsx
git commit -m "feat(web): shared target editor for network grant rules"
```

---

### Task 3: The Governance Network section

**Files:**
- Modify: `apps/web/app/components/PolicyLimits.tsx` (its header comment already names Network; add the section after the Approvals block)

**Interfaces:**
- Consumes: `networkOf`, `MODE_ORDER`, `MODE_LABEL`, `MODE_HINT` from `network.ts`; `TargetRuleEditor` from Task 2.
- Produces: nothing new — edits `content.network` in the existing draft.

- [ ] **Step 1: Add the imports**

```tsx
import { NetworkGrantMode, NetworkPolicy, TargetRule } from "../lib/api";
import { MODE_HINT, MODE_LABEL, MODE_ORDER, networkOf } from "../lib/network";
import { TargetRuleEditor } from "./TargetRuleEditor";
```

- [ ] **Step 2: Add the section inside `PolicyLimits`, after the Approvals block**

```tsx
{(() => {
  const net = networkOf(content);
  const setNet = (patch: Partial<NetworkPolicy>) =>
    set({ network: { ...net, ...patch } });
  return (
    <>
      <div className="sectitle">Where a sandbox may reach</div>
      <p className="helper" style={{ marginBottom: 4 }}>
        The ceiling for every run on this policy. An agent may ask for less, never more.
      </p>

      <label className="field">
        <span className="lab">Ceiling</span>
        <select
          className="inp"
          value={net.max_mode}
          onChange={(e) => {
            const max_mode = e.target.value as NetworkGrantMode;
            // A public request must carry NO targets; clearing here keeps the
            // ceiling and the catalog from disagreeing on screen.
            setNet(max_mode === "public" ? { max_mode, allow: [] } : { max_mode });
          }}
        >
          {MODE_ORDER.map((m) => (
            <option key={m} value={m}>
              {MODE_LABEL[m]}
            </option>
          ))}
        </select>
      </label>
      <p className="helper">{MODE_HINT[net.max_mode]}</p>

      {net.max_mode === "public" && (
        <p className="helper warn">
          Public grants reach anything the deployment&rsquo;s deny wall does not forbid.
          On a deployment fronted by a CDN, that wall cannot enumerate every address of
          your own public API, so a run could in principle reach it. Sandbox tokens are
          scoped to the internal plane and the load balancer refuses unsigned origin
          traffic, so the exposure is limited to unauthenticated endpoints — but prefer
          Approved targets where you can name them.
        </p>
      )}

      {net.max_mode === "approved" && (
        <>
          <div className="sectitle">Allowed targets</div>
          <TargetRuleEditor
            value={net.allow}
            onChange={(allow: TargetRule[]) => setNet({ allow })}
          />
        </>
      )}

      {net.max_mode !== "offline" && (
        <>
          <label className="field">
            <span className="lab">Require a human to authorize each run</span>
            <input
              type="checkbox"
              checked={net.require_approval}
              onChange={(e) => setNet({ require_approval: e.target.checked })}
            />
          </label>
          <p className="helper">
            The run parks in <code>awaiting_authorization</code> and appears in the
            timeline for approval before it gets any egress.
          </p>

          <label className="field">
            <span className="lab">Max grant lifetime (seconds)</span>
            <input
              className="inp"
              type="number"
              value={net.max_grant_secs ?? ""}
              placeholder="default"
              onChange={(e) =>
                setNet({ max_grant_secs: e.target.value === "" ? null : Number(e.target.value) })
              }
            />
          </label>
        </>
      )}
    </>
  );
})()}
```

- [ ] **Step 3: Verify**

Run: `cd apps/web && pnpm typecheck && pnpm test && pnpm build`
Expected: all clean.

- [ ] **Step 4: Commit**

```bash
git add apps/web/app/components/PolicyLimits.tsx
git commit -m "feat(web): edit the sandbox egress ceiling in Governance"
```

---

### Task 4: The agent's declaration

**Files:**
- Modify: `apps/web/app/app/agents/page.tsx` (revision form; POST at ~line 312)

**Interfaces:**
- Consumes: `NetworkRequest` from `api.ts`; `TargetRuleEditor`; `MODE_ORDER`/`MODE_LABEL`/`networkOf`.
- Produces: sends `network` in the revision body.

- [ ] **Step 1: Add state, seeded from the current revision**

```tsx
const [network, setNetwork] = useState<NetworkRequest>(
  latest?.network ?? { mode: "offline", targets: [], duration_secs: null },
);
```

- [ ] **Step 2: Render the block, showing the governing ceiling**

The ceiling comes from the policy already loaded for the picker. Showing it here is the point: a declaration above the ceiling fails at run creation, and this makes the conflict visible where it is authored.

```tsx
<div className="sectitle">Network access</div>
<p className="helper">
  Governing policy ceiling: <strong>{MODE_LABEL[ceilingMode]}</strong>. Asking for more
  than the ceiling fails when a run is created.
</p>
<label className="field">
  <span className="lab">Mode</span>
  <select
    className="inp"
    value={network.mode}
    onChange={(e) => {
      const mode = e.target.value as NetworkGrantMode;
      setNetwork({ ...network, mode, targets: mode === "public" ? [] : network.targets });
    }}
  >
    {MODE_ORDER.map((m) => (
      <option key={m} value={m}>{MODE_LABEL[m]}</option>
    ))}
  </select>
</label>
{network.mode === "approved" && (
  <TargetRuleEditor
    value={network.targets}
    onChange={(targets) => setNetwork({ ...network, targets })}
  />
)}
{network.mode === "public" && (
  <p className="helper">
    A public declaration carries no targets — core refuses that pairing, because listing
    targets beside &ldquo;everything&rdquo; reads as a narrowing the datapath would not apply.
  </p>
)}
```

`ceilingMode` needs a real fetch. The page's `policies` state is
`PolicySummary[]` from `GET /policies` (id, name, version) — it carries **no
content and no `network`**, so it cannot answer this. Load the detail for the
selected policy:

```tsx
const [ceiling, setCeiling] = useState<NetworkGrantMode | null>(null);

useEffect(() => {
  const name = policyName ?? currentPolicyName;
  if (!name) {
    setCeiling(null);
    return;
  }
  let live = true;
  apiGetCached<{ content: PolicyContent }>(`/policies/${encodeURIComponent(name)}`, {
    maxAgeMs: 30_000,
  })
    .then((d) => live && setCeiling(networkOf(d.content).max_mode))
    // A failed read must not assert a ceiling we did not read.
    .catch(() => live && setCeiling(null));
  return () => {
    live = false;
  };
}, [policyName, currentPolicyName]);
```

Render `null` as "unknown" — never as `offline`. Claiming a ceiling you failed
to read is the same false-confidence bug as echoing config for the enforcer:

```tsx
<p className="helper">
  Governing policy ceiling:{" "}
  <strong>{ceiling ? MODE_LABEL[ceiling] : "unknown"}</strong>
  {ceiling ? null : " — could not read the policy; a run will still enforce it."}
</p>
```

- [ ] **Step 3: Send it, WYSIWYG like the neighbouring fields**

In the existing `apiPost` body, add:

```tsx
network,
```

- [ ] **Step 4: Verify**

Run: `cd apps/web && pnpm typecheck && pnpm build`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add apps/web/app/app/agents/page.tsx
git commit -m "feat(web): declare an agent's network needs on a revision"
```

---

### Task 5: The run composer's Network access block

**Files:**
- Modify: `apps/web/app/components/RunComposer.tsx` (new section after Guardrails, which ends ~line 1447)

**Interfaces:**
- Consumes: `NetworkRequest`; the selected agent's latest revision (already loaded at ~line 383).
- Produces: sends `network` on `POST /sessions` when narrowing.

- [ ] **Step 1: Add state**

```tsx
// Overrides may only NARROW, so the only choice is inherit-or-offline.
const [offlineOnly, setOfflineOnly] = useState(false);
const declared: NetworkRequest | null = revision?.network ?? null;
```

- [ ] **Step 2: Render the block after Guardrails**

The wrapper is `ComposerSection`, and it is **indexed** — Guardrails is
`index={4}`, so this becomes `index={5}` and any section after it must shift.
Check the numbering of everything below Guardrails before committing.

```tsx
<ComposerSection index={5} title="Network access" hint="Where this run may reach.">
  {!declared || declared.mode === "offline" ? (
    <p className="helper">
      This agent declares no network access, so the run is offline. Add a declaration on
      the agent to change that.
    </p>
  ) : (
    <>
      <label className="field">
        <input
          type="radio"
          checked={!offlineOnly}
          onChange={() => setOfflineOnly(false)}
        />
        <span>Inherit from agent · {MODE_LABEL[declared.mode]}</span>
      </label>
      <label className="field">
        <input type="radio" checked={offlineOnly} onChange={() => setOfflineOnly(true)} />
        <span>Offline only (this run)</span>
      </label>
      <p className="helper">
        A run may narrow what the agent declared, never widen it.
      </p>
    </>
  )}
</ComposerSection>
```

Use the same `Section`/markup wrapper the neighbouring steps use — copy the shape from the Guardrails section at line 1321 rather than inventing one.

- [ ] **Step 3: Send the override on submit**

In the `POST /sessions` body:

```tsx
...(offlineOnly ? { network: { mode: "offline", targets: [], duration_secs: null } } : {}),
```

- [ ] **Step 4: Verify**

Run: `cd apps/web && pnpm typecheck && pnpm build`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add apps/web/app/components/RunComposer.tsx
git commit -m "feat(web): narrow a single run to offline from the composer"
```

---

### Task 6: The grant approval card

**Files:**
- Modify: `apps/web/app/app/sessions/[id]/page.tsx` (approval rendering, ~line 243)

**Interfaces:**
- Consumes: the pending-approval shape already rendered there.
- Produces: nothing new — the decision value sent stays `approved_once`.

- [ ] **Step 1: Branch on the synthetic tool name**

The parked grant rides the ordinary approvals machinery with `tool = "network.grant"`. "Approve once" and "Approve for session" are meaningless for a grant that is inherently per-run, so collapse them.

```tsx
{a.tool === "network.grant" ? (
  <>
    <p className="helper">
      This run is asking for network access before it starts. Authorizing grants it for
      the run only; the grant expires with the run.
    </p>
    <button className="btn primary" onClick={() => decide(a.id, "approved_once")}>
      Authorize
    </button>
    <button className="btn ghost" onClick={() => decide(a.id, "denied")}>
      Deny
    </button>
  </>
) : (
  /* the existing once / session / deny buttons, unchanged */
)}
```

- [ ] **Step 2: Verify**

Run: `cd apps/web && pnpm typecheck && pnpm build`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add "apps/web/app/app/sessions/[id]/page.tsx"
git commit -m "feat(web): authorize a parked network grant from the timeline"
```

---

### Task 7: Surface the resolved enforcer

**Files:**
- Modify: `crates/fluidbox-server/src/api.rs` (`list_harnesses`)
- Modify: `apps/web/app/lib/api.ts` (harnesses response type)
- Modify: `apps/web/app/lib/harnesses.ts` (expose it)
- Modify: `apps/web/app/components/PolicyLimits.tsx` (gate the ceiling selector)

**Interfaces:**
- Consumes: `AppState.provider`.
- Produces: `network: { enforcer: string, supports_egress_grants: bool }` on `GET /v1/harnesses`; `useHarnesses().network` in the browser.

- [ ] **Step 1: Write the failing Rust test**

In `crates/fluidbox-server/src/api.rs` tests:

```rust
#[test]
fn harnesses_payload_reports_the_resolved_enforcer_not_the_config() {
    // The value must come from the PROVIDER. Echoing config is the bug that
    // let FLUIDBOX_NETWORK_ENFORCER=cilium sit on a cluster with no enforcer.
    let body = harnesses_network_block(&fluidbox_core::traits::NoNetworkEnforcer);
    assert_eq!(body["supports_egress_grants"], serde_json::json!(false));
    assert_eq!(body["enforcer"], serde_json::json!("none"));
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p fluidbox-server harnesses_payload_reports`
Expected: FAIL — `harnesses_network_block` not found.

- [ ] **Step 3: Implement**

```rust
/// The deployment's RESOLVED network posture, asked of the provider rather
/// than read from config — config says what was requested, the provider says
/// what is true.
fn harnesses_network_block(
    enforcer: &dyn fluidbox_core::traits::NetworkPolicyProvider,
) -> Value {
    json!({
        "enforcer": enforcer.enforcer_name(),
        "supports_egress_grants": enforcer.supports_egress_grants(),
    })
}
```

And in `list_harnesses`, replace the final line:

```rust
Ok(Json(json!({
    "harnesses": harnesses,
    "network": harnesses_network_block(state.provider.network_enforcer()),
})))
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p fluidbox-server harnesses_payload_reports`
Expected: PASS.

- [ ] **Step 5: Mirror it in the browser and gate the selector**

`api.ts`:

```ts
export interface DeploymentNetwork {
  enforcer: string;
  supports_egress_grants: boolean;
}
```

`harnesses.ts`: add `network: DeploymentNetwork | null` to `HarnessCatalog`, parse it from the same response, default `null` when absent.

`PolicyLimits.tsx`: when `network !== null && !network.supports_egress_grants`, disable the ceiling `<select>` and render:

```tsx
<p className="helper warn">
  This deployment has no network enforcer ({network.enforcer}), so any ceiling above
  Offline would be refused when a run is created. Install Cilium and set
  FLUIDBOX_NETWORK_ENFORCER to enable it.
</p>
```

When `network === null` (an older server that does not send the field), leave the selector **enabled with no banner** — today's behaviour — so the dashboard can ship ahead of the API.

- [ ] **Step 6: Verify both sides**

Run: `cargo test -p fluidbox-server && cd apps/web && pnpm typecheck && pnpm test && pnpm build`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/fluidbox-server/src/api.rs apps/web/app/lib/api.ts apps/web/app/lib/harnesses.ts apps/web/app/components/PolicyLimits.tsx
git commit -m "feat(api): report the resolved network enforcer so the dashboard cannot offer what it cannot enforce"
```

---

### Task 8: Live acceptance

**Files:**
- Create: `docs/reviews/2026-08-04-network-grant-ui-acceptance/README.md`

This closes the criterion left open by the Cilium cutover. Do it against the real deployment.

- [ ] **Step 1: Ship the dashboard**

```bash
cd apps/web && vercel deploy --prod
```

Hard-reload with a cache-buster — the browser will otherwise serve the previous `?dpl=` build.

- [ ] **Step 2: Ship the API (only needed for Task 7)**

Merge to main, let release-please cut the release, wait for the image, then:

```bash
# bump chart_version in deploy/cloud/terraform/app/terraform.auto.tfvars
AWS_PROFILE=fluidbox-operator scripts/cloud/deploy-app.sh
```

- [ ] **Step 3: Configure the drill org through the new UI**

Governance → the `default` policy → Where a sandbox may reach → ceiling **Public**, tick **Require a human to authorize each run** → Publish.
Agents → `test` → Network access → **Public** → save the revision.

- [ ] **Step 4: Run it and capture evidence**

Launch the GPU-research agent. Confirm in order: the run parks in `awaiting_authorization`; the timeline offers **Authorize**; after authorizing, `network.grant.frozen` shows `mode: public`; the agent reaches real sources; the run returns research rather than DNS timeouts.

Save the timeline, the grant event, and the resulting artifact into the evidence directory.

- [ ] **Step 5: Commit the evidence**

```bash
git add docs/reviews/2026-08-04-network-grant-ui-acceptance/
git commit -m "docs(cloud): live acceptance — a granted run reaches the internet"
```

---

## Notes for the implementer

- **The 422 trap.** If Publish fails with a 422 naming an unknown field, a TS field name has drifted from the Rust serde name. Check against the Global Constraints list — do not "fix" it by loosening the server.
- **The absent-key trap.** Never read `content.network` directly; always `networkOf(content)`. Existing policies have no such key.
- **Do not compute verdicts in the browser.** If you find yourself deciding whether a target is reachable, stop — that answer comes from `/policies/preview`.
