// The real topology, drawn precisely: callers on /v1, the Rust control plane
// in the middle (gate, approvals, ledger, orchestrator, broker, facade,
// Postgres), the disposable sandbox below on /internal, credential holders on
// the right. Theme-aware via CSS variables; labels in the product's own
// vocabulary. This is a diagram of the shipped system, not marketing artwork.
export function ArchitectureDiagram() {
  return (
    <svg
      className="arch"
      viewBox="0 0 880 470"
      role="img"
      aria-label="Architecture: CLI, dashboard, CI, and webhooks call the /v1 API of the Rust control plane, which contains the permission gate, approvals, orchestrator, append-only ledger, broker, and LLM facade over Postgres. The disposable sandbox running the agent harness speaks the /internal runner contract; the LLM facade forwards to the LiteLLM gateway which alone holds provider keys; the broker calls credentialed MCP services control-plane-side."
    >
      <defs>
        <marker
          id="arr"
          viewBox="0 0 8 8"
          refX="7"
          refY="4"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M0 0.5 L7.5 4 L0 7.5" className="arch-arrhead" />
        </marker>
      </defs>

      {/* Callers */}
      <rect x="12" y="40" width="168" height="118" rx="8" className="arch-box" />
      <text x="28" y="66" className="arch-title">your systems</text>
      <text x="28" y="90" className="arch-sub">dashboard · CLI · CI</text>
      <text x="28" y="108" className="arch-sub">API triggers · schedules</text>
      <text x="28" y="126" className="arch-sub">GitHub webhooks</text>

      {/* /v1 arrow */}
      <line x1="180" y1="99" x2="248" y2="99" className="arch-line" markerEnd="url(#arr)" />
      <text x="214" y="90" className="arch-wire" textAnchor="middle">/v1</text>

      {/* Control plane */}
      <rect x="250" y="16" width="380" height="366" rx="10" className="arch-box arch-box-main" />
      <text x="270" y="44" className="arch-title">fluidbox control plane · Rust</text>

      <rect x="270" y="60" width="164" height="64" rx="6" className="arch-inner" />
      <text x="282" y="82" className="arch-label">permission gate</text>
      <text x="282" y="99" className="arch-sub">budget → surface → schema</text>
      <text x="282" y="113" className="arch-sub">→ trust → policy → approval</text>

      <rect x="446" y="60" width="164" height="64" rx="6" className="arch-inner" />
      <text x="458" y="82" className="arch-label">approvals</text>
      <text x="458" y="99" className="arch-sub">idempotent decisions</text>
      <text x="458" y="113" className="arch-sub">expiry = deny</text>

      <rect x="270" y="140" width="164" height="64" rx="6" className="arch-inner" />
      <text x="282" y="162" className="arch-label">orchestrator</text>
      <text x="282" y="179" className="arch-sub">frozen RunSpecs</text>
      <text x="282" y="193" className="arch-sub">workspace fetch, lifecycle</text>

      <rect x="446" y="140" width="164" height="64" rx="6" className="arch-inner" />
      <text x="458" y="162" className="arch-label">append-only ledger</text>
      <text x="458" y="179" className="arch-sub">redacted events, gapless seq</text>
      <text x="458" y="193" className="arch-sub">SSE timeline</text>

      <rect x="270" y="220" width="164" height="64" rx="6" className="arch-inner" />
      <text x="282" y="242" className="arch-label">broker</text>
      <text x="282" y="259" className="arch-sub">credentialed MCP calls,</text>
      <text x="282" y="273" className="arch-sub">executed control-plane-side</text>

      <rect x="446" y="220" width="164" height="64" rx="6" className="arch-inner" />
      <text x="458" y="242" className="arch-label">LLM facade</text>
      <text x="458" y="259" className="arch-sub">budget stop · metering</text>
      <text x="458" y="273" className="arch-sub">credential swap</text>

      <rect x="270" y="304" width="340" height="56" rx="6" className="arch-inner arch-db" />
      <text x="282" y="326" className="arch-label">Postgres</text>
      <text x="282" y="343" className="arch-sub">RunSpecs · policies · ledger · approvals · sealed credentials</text>

      {/* Sandbox */}
      <rect x="12" y="250" width="200" height="150" rx="8" className="arch-box arch-sandbox" />
      <text x="28" y="276" className="arch-title">disposable sandbox</text>
      <text x="28" y="298" className="arch-sub">Docker / Kubernetes Job</text>
      <text x="28" y="316" className="arch-sub">harness: Claude Agent SDK,</text>
      <text x="28" y="330" className="arch-sub">Codex — via one contract</text>
      <text x="28" y="350" className="arch-sub">/workspace = bind-mounted copy</text>
      <text x="28" y="368" className="arch-sub">no network egress</text>

      <line x1="212" y1="290" x2="248" y2="290" className="arch-line" markerEnd="url(#arr)" />
      <text x="230" y="281" className="arch-wire" textAnchor="middle">/internal</text>
      <text x="230" y="418" className="arch-wire" textAnchor="middle">
        every tool call · session token is its only credential
      </text>
      <line x1="112" y1="400" x2="112" y2="404" className="arch-line arch-hidden" />

      {/* LiteLLM */}
      <rect x="668" y="60" width="200" height="86" rx="8" className="arch-box" />
      <text x="684" y="86" className="arch-title">LiteLLM gateway</text>
      <text x="684" y="108" className="arch-sub">the only holder of</text>
      <text x="684" y="122" className="arch-sub">provider API keys</text>
      <line x1="630" y1="100" x2="666" y2="100" className="arch-line" markerEnd="url(#arr)" />

      {/* Model providers */}
      <rect x="668" y="170" width="200" height="54" rx="8" className="arch-box" />
      <text x="684" y="196" className="arch-title">model providers</text>
      <text x="684" y="212" className="arch-sub">Anthropic · OpenAI · …</text>
      <line x1="768" y1="146" x2="768" y2="168" className="arch-line" markerEnd="url(#arr)" />

      {/* Credentialed services */}
      <rect x="668" y="252" width="200" height="86" rx="8" className="arch-box" />
      <text x="684" y="278" className="arch-title">credentialed services</text>
      <text x="684" y="300" className="arch-sub">MCP servers · GitHub</text>
      <text x="684" y="314" className="arch-sub">credentials sealed at rest,</text>
      <text x="684" y="328" className="arch-sub">never inside a sandbox</text>
      <line x1="630" y1="290" x2="666" y2="290" className="arch-line" markerEnd="url(#arr)" />
    </svg>
  );
}
