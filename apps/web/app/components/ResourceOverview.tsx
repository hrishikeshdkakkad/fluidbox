"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  Agent,
  apiGetCached,
  apiPost,
  CapabilityBundle,
  Connection,
  GithubAppRegistration,
  isGitConnection,
  isToolConnection,
} from "../lib/api";
import { LoadingRows } from "./bits";

interface ResourceSnapshot {
  agents: Agent[];
  bundles: CapabilityBundle[];
  connections: Connection[];
  registrations: GithubAppRegistration[];
}

const EMPTY: ResourceSnapshot = {
  agents: [],
  bundles: [],
  connections: [],
  registrations: [],
};

export function ResourceOverview({
  refreshKey = 0,
  onCreateAgent,
  onAddCapability,
}: {
  refreshKey?: number;
  onCreateAgent: () => void;
  onAddCapability: () => void;
}) {
  const [snapshot, setSnapshot] = useState<ResourceSnapshot>(EMPTY);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [loadErr, setLoadErr] = useState("");
  const [hasSnapshot, setHasSnapshot] = useState(false);

  const load = useCallback(async () => {
    const results = await Promise.allSettled([
      apiGetCached<{ agents: Agent[] }>("/agents", { maxAgeMs: 15_000 }),
      apiGetCached<{ bundles: CapabilityBundle[] }>("/capabilities", { maxAgeMs: 30_000 }),
      apiGetCached<{ connections: Connection[] }>("/connections", { maxAgeMs: 10_000 }),
      apiGetCached<{ registrations: GithubAppRegistration[] }>("/github/app", { maxAgeMs: 10_000 }),
    ]);
    const fulfilled = results.filter((result) => result.status === "fulfilled").length;
    setSnapshot((current) => ({
      agents: results[0].status === "fulfilled" ? results[0].value.agents : current.agents,
      bundles: results[1].status === "fulfilled" ? results[1].value.bundles : current.bundles,
      connections:
        results[2].status === "fulfilled" ? results[2].value.connections : current.connections,
      registrations:
        results[3].status === "fulfilled"
          ? results[3].value.registrations
          : current.registrations,
    }));
    if (fulfilled > 0) setHasSnapshot(true);
    setLoadErr(
      fulfilled === 0
        ? "Resource status is unavailable because the control plane could not be reached."
        : fulfilled < results.length
          ? "Some resource status could not be refreshed; showing the last available values."
          : ""
    );
    setLoading(false);
  }, []);

  useEffect(() => {
    const first = window.setTimeout(() => void load(), 0);
    window.addEventListener("focus", load);
    return () => {
      clearTimeout(first);
      window.removeEventListener("focus", load);
    };
  }, [load, refreshKey]);

  const openGithubSetup = () => {
    const tab = window.open("", "_blank");
    setErr("");
    apiPost<{ go_url: string }>("/github/app/manifest/start", { organization: null })
      .then((response) => {
        if (tab) tab.location.href = response.go_url;
        else window.location.href = response.go_url;
      })
      .catch((error) => {
        tab?.close();
        setErr(String(error));
      });
  };

  const activeConnections = snapshot.connections.filter(
    (connection) => connection.status === "active" && isGitConnection(connection)
  );
  const activeToolConnections = snapshot.connections.filter(
    (connection) => connection.status === "active" && isToolConnection(connection)
  );
  const activeRegistrations = snapshot.registrations.filter(
    (registration) => registration.status === "active"
  );
  const latestBundles = snapshot.bundles.filter(
    (bundle, index, bundles) => bundles.findIndex((candidate) => candidate.name === bundle.name) === index
  );
  const ready = snapshot.agents.length > 0;
  const unavailable = !loading && !hasSnapshot;

  return (
    <section className="configuration-section" id="configuration" aria-labelledby="configuration-heading">
      <div className="configuration-head">
        <div>
          <h2 id="configuration-heading">Resources</h2>
          <p>
            Reusable definitions and connections available to every run.
          </p>
        </div>
        <div className={`readiness ${unavailable ? "unavailable" : ready ? "ready" : "needs-setup"}`}>
          <span className={`signal ${unavailable ? "down" : ""}`} />
          <span>
            <strong>{unavailable ? "Unavailable" : ready ? "Ready" : "Setup Required"}</strong>
            <small>
              {unavailable
                ? "Control plane offline"
                : ready
                  ? `${snapshot.agents.length} agent${snapshot.agents.length === 1 ? "" : "s"}`
                  : "Create an agent"}
            </small>
          </span>
        </div>
      </div>

      {err && <div className="err configuration-error">{err}</div>}
      {loadErr && <div className="note configuration-error">{loadErr}</div>}

      {loading ? (
        <div className="configuration-loading"><LoadingRows rows={3} /></div>
      ) : unavailable ? (
        <div className="panel launch-empty">
          <div>
            <h3>Resources could not be loaded.</h3>
            <p>No setup assumptions were made from a failed response.</p>
          </div>
          <div className="empty-actions">
            <button className="btn" type="button" onClick={() => void load()}>
              Retry now
            </button>
          </div>
        </div>
      ) : (
        <div className="resource-grid">
          <ResourceCard
            tone="agent"
            eyebrow="Required"
            title="Agents"
            count={snapshot.agents.length}
            description={
              snapshot.agents.length === 0
                ? "Create the reusable runtime, model, instructions, workspace, and capability configuration for a run."
                : "Versioned definitions available to manual and automated runs."
            }
            items={snapshot.agents.map((agent) => agent.name)}
            action={<button className="btn sm" type="button" onClick={onCreateAgent}>{snapshot.agents.length === 0 ? "Create Agent" : "New Agent"}</button>}
            secondary={snapshot.agents.length > 0 ? <Link className="resource-secondary" href="/agents">Manage</Link> : undefined}
          />

          <ResourceCard
            tone="integration"
            eyebrow="Optional"
            title="Integrations"
            count={activeConnections.length}
            description={
              activeConnections.length === 0
                ? "Connect GitHub when runs need private repositories, pull-request triggers, or result publishing."
                : "Repository access and event delivery are available to eligible runs."
            }
            items={activeConnections.map((connection) => connection.display_name)}
            action={
              activeConnections.length === 0 && activeRegistrations.length === 0
                ? <button className="btn sm" type="button" onClick={openGithubSetup}>Connect GitHub</button>
                : <Link className="btn sm" href="/integrations">Manage</Link>
            }
            secondary={
              activeRegistrations.length > 0 && activeConnections.length === 0
                ? <Link className="resource-secondary" href="/integrations">Add Repositories</Link>
                : undefined
            }
          />

          <ResourceCard
            tone="capability"
            eyebrow="Optional"
            title="Capabilities"
            count={latestBundles.length}
            description={
              latestBundles.length === 0
                ? "Add a remote tool server when an agent needs governed access to an external service."
                : `${activeToolConnections.length} active tool connection${activeToolConnections.length === 1 ? "" : "s"}; exact bundle versions are pinned on agents.`
            }
            items={latestBundles.map((bundle) => `${bundle.name}@${bundle.version}`)}
            action={<button className="btn sm" type="button" onClick={onAddCapability}>{latestBundles.length === 0 ? "Add Capability" : "Add Another"}</button>}
            secondary={<Link className="resource-secondary" href="/capabilities">Manage</Link>}
          />
        </div>
      )}
    </section>
  );
}

function ResourceCard({
  tone,
  eyebrow,
  title,
  count,
  description,
  items,
  action,
  secondary,
}: {
  tone: "integration" | "capability" | "agent";
  eyebrow: string;
  title: string;
  count: number;
  description: string;
  items: string[];
  action: React.ReactNode;
  secondary?: React.ReactNode;
}) {
  return (
    <article className={`resource-card resource-${tone}`}>
      <ResourceGlyph tone={tone} />
      <div className="resource-card-content">
        <div className="resource-card-top">
          <h3>{title}</h3>
          <span className="resource-eyebrow">{eyebrow}</span>
          <span className="resource-count">{count}</span>
        </div>
        <p>{description}</p>
        {items.length > 0 && (
          <div className="resource-items">
            {items.slice(0, 3).map((item, index) => <span key={`${item}-${index}`}>{item}</span>)}
            {items.length > 3 && <span>+{items.length - 3} more</span>}
          </div>
        )}
      </div>
      <div className="resource-actions">
        {action}
        {secondary}
      </div>
    </article>
  );
}

function ResourceGlyph({ tone }: { tone: "integration" | "capability" | "agent" }) {
  if (tone === "integration") {
    return (
      <span className="resource-glyph" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none">
          <circle cx="7" cy="12" r="3.5" />
          <circle cx="17" cy="7" r="2.5" />
          <circle cx="17" cy="17" r="2.5" />
          <path d="m10 10.5 4.6-2.3M10 13.5l4.6 2.3" />
        </svg>
      </span>
    );
  }

  if (tone === "capability") {
    return (
      <span className="resource-glyph" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none">
          <path d="M8 5H5v14h3M16 5h3v14h-3M9.5 12h5" />
          <circle cx="12" cy="12" r="2.25" />
        </svg>
      </span>
    );
  }

  return (
    <span className="resource-glyph" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none">
        <rect x="5" y="4.5" width="14" height="15" rx="3" />
        <path d="M8.5 9h7M8.5 12h4.5M8.5 15h6" />
      </svg>
    </span>
  );
}
