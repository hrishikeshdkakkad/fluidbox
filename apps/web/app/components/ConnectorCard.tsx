"use client";

// The connector card, shared by the two surfaces that present catalog entries:
// the MCP Store (browse + Connect) and the agent's requirement editor (declare
// what the agent needs). They ask different questions of the same object, so
// the trailing ACTION is a slot rather than something this component decides —
// the Store puts "Connect"/"Connected" there, the picker puts "Select".
//
// Extracting this is what makes the two surfaces read as one system: before,
// the Store rendered a card with a logo, description and live connection state
// while the requirement editor rendered a bare <select> of names, so the same
// seven connectors looked like two unrelated features.

import { ReactNode } from "react";
import { CatalogEntry } from "../lib/api";
import { GitHubMark } from "./bits";

/** Slugs with a dedicated tint in globals.css (`.connector-mark-*`). */
const TONED = ["atlassian", "github", "linear", "notion", "sentry", "stripe", "workspace"];

export function ConnectorMark({ entry }: { entry: CatalogEntry }) {
  const tone = TONED.includes(entry.slug) ? entry.slug : "custom";
  const initials = entry.name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase();

  return (
    <span className={`connector-mark connector-mark-${tone}`} aria-hidden="true">
      {entry.slug === "github" ? <GitHubMark size={21} /> : <span>{initials || "C"}</span>}
    </span>
  );
}

/**
 * Is this entry backed by a usable connection right now?
 *
 * `connection` is server-side decoration on the catalog row (the non-revoked
 * connection covering the entry). An `auth_mode: "none"` entry needs no
 * credential at all, so a photographed bundle is what makes it usable.
 *
 * Shared deliberately: the Store and the requirement picker must never disagree
 * about whether something is connected.
 */
export function connectorConnected(entry: CatalogEntry): boolean {
  return entry.connection?.status === "active" || (entry.auth_mode === "none" && !!entry.bundle);
}

/** A non-active connection that the user should be told about (error/pending). */
export function connectorAttention(entry: CatalogEntry): string | null {
  if (connectorConnected(entry)) return null;
  return entry.connection && entry.connection.status !== "active" ? entry.connection.status : null;
}

export function connectorAuthLabel(entry: CatalogEntry): string {
  return entry.auth_mode === "none"
    ? "No credential"
    : entry.auth_mode === "api_key"
      ? "API key"
      : "OAuth";
}

export function ConnectorCard({
  entry,
  onClick,
  action,
  selected = false,
  meta,
  title,
}: {
  entry: CatalogEntry;
  onClick: () => void;
  /** Trailing pill — the caller owns this, since the two surfaces differ. */
  action: ReactNode;
  selected?: boolean;
  /** Overrides the default auth-mode line. */
  meta?: ReactNode;
  /** Accessible label; defaults to the connector name. */
  title?: string;
}) {
  return (
    <button
      className={`connector-card${selected ? " selected" : ""}`}
      type="button"
      onClick={onClick}
      aria-pressed={selected}
      aria-label={title ?? entry.name}
    >
      <ConnectorMark entry={entry} />
      <span className="connector-card-copy">
        <span className="connector-card-title">
          <span className="nm">{entry.name}</span>
          {entry.tier !== "verified" && <span className="badge">{entry.tier}</span>}
        </span>
        <span className="desc">
          {entry.description || "Connect this service as a governed MCP server."}
        </span>
        <span className="connector-card-meta">
          {meta ?? (
            <>
              {connectorAuthLabel(entry)}
              {entry.bundle ? ` · v${entry.bundle.version}` : ""}
            </>
          )}
        </span>
      </span>
      <span className="connector-card-action">{action}</span>
    </button>
  );
}
