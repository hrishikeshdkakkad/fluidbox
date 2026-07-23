"use client";

import React, { useEffect, useId, useRef } from "react";
import Link from "next/link";
import { Connection, ownerBadge } from "../lib/api";

export function Pill({ status }: { status: string }) {
  const label = status.replace(/_/g, " ");
  return (
    <span className={`pill ${status}`}>
      <span className="dot" />
      {label}
    </span>
  );
}

/** Small neutral/amber badge for autonomy, enabled-ness, tiers, … */
export function AutoPill({ autonomy }: { autonomy: string }) {
  return (
    <span className={`badge ${autonomy === "autonomous" ? "warn" : ""}`}>{autonomy}</span>
  );
}

/** Ownership chip for a connection row (Phase C): "Organization" / "Personal",
 *  with a "yours" marker when a personal connection's owner matches the viewer
 *  (needs `meUserId`; absent in admin mode → no marker). Renders nothing for a
 *  row without ownership data (pre-Phase-C shape). Presentation only. */
export function OwnerTag({
  connection,
  meUserId,
}: {
  connection: Connection;
  meUserId?: string | null;
}) {
  const badge = ownerBadge(connection, meUserId);
  if (!badge) return null;
  return (
    <span className="chip" title={badge.label === "Personal" ? "Personal connection" : "Organization connection"}>
      {badge.label}
      {badge.yours && <span className="faint" style={{ marginLeft: 4 }}>· yours</span>}
    </span>
  );
}

export function short(id: string, n = 8): string {
  return id.slice(0, n);
}

export function PageHead({
  title,
  sub,
  right,
  crumbs,
}: {
  title: string;
  sub?: string;
  right?: React.ReactNode;
  crumbs?: { href: string; label: string }[];
}) {
  return (
    <div className="pagehead">
      <div style={{ minWidth: 0 }}>
        {crumbs && crumbs.length > 0 && (
          <div className="crumbs">
            {crumbs.map((c) => (
              <React.Fragment key={c.href}>
                <Link href={c.href}>{c.label}</Link>
                <span aria-hidden>/</span>
              </React.Fragment>
            ))}
          </div>
        )}
        <h1 className="title">{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {right && <div className="page-actions">{right}</div>}
    </div>
  );
}

/** Modal chrome: header with title/subtitle and a close button. */
export function ModalShell({
  title,
  sub,
  onClose,
  children,
  wide,
  maxWidth,
  dismissOnBackdrop = false,
  dirty = false,
  discardTitle = "Discard unsaved changes?",
  discardMessage = "This form is intentionally not stored in the browser.",
}: {
  title: string;
  sub?: string;
  onClose: () => void;
  children: React.ReactNode;
  wide?: boolean;
  /** Explicit shell width — beats `wide`. For layouts that need two panes. */
  maxWidth?: string;
  /**
   * Forms default to deliberate dismissal so a stray click outside a long
   * draft cannot throw work away. Read-only panels may opt back in.
   */
  dismissOnBackdrop?: boolean;
  /** Protect non-persisted forms (especially credential forms) from loss. */
  dirty?: boolean;
  /** Allows one-time-secret panels to explain their more specific loss mode. */
  discardTitle?: string;
  discardMessage?: string;
}) {
  const modalRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  const dirtyRef = useRef(dirty);
  const [confirmDiscard, setConfirmDiscard] = React.useState(false);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);
  useEffect(() => {
    dirtyRef.current = dirty;
  }, [dirty]);

  const requestClose = () => {
    if (dirtyRef.current) {
      setConfirmDiscard(true);
      return;
    }
    onCloseRef.current();
  };

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const modal = modalRef.current;
    const previousOverflow = document.body.style.overflow;
    const previousPaddingRight = document.body.style.paddingRight;
    const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
    document.body.style.overflow = "hidden";
    if (scrollbarWidth > 0) document.body.style.paddingRight = `${scrollbarWidth}px`;
    const focusable = modal?.querySelector<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    focusable?.focus();
    if (modal) modal.scrollTop = 0;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") requestClose();
      if (event.key !== "Tab" || !modal) return;
      const elements = Array.from(
        modal.querySelectorAll<HTMLElement>(
          'button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])'
        )
      );
      if (elements.length === 0) return;
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
      document.body.style.paddingRight = previousPaddingRight;
      previous?.focus();
    };
  }, []);

  return (
    <div
      className="overlay"
      onMouseDown={(event) => {
        if (dismissOnBackdrop && event.target === event.currentTarget) requestClose();
      }}
    >
      <div
        ref={modalRef}
        className="modal"
        style={maxWidth ? { width: maxWidth } : wide ? { width: "min(680px, 92vw)" } : undefined}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={sub ? descriptionId : undefined}
      >
        <div className="mh">
          <div>
            <div className="t" id={titleId}>{title}</div>
            {sub && <div className="s" id={descriptionId}>{sub}</div>}
          </div>
          <button className="xbtn" onClick={requestClose} aria-label="Close">
            <X />
          </button>
        </div>
        {confirmDiscard && (
          <div className="discard-confirm" role="alert">
            <span>
              <strong>{discardTitle}</strong>
              <small>{discardMessage}</small>
            </span>
            <span className="discard-actions">
              <button className="btn sm ghost" type="button" onClick={() => setConfirmDiscard(false)}>
                Keep editing
              </button>
              <button className="btn sm danger" type="button" onClick={() => onCloseRef.current()}>
                Discard
              </button>
            </span>
          </div>
        )}
        <div className="mb">{children}</div>
      </div>
    </div>
  );
}

export function LoadingRows({ rows = 4 }: { rows?: number }) {
  return (
    <div className="loading-rows" aria-label="Loading" aria-busy="true">
      {Array.from({ length: rows }, (_, index) => (
        <div className="loading-row" key={index}>
          <span className="skeleton short" />
          <span className="skeleton" />
          <span className="skeleton tiny" />
        </div>
      ))}
    </div>
  );
}

function X() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
      <path d="M18 6 6 18M6 6l12 12" />
    </svg>
  );
}

/** The GitHub mark (lucide dropped brand icons). */
export function GitHubMark({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden>
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

/** Render a unified diff with add/del/hunk coloring. */
export function DiffView({ content }: { content: string }) {
  if (!content || content === "(no changes)") {
    return <div className="empty">No file changes.</div>;
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

export function timeAgo(iso: string): string {
  const d = new Date(iso).getTime();
  const s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
