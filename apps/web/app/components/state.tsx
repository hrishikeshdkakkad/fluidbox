"use client";

import Link from "next/link";
import { ApiError, errorDetail } from "../lib/api";

// The shared not-found / empty / error surfaces.
//
// They deliberately reuse `.launch-empty` — the card the dashboard already
// uses for "Agents are unavailable." — so these introduce no new CSS and
// inherit the kernel identity (flat, hairline, lowercase chrome voice) for
// free. Marked "use client" for the same reason bits.tsx is: it is the
// convention for shared presentational components here, and StateError takes
// an onRetry callback.

function StateCard({
  code,
  title,
  body,
  children,
  alert = false,
}: {
  /** A machine value (404, 500). Mono, per the type rule for generated data. */
  code?: string;
  title: string;
  body: string;
  children?: React.ReactNode;
  alert?: boolean;
}) {
  return (
    <div className="panel launch-empty" {...(alert ? { role: "alert" } : {})}>
      <div>
        {code && <p className="mono">{code}</p>}
        <h3>{title}</h3>
        <p>{body}</p>
      </div>
      {children && <div className="empty-actions">{children}</div>}
    </div>
  );
}

/** A fulfilled read that returned nothing. Never render this for a FAILED
 *  read — that is the defect this component exists to make hard to write. */
export function StateEmpty({
  title,
  body,
  action,
}: {
  title: string;
  body: string;
  action?: React.ReactNode;
}) {
  return (
    <StateCard title={title} body={body}>
      {action}
    </StateCard>
  );
}

/** The thing was asked for by name and does not exist. No Retry: retrying a
 *  404 can never succeed, and offering it was the original defect. */
export function StateNotFound({
  title = "not found",
  body = "This may have been deleted, or the address may be wrong.",
  href = "/app",
  label = "Back to overview",
}: {
  title?: string;
  body?: string;
  href?: string;
  label?: string;
}) {
  return (
    <StateCard code="404" title={title} body={body}>
      <Link className="btn" href={href}>
        {label}
      </Link>
    </StateCard>
  );
}

/**
 * A read that failed. Reads `ApiError.kind` so the copy matches what actually
 * happened; a 404 delegates to StateNotFound rather than offering a Retry that
 * cannot work. Never renders `String(error)` at a user.
 */
export function StateError({
  error,
  onRetry,
  body,
  notFoundHref = "/app",
}: {
  error: unknown;
  onRetry?: () => void;
  /** Overrides the derived copy. Use it where the underlying message is not
   *  fit to show a person — a Server Component error is replaced by a generic
   *  framework string in production. */
  body?: string;
  notFoundHref?: string;
}) {
  const kind = error instanceof ApiError ? error.kind : "error";

  if (kind === "notFound") {
    return <StateNotFound href={notFoundHref} />;
  }

  if (kind === "denied") {
    return (
      <StateCard
        alert
        code="401"
        title="your session expired"
        body="Sign in again to continue. Nothing was lost."
      >
        <Link className="btn" href="/login">
          Sign in
        </Link>
      </StateCard>
    );
  }

  const unreachable = kind === "unreachable";
  return (
    <StateCard
      alert
      code={error instanceof ApiError ? String(error.status) : undefined}
      title={unreachable ? "the control plane is unreachable" : "that request failed"}
      body={
        body ??
        (unreachable
          ? "A failed read is not treated as empty — nothing below was assumed from it."
          : errorDetail(error))
      }
    >
      {onRetry && (
        <button className="btn" type="button" onClick={onRetry}>
          Retry now
        </button>
      )}
    </StateCard>
  );
}
