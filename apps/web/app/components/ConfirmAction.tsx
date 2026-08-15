"use client";

import { useState } from "react";
import { ModalShell } from "./bits";

/**
 * A destructive button that asks first.
 *
 * Revoking a credential used to fire on a single click — no confirmation, no
 * undo, and the same visual weight as "Refresh". The product already had the
 * right pattern (recipes/instances/[id] guards its delete with a ModalShell);
 * it just was not applied to the one action that destroys a credential.
 *
 * Deliberately NOT window.confirm: two places in this codebase still use it,
 * and it renders an OS dialog that ignores the product's voice entirely. This
 * reuses ModalShell so a confirmation looks like the rest of the app.
 */
export function ConfirmAction({
  label,
  title,
  body,
  confirmLabel,
  onConfirm,
  className = "btn ghost sm danger",
  disabled = false,
}: {
  label: string;
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  className?: string;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <button className={className} type="button" disabled={disabled} onClick={() => setOpen(true)}>
        {label}
      </button>
      {open && (
        <ModalShell title={title} onClose={() => setOpen(false)}>
          {typeof body === "string" ? <p>{body}</p> : body}
          <div className="modal-footer">
            <button className="btn ghost" type="button" onClick={() => setOpen(false)}>
              Cancel
            </button>
            <button
              className="btn danger"
              type="button"
              onClick={() => {
                setOpen(false);
                onConfirm();
              }}
            >
              {confirmLabel}
            </button>
          </div>
        </ModalShell>
      )}
    </>
  );
}
