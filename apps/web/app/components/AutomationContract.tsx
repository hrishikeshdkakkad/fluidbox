"use client";

import { useState } from "react";
import { TriggerSubscription } from "../lib/api";
import { buildCurl, classifyVariables } from "../lib/automation-contract";

/* ─── Automation integration contract ─────────────────────────────────────
   What a caller needs to actually integrate, in one copyable place: the real
   endpoint (absolute, from the control plane — never a `<placeholder>` host),
   the variables this automation declares, and the responses to expect. This
   is the shared body rendered by the one-time secrets modal's pointer target
   (the durable /automations/{id} page) and the composer preview, so all
   surfaces show the SAME contract without drifting. */

export function CopyBlock({ label, value, hint }: { label: string; value: string; hint?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard unavailable — the text is selectable either way */
    }
  };
  return (
    <div className="field">
      <div className="contract-head">
        <span className="lab">{label}</span>
        <button type="button" className="btn ghost sm" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="token">{value}</pre>
      {hint && <span className="field-hint">{hint}</span>}
    </div>
  );
}

export function AutomationContract({
  subscription,
  invokeUrl,
  pollUrl,
  ingressUrl,
  token,
  updatedAt,
}: {
  subscription: TriggerSubscription;
  invokeUrl: string;
  pollUrl: string;
  ingressUrl: string | null;
  token: string | null;
  updatedAt: string | null;
}) {
  const kind = subscription.trigger_kind;
  const { caller: callerVars, system: systemVars, invalid: invalidVars } = classifyVariables(
    kind,
    subscription.task_template
  );
  const declared = [...callerVars, ...systemVars, ...invalidVars];

  const curl = buildCurl({
    invokeUrl,
    token,
    caller: callerVars,
    hasTemplate: !!subscription.task_template,
  });

  const responseExample = [
    "200 OK",
    JSON.stringify(
      {
        session_id: "019f…",
        status: "queued",
        replay: false,
        poll_url: `/v1/triggers/${subscription.id}/runs/{session_id}`,
      },
      null,
      2
    ),
  ].join("\n");

  const hasSignedWebhook = subscription.result_destinations.some(
    (d) => d.kind === "signed_webhook"
  );

  return (
    <div className="contract">
      {kind === "api" && (
        <section className="contract-section">
          <h4>Endpoint</h4>
          <CopyBlock label="Invoke" value={`POST ${invokeUrl}`} />
          <CopyBlock
            label="Poll a run"
            value={`GET ${pollUrl}`}
            hint="Substitute the session_id returned by invoke."
          />
        </section>
      )}

      {kind === "event" && (
        <section className="contract-section">
          <h4>Endpoint</h4>
          {ingressUrl && (
            <CopyBlock
              label="Webhook ingress"
              value={ingressUrl}
              hint="Deliveries are authenticated by their signature, so this URL needs no token."
            />
          )}
          <p className="contract-note">
            Runs start from repository events — there is no API caller to authenticate.
          </p>
        </section>
      )}

      {kind === "schedule" && (
        <section className="contract-section">
          <h4>Endpoint</h4>
          <p className="contract-note">
            Runs start on the clock — there is no API caller.
          </p>
        </section>
      )}

      <section className="contract-section">
        <h4>Variables</h4>
        {declared.length === 0 ? (
          <p className="contract-note">
            This automation&apos;s task has no placeholders, so callers send an empty body.
            Add <code>{"{{name}}"}</code> to the task template to accept values.
          </p>
        ) : (
          <div className="rows">
            {callerVars.map((name) => (
              <div key={name} className="row contract-var">
                <span className="mono">{`{{${name}}}`}</span>
                <span className="faint">
                  you supply it in <code>context</code>
                </span>
              </div>
            ))}
            {systemVars.map((name) => (
              <div key={name} className="row contract-var">
                <span className="mono">{`{{${name}}}`}</span>
                <span className="faint">filled in by fluidbox</span>
              </div>
            ))}
            {invalidVars.map((name) => (
              <div key={name} className="row contract-var">
                <span className="mono invalid">{`{{${name}}}`}</span>
                <span className="faint invalid">
                  not available — save refuses this placeholder
                </span>
              </div>
            ))}
          </div>
        )}
        <p className="contract-note">
          <strong>{subscription.allow_task_override ? "Task override allowed" : "Task override refused"}</strong> ·{" "}
          <strong>{subscription.allow_workspace_override ? "workspace override allowed" : "workspace override refused"}</strong>.
          Sending a refused field returns 400. Context values must be flat strings.
        </p>
      </section>

      {kind === "api" && (
        <section className="contract-section">
          <h4>Request</h4>
          <CopyBlock
            label="Example"
            value={curl}
            hint="Idempotency-Key is optional but strongly recommended: replaying the same key returns the original run instead of starting a second one."
          />
        </section>
      )}

      <section className="contract-section">
        <h4>Responses</h4>
        <CopyBlock label="Success" value={responseExample} />
        <div className="rows">
          <div className="row contract-var">
            <span className="mono">409</span>
            <span className="faint">
              a run is already active and this automation is set to{" "}
              <code>{subscription.concurrency_policy}</code>
            </span>
          </div>
          <div className="row contract-var">
            <span className="mono">422</span>
            <span className="faint">
              the Idempotency-Key was already used with a different request body
            </span>
          </div>
          <div className="row contract-var">
            <span className="mono">400</span>
            <span className="faint">an override this subscription does not allow</span>
          </div>
          <div className="row contract-var">
            <span className="mono">401</span>
            <span className="faint">wrong token, or the token was revoked</span>
          </div>
        </div>
      </section>

      {hasSignedWebhook && (
        <section className="contract-section">
          <h4>Result delivery</h4>
          <p className="contract-note">
            When the run finishes, fluidbox POSTs the result to your callback URL and retries
            with backoff over roughly an hour. Delivery is at-least-once — deduplicate on{" "}
            <code>x-fluidbox-delivery</code>.
          </p>
          <CopyBlock
            label="Signature"
            value={'x-fluidbox-signature: v1=hmac-sha256(secret, "{timestamp}.{body}")'}
            hint="Also sent: x-fluidbox-delivery (unique id) and x-fluidbox-timestamp. Verify before trusting the payload."
          />
        </section>
      )}

      {updatedAt && (
        <p className="contract-stamp">
          Reflects the configuration as of {new Date(updatedAt).toLocaleString()}.
        </p>
      )}
    </div>
  );
}

/** Live placeholder read-back under a template textarea: which {{names}}
 *  the caller supplies, which the platform fills, and which a no-caller
 *  kind can never fill (save will refuse those). */
export function TemplateChips({ kind, template }: { kind: string; template: string }) {
  const { caller, system, invalid } = classifyVariables(kind, template || null);
  if (caller.length === 0 && system.length === 0 && invalid.length === 0) return null;
  return (
    <div className="tpl-chips">
      {caller.map((name) => (
        <span key={name} className="tpl-chip caller" title="Caller supplies this in `context`">
          {`{{${name}}}`} · caller
        </span>
      ))}
      {system.map((name) => (
        <span key={name} className="tpl-chip system" title="Filled in by fluidbox">
          {`{{${name}}}`} · fluidbox
        </span>
      ))}
      {invalid.map((name) => (
        <span key={name} className="tpl-chip invalid" title="This trigger has no caller and fluidbox does not fill this name — saving will be refused">
          {`{{${name}}}`} · unknown
        </span>
      ))}
    </div>
  );
}
