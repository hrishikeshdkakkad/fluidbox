# §9-13 + §9-14 drill — operator cancellation and tenant containment

Executed 2026-08-03T18:27:43Z by `scripts/cloud/m1-containment-drill.sh` against a
real control plane (docker provider, replay runner, throwaway database). No
AWS, no model calls. This file is the OBSERVED behaviour, including the
limitations the M1 brief requires be recorded.

## §9-13 — operator cancellation

Cancelled a run blocked on a human approval (the realistic stuck run).
Cancel response `{"cancelled":true}`; terminal status `cancelled`; sandbox container
reclaimed; a repeated cancel returns 200 rather than erroring, so an
operator can retry safely.

## §9-14 — containment runbook (§7), exercised

Steps executed against a real multi-user control plane, in runbook order.

- **(a) disable the org's IdP** — WORKS (`200`). New logins stop immediately.
  Login start after disabling now answers `200` (was a 303 redirect to the IdP).
- **(b) deactivate memberships** — the org has `0` membership(s) at drill time.
  Nobody had completed a login, so there was nothing to deactivate. **This is
  itself a finding:** an org armed with a bootstrap owner who has not yet
  logged in has NO membership row, so step (b) is a no-op — containment of
  such an org rests entirely on step (a).
- **(c) cancel the tenant's active runs** — under `FLUIDBOX_REQUIRE_SSO=1` the
  admin token is confined to `/v1/admin/*`: `GET /v1/sessions` answers
  `401`. The operator therefore CANNOT list or cancel tenant runs with the
  break-glass credential alone — it needs an operator PAT minted from a
  logged-in identity inside that org, which step (a) has just made harder to
  obtain. **Order matters: cancel runs BEFORE disabling login, or keep a
  standing operator PAT per org.** This is the sharpest edge in the runbook.
- **(d) disable trigger subscriptions/schedules** — they invoke with
  subscription authority, not a member session, so (a) and (b) do not stop
  them. Not exercised here (no subscriptions in the drill org), and it
  remains a REQUIRED step in any real containment.

### Limitations observed (not theoretical)

1. **Not atomic.** (a)–(d) are four independent calls; a run can start
   between them.
2. **Ordering trap, newly observed.** Disabling the IdP first can strip the
   operator of the very credential needed for (c). Cancel first.
3. **Empty-membership orgs.** An armed-but-never-logged-in org has no
   membership row, so (b) does nothing.
4. **No reactivation switch.** Undoing this means re-enabling the IdP and
   re-activating every membership by hand — easy to leave half-done.
5. **In-flight sandbox tokens** keep their run alive until (c) lands.

These are why suspend/reactivate is an M3 core proposal and why this
runbook is labelled incomplete rather than merely awkward.
