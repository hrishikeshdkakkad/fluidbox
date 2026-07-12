<!-- Thanks for contributing! Small, focused PRs review fastest. -->

## What & why

<!-- What does this change, and what problem does it solve? Link the issue: Fixes #123 -->

## How was this tested?

<!-- e.g. new unit tests in fluidbox-core, `just check`, `just e2e`, manual run via CLI/dashboard -->

## Checklist

- [ ] `just check` passes (fmt, clippy `-D warnings`, tests, web build)
- [ ] Touched the permission/approval/trigger path → ran `just e2e`
- [ ] Behavior change → tests added/updated
- [ ] User-visible change → `CHANGELOG.md` (Unreleased) and docs updated
- [ ] Architectural change → preserves the convergence invariants (`PLAN.md` §2)
- [ ] No secrets in code, tests, fixtures, or logs
