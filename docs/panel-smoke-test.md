# PR review panel — smoke test

This file exists to exercise the `hrishi-init` PR review panel deployment:
three sandboxed reviewers (correctness, security, test coverage) fire on
`pull_request.opened`, each in a governed run with a $1 ceiling.

Expected outcome for this PR: one stable summary comment from the
correctness lead, plus three commit checks named after their automations.

Safe to close without merging — nothing references this file.
