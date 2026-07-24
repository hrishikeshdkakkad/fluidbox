#!/bin/sh
# fluidbox runner entrypoint — moves the runner-control credential OUT of the
# process environment BEFORE the runner is exec'd. Shared verbatim by both
# harness images (claude: /opt/fluidbox-runner/lib, codex: /opt/fluidbox-codex/lib).
#
# WHY THIS EXISTS (Phase F; security invariant 19).
# Phase E split the sandbox's single bearer into four audience-scoped tokens
# and both runner images `delete process.env.FLUIDBOX_SESSION_TOKEN` before
# spawning any agent code. That delete only rewrites the environment handed to
# CHILDREN. A process's own environ region is fixed at execve() time and the
# kernel keeps exposing it at /proc/<pid>/environ, so a same-uid agent child —
# and every agent child IS same-uid, same-PID-namespace as the runner — could
# still read the runner-control token straight out of /proc/1/environ. This
# script closes that read by making the environ region the runner is exec'd
# with never contain the token at all.
#
# MECHANISM. The token can only arrive here in the environment (that is the
# only channel the control plane has; the server-side env contract is
# deliberately untouched by this change). So we:
#   1. write it to a fresh 0600 file  (umask 077 + mktemp — never a widening
#      chmod after the bytes have landed),
#   2. open that file as fd 3,
#   3. UNLINK the file — the bytes now live only behind our fd, reachable by
#      no path,
#   4. `unset` the variable, and
#   5. `exec` the runner: execve() installs a brand-new environ region, on the
#      SAME pid, that has never held the token, with fd 3 inherited.
# The runner learns the descriptor number from FLUIDBOX_SESSION_TOKEN_FD (not a
# secret — it names a channel, it is not one), reads it, and closes it before it
# spawns anything. See `resolveControlToken` in lib/contract.mjs.
#
# WHY AN UNLINKED-FILE FD, AND NOT THE ALTERNATIVES:
#   * NOT the runner's stdin. Neither entrypoint reads its own stdin today, but
#     fd 0 is the one descriptor children inherit by convention; a token parked
#     unread in the runner's stdin would be readable by anything that inherits
#     it. An explicitly-numbered fd we close on arrival has no such default.
#   * NOT a heredoc (`exec 3<<EOF`). It is POSIX and needs no temp file of our
#     own, but whether the shell backs it with a pipe (dash) or an on-disk temp
#     file (bash) is an implementation detail — so the "0600 and unlinked"
#     guarantee would not be ours to make, and this file must behave identically
#     under whatever /bin/sh the base image ships.
#   * NOT a second environment variable under a different name, obviously, and
#     NOT a file left on disk for the runner to open by path: an unlinked fd
#     cannot be re-opened by an agent child that goes looking.
#
# WHAT THIS DOES **NOT** CLOSE — read this before claiming invariant 19 is met:
# a same-uid child can still ptrace(2) the runner and read the token out of its
# live memory. `capabilities: drop ALL`, `allowPrivilegeEscalation: false` and
# `seccompProfile: RuntimeDefault` do NOT block same-uid ptrace. Only a real uid
# split, or moving the runner into its own container (a separate PID namespace),
# closes that. This script closes the PASSIVE /proc/<pid>/environ read — a
# read that needs no syscall trickery, no debugger, and survives in a core dump
# — and nothing more.
set -eu

# EXIT_TOKEN_HANDOFF. Keep in sync with lib/contract.mjs: 2 = missing required
# env, 3 = EXIT_AUDIENCE_MISMATCH, 4 = the credential hand-off failed.
EXIT_TOKEN_HANDOFF=4

# Refuse to start the runner, loudly. Never `exit 0`, never a warning-and-carry-on.
abort() {
	echo "fluidbox-runner-entrypoint: FATAL — $1" >&2
	exit "$EXIT_TOKEN_HANDOFF"
}

# The hand-off could not be made. The tempting "just exec anyway" is the one
# thing this script must not do.
fatal() {
	abort "could not hand the runner-control credential to the runner off-environment ($1). Refusing to exec the runner with the token still in its environment: that would silently re-expose it at /proc/<pid>/environ to every same-uid agent child, which is precisely the residual this entrypoint exists to close."
}

[ "$#" -gt 0 ] || abort "no runner command was given to exec"

# No token in the environment: exec the runner unchanged and say nothing. This
# is NOT the token-missing error path — the runner's own requireEnv() owns that
# diagnostic — and staying quiet here keeps `docker run <image> node -e ...`
# style debugging, and any future token-less container, working.
if [ -z "${FLUIDBOX_SESSION_TOKEN:-}" ]; then
	exec "$@"
fi

# 0600 from creation. mktemp already creates 0600, and umask makes that true
# even where it does not.
umask 077

# /tmp is the normal home for this, but a deployment may mount it read-only, so
# fall back rather than kill the run over a writability detail. Every candidate
# is a directory only this uid needs; the file is unlinked microseconds later.
tokfile=
for dir in "${TMPDIR:-}" /tmp "${HOME:-}"; do
	[ -n "$dir" ] || continue
	[ -d "$dir" ] || continue
	[ -w "$dir" ] || continue
	# `if` (not `&&`) so `set -e` cannot turn a probe miss into a silent exit.
	if tokfile=$(mktemp "$dir/.fluidbox-handoff.XXXXXXXX" 2>/dev/null); then
		break
	fi
	tokfile=
done
[ -n "$tokfile" ] || fatal "no writable directory for the hand-off file"

# Each step is guarded explicitly: `set -e` alone would abort with no named
# diagnostic, and a silent abort is the one failure shape this must not have.
chmod 600 "$tokfile" 2>/dev/null || { rm -f "$tokfile"; fatal "chmod 600 on the hand-off file failed"; }
printf '%s' "$FLUIDBOX_SESSION_TOKEN" >"$tokfile" 2>/dev/null || { rm -f "$tokfile"; fatal "writing the hand-off file failed"; }
# `exec 3<file` is a redirection on a SPECIAL BUILTIN: if the open fails the
# shell exits outright and no `||` handler of ours would ever run. So prove the
# open will succeed first, while a diagnostic is still reachable.
[ -r "$tokfile" ] || { rm -f "$tokfile"; fatal "the hand-off file is not readable"; }

# This is the one shell behaviour the hand-off depends on: a descriptor opened
# by `exec n<` must survive execve(2), i.e. must not be close-on-exec. POSIX
# requires that and dash — Debian's /bin/sh, which is what both images ship —
# does it. (ksh93 does NOT: it marks fd 3 cloexec, so the runner would find a
# bad descriptor. That is a fail-CLOSED degradation, not a silent one: the
# runner aborts with EXIT_TOKEN_HANDOFF and a named diagnostic rather than
# falling back to an environment the entrypoint already cleared.)
exec 3<"$tokfile"
rm -f "$tokfile" || fatal "could not unlink the hand-off file"
unset FLUIDBOX_SESSION_TOKEN
FLUIDBOX_SESSION_TOKEN_FD=3
export FLUIDBOX_SESSION_TOKEN_FD

# execve(2): same pid, brand-new environ region, fd 3 inherited.
exec "$@"
