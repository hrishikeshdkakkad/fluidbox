# fluidbox private beta — invitation draft

A short, honest invitation to adapt. Fill the `___` fields; keep the candour. No hype — the value of this beta depends on people arriving with accurate expectations. Two variants: a full email and a shorter DM.

---

## Email variant

**Subject:** Testing fluidbox `0.4.0-rc.1` — a small, honest private beta

Hi `___`,

I'm running a small private beta for **fluidbox**, an open-source (MIT) control plane that runs AI coding agents in disposable, policy-gated sandboxes: it freezes what an agent is allowed to do, decides every tool call against a policy *before* it runs, pauses for human approval when the policy says so, and ends with a diff and a cost report. I'd value your eyes on it as `___` [a Kubernetes operator / someone who runs coding agents / a security reviewer / a backend engineer].

**What I'm asking.** Roughly **60–90 minutes total**, ideally including one scheduled session where I watch you install it — I'm testing the docs, not you, so I'll stay quiet and let you take the path you'd take if I weren't there. After that, use it as much or as little as you like. The fastest first success is a **keyless five-minute demo** (`just demo`): a deterministic, clearly-labelled replay that drives the real control plane, the real policy gate, and a real sandbox, and makes no model calls, so it costs nothing and needs no API key.

**What is honestly not ready.** This is **pre-1.0 security software** and a **release candidate that has not been published** — expect rough edges, and please treat every boundary as unproven until you've checked it. A few things I want you to know before you say yes:

- **No live Claude run was validated for this candidate.** My Anthropic key is out of credit, so the model-backed Claude path is untested on this build. The gate itself is proven without a model (`just gate-proof`, no key, no spend), and a live **Codex** run *was* validated (OpenAI, ~$0.003 for two runs). If you have your own funded Anthropic key and try the Claude path, you'd be the first — and that's genuinely useful.
- **The default Docker sandbox is not an egress boundary**, and the eval profile's API is reachable on your network (protected only by an admin token). So: run it on a network you trust, and **do not point a run at anything sensitive** — throwaway or test repositories only, nothing with secrets or personal data.
- Only **macOS on Apple Silicon (arm64)** has been validated. If you're on Intel/amd64, Linux, or Windows, you're helping me find out whether it works at all.

If you find a **security** issue, please report it to me privately rather than in any shared channel — I'll coordinate disclosure and credit you.

If you're in, reply and I'll send a scheduling link plus a one-page guide. No obligation to continue if it isn't your thing.

Thanks,
`___`

Repo: `___`   ·   Docs: the participant guide I'll send   ·   License: MIT

---

## DM variant

Hi `___` — running a small private beta for **fluidbox**, an open-source (MIT) control plane that runs AI coding agents in disposable, policy-gated sandboxes (every tool call is decided against a policy before it runs, with approvals + a diff + a cost report). Would love your take as `___`.

Ask: ~60–90 min total, ideally one session where I watch you install it (I'll stay quiet — testing the docs, not you). First success is a **keyless 5-min demo** — no API key, no model spend.

Being straight with you: it's **pre-1.0 security software** and an **unpublished release candidate**. **No live Claude run was validated on this build** (my Anthropic key is out of credit; the gate is proven without a model, and a live Codex run *was* validated). The default Docker sandbox isn't an egress boundary, so **please only point it at throwaway repos on a network you trust**. Only macOS arm64 is validated — other platforms are part of what I'm hoping to learn. Security findings to me privately, not in a group chat.

In? I'll send a scheduling link and a short guide.
