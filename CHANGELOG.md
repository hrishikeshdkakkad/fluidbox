# Changelog

All notable, user-visible changes to fluidbox are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org).

## [0.7.0](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.6.0...v0.7.0) (2026-08-06)


### Added

* **web:** make an agent's declared egress visible, and declarable at creation ([44bc3f7](https://github.com/hrishikeshdkakkad/fluidbox/commit/44bc3f799bb823f77dc8ed1d14db3b91903643aa))
* **web:** make an agent's declared egress visible, and declarable at creation ([e417112](https://github.com/hrishikeshdkakkad/fluidbox/commit/e4171121e814a2d5273a0786760d232fa0523290))


### Fixed

* **cloud,web:** cold-start enforcement deadline + collapse the grant card on Overview ([1d6373e](https://github.com/hrishikeshdkakkad/fluidbox/commit/1d6373eef04811437d8a3d135edb6beb63470774))
* **cloud,web:** cold-start enforcement deadline + E2E scenario matrix evidence ([2f25b2f](https://github.com/hrishikeshdkakkad/fluidbox/commit/2f25b2f9bf362b494adcfc23c5a8da4884961e6d))
* **web:** close the network-grant UI review findings ([78adc96](https://github.com/hrishikeshdkakkad/fluidbox/commit/78adc96ba411f2796075358b6def9067a5f72be5))
* **web:** close the network-grant UI review findings ([10a7166](https://github.com/hrishikeshdkakkad/fluidbox/commit/10a7166346b484b980850c0d6f61ceb73ef06ac2))


### Documentation

* **cloud:** cold-start regression test confirms the netpol deadline fix ([9218025](https://github.com/hrishikeshdkakkad/fluidbox/commit/9218025e0270d7e180a4ec8e4908c1d046e56e0e))
* **cloud:** live acceptance — a granted run reaches the internet ([9fb474e](https://github.com/hrishikeshdkakkad/fluidbox/commit/9fb474e9246dadfc137daad7971bba58ff4335e1))
* **cloud:** network-grant UI live acceptance evidence ([94bcc6d](https://github.com/hrishikeshdkakkad/fluidbox/commit/94bcc6dc56239192ef23907e36a754437d551add))

## [0.6.0](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.5.1...v0.6.0) (2026-08-05)


### Added

* **api:** report the resolved network enforcer so the dashboard cannot offer what it cannot enforce ([82d880d](https://github.com/hrishikeshdkakkad/fluidbox/commit/82d880d33941f52db86df1b66b1af60981df0d96))
* **cloud:** turn on governed network access — chart 0.5.1 + the Cilium enforcer ([e94729a](https://github.com/hrishikeshdkakkad/fluidbox/commit/e94729a560bad8997e5e117a1bf76c0e89917a5b))
* network-grant dashboard UI — govern sandbox egress from the dashboard ([5f6287e](https://github.com/hrishikeshdkakkad/fluidbox/commit/5f6287e9dba42312f119bcee28ab64dd4d9f36ad))
* **web:** authorize a parked network grant from the timeline ([ca0b2da](https://github.com/hrishikeshdkakkad/fluidbox/commit/ca0b2da9457c054c6c262a35a53cb32b86bfd0c8))
* **web:** declare an agent's network needs on a revision ([13ee4a6](https://github.com/hrishikeshdkakkad/fluidbox/commit/13ee4a6c6aaa3b91ef04c496246df8ed3c4dc098))
* **web:** edit the sandbox egress ceiling in Governance ([e0c9957](https://github.com/hrishikeshdkakkad/fluidbox/commit/e0c9957495fca3fae6f3ed1580b087f85ba22fb6))
* **web:** narrow a single run to offline from the composer ([b0d0ff0](https://github.com/hrishikeshdkakkad/fluidbox/commit/b0d0ff02abc727e0e2417e2021db645d71e029fa))
* **web:** shared target editor for network grant rules ([c39895f](https://github.com/hrishikeshdkakkad/fluidbox/commit/c39895f601daf04e3cec0a5b5f8aa642b3bf3a7d))
* **web:** type mirrors and presentation helpers for network grants ([4b6fa7d](https://github.com/hrishikeshdkakkad/fluidbox/commit/4b6fa7d0a3e2860795dea95950d935d684938913))


### Fixed

* **web,api:** review fixes — preserve the allow catalog across ceiling switches, never fabricate a declaration, persist and reset the run narrowing choice, pin enforcer delegation ([21108b4](https://github.com/hrishikeshdkakkad/fluidbox/commit/21108b450205eb4d454ebb982e0134382409bc31))


### Documentation

* **cloud:** record the Cilium cutover, its two upstream bugs, and the last mile ([33b0524](https://github.com/hrishikeshdkakkad/fluidbox/commit/33b05244ece125566cb48e85cde23a29e363b6f0))
* **plan:** implementation plan for the network-grant dashboard UI ([8dffed5](https://github.com/hrishikeshdkakkad/fluidbox/commit/8dffed518567350de3db3276018b738189454052))
* **spec:** governed sandbox egress, selectable in the dashboard ([395bdab](https://github.com/hrishikeshdkakkad/fluidbox/commit/395bdab4478583bec3a2d0be1c5a173f622e0c86))

## [0.5.1](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.5.0...v0.5.1) (2026-08-04)


### Fixed

* **chart:** the controlled resolver could not exec — grant it NET_BIND_SERVICE ([d5ccd59](https://github.com/hrishikeshdkakkad/fluidbox/commit/d5ccd591ed890952dab59bc5568788b48c092758))
* **chart:** the controlled resolver could not exec — grant it NET_BIND_SERVICE ([dd1382d](https://github.com/hrishikeshdkakkad/fluidbox/commit/dd1382d050b26cab023e2a1e366a6ef3a18708b8))
* **network:** a CAS answers "did I win", never "is there work left" ([75d7e61](https://github.com/hrishikeshdkakkad/fluidbox/commit/75d7e612b438f7636d73985afb4e66b935e4eab8))
* **network:** a CAS loser must distinguish "someone else won" from "resolved away" ([256a723](https://github.com/hrishikeshdkakkad/fluidbox/commit/256a723f7592e3703b844425650b0ace72a18d19))
* **network:** a DNS deny Cilium cannot express, plus the third review's blockers ([786b86d](https://github.com/hrishikeshdkakkad/fluidbox/commit/786b86dd874279bbcf6b735be76d0ed9a48b6b7e))
* **network:** close the review's blocking findings ([991deb5](https://github.com/hrishikeshdkakkad/fluidbox/commit/991deb55d9350f25b24d64b8e456980f79f02838))
* **network:** close the second review's blockers, including a race my own fix added ([494ac12](https://github.com/hrishikeshdkakkad/fluidbox/commit/494ac12e6fd86a8aa30a70a954742c1e32cda622))
* **network:** disambiguate legacy deny snapshots, and reconcile live grants ([343b60b](https://github.com/hrishikeshdkakkad/fluidbox/commit/343b60bdf355797e0f974b82850dd23fdeb4cf47))
* **network:** fail closed at the renderer, and align adoption with ownership ([8c226ef](https://github.com/hrishikeshdkakkad/fluidbox/commit/8c226efa653d58bff61cb54e6db77776f4d43b95))
* **network:** reconcile from the datapath, and bound the schema in both directions ([ea3fec9](https://github.com/hrishikeshdkakkad/fluidbox/commit/ea3fec90e21a41b4de7f3b0f3b67bf3c017f9cc3))
* **network:** scope DNS lookups to the grant, align the deny wall, correct the order ([a8ae238](https://github.com/hrishikeshdkakkad/fluidbox/commit/a8ae23834a07f297e03f96c88d75e1ac9e68e9d6))
* **network:** ten security fixes for governed network access (nine review rounds) ([4ee659d](https://github.com/hrishikeshdkakkad/fluidbox/commit/4ee659db032e4ef1b26799574cf113a78ed8af75))

## [0.5.0](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.4.0...v0.5.0) (2026-08-04)


### Added

* **core:** bounded denied-flow observation + EKS acceptance runbook ([b0ddb5d](https://github.com/hrishikeshdkakkad/fluidbox/commit/b0ddb5de431549757440492b1264fe0e1ca104e9))
* **core:** network grant domain, authorization pause, Cilium spike findings ([1145e6e](https://github.com/hrishikeshdkakkad/fluidbox/commit/1145e6e0bf583af6c929c3f0666e5a1f6dd2ba86))
* Enterprise Recipes — versioned templates that stamp governed automations ([dcacd9b](https://github.com/hrishikeshdkakkad/fluidbox/commit/dcacd9b954200085e8c4438469d1cf2db73d5c1f))
* governed sandbox network access ([d006881](https://github.com/hrishikeshdkakkad/fluidbox/commit/d0068817fb50b22aeebce6fa1a34a12379731905))
* **k8s:** actually program the per-run network policy at provision ([29fa915](https://github.com/hrishikeshdkakkad/fluidbox/commit/29fa915054f49ad3864c5425f616ab4cf41ee241))
* **k8s:** Cilium enforcer + verify() at provision ([d491bc1](https://github.com/hrishikeshdkakkad/fluidbox/commit/d491bc1c33faf46cca48b4e6ae7b732da60633e8))
* **k8s:** Cilium provider seam, per-run policy lowering, chart-static wall ([9d9c2ac](https://github.com/hrishikeshdkakkad/fluidbox/commit/9d9c2acdaca5dd82e962996cd5243a6383b864f4))
* **k8s:** implement the Cilium enforcer and invoke verify() at provision ([7df0baf](https://github.com/hrishikeshdkakkad/fluidbox/commit/7df0baf510c7b712a0f5abfd89def970d4391fca))
* **server:** resolve, park, and revoke sandbox network grants ([96def7a](https://github.com/hrishikeshdkakkad/fluidbox/commit/96def7aa7cbc357edb1a64c02847cee04bec8850))


### Documentation

* network-grant runbook, design doc, threat-model residuals, claim fixes ([d317ade](https://github.com/hrishikeshdkakkad/fluidbox/commit/d317adef7fa5307b2276409aed7aa40ede5b4e69))

## [0.4.0](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.4.0-rc.1...v0.4.0) (2026-07-31)


### ⚠ BREAKING CHANGES

* **policies:** fold managed overrides into head rules in the engine

### Added

* audience-scoped sandbox credentials — llm/tool/control/workspace split ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([fa87936](https://github.com/hrishikeshdkakkad/fluidbox/commit/fa879360ed60a4919f5f87c8800c422d6bfa68c2))
* bring your own MCP server, intuitively + authoritative harness/model ([#24](https://github.com/hrishikeshdkakkad/fluidbox/issues/24)) ([ac7653f](https://github.com/hrishikeshdkakkad/fluidbox/commit/ac7653f2a406a184d044c79ae4a1c029aec9fecb))
* **broker,db:** tear down upstream MCP sessions from any replica ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([7007ac5](https://github.com/hrishikeshdkakkad/fluidbox/commit/7007ac53124cdb0e7ad11c8cbd5ef977a75ee328))
* **capabilities:** design-doc Phase 5 — capability & MCP catalog ([c31f3e0](https://github.com/hrishikeshdkakkad/fluidbox/commit/c31f3e08562459695be4355965671ce58fa58b6d))
* **catalog:** connector-catalog bulk import — MCP Registry (primary) + open-connector (supplement) ([#25](https://github.com/hrishikeshdkakkad/fluidbox/issues/25)) ([6ee603e](https://github.com/hrishikeshdkakkad/fluidbox/commit/6ee603e444e0fe08f3b5c00ecb57c59b9f1c5d63))
* **catalog:** decorate entries with live connection/bundle state; connected cards get Disconnect/Reconnect ([b1da355](https://github.com/hrishikeshdkakkad/fluidbox/commit/b1da3554c2dff3c6965bf8e09e89e4f77566d3be))
* **chart:** archive object store and replica declaration ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([95ad63d](https://github.com/hrishikeshdkakkad/fluidbox/commit/95ad63d88fe2de0d46fee4a503cfebcb1cc15a00))
* **ci,dx:** non-vacuous CI, supply-chain gate, GHCR distribution, user guides, policy proptests ([#22](https://github.com/hrishikeshdkakkad/fluidbox/issues/22)) ([7aabf3b](https://github.com/hrishikeshdkakkad/fluidbox/commit/7aabf3b79defb1211a8354b4bd0d6eba6f0732dd))
* **ci:** prove the permission gate with no model spend, and gate it on every PR ([0e49849](https://github.com/hrishikeshdkakkad/fluidbox/commit/0e498493ffba46915d8a0766e4fd216e7cc86024))
* **ci:** secrets acceptance matrix — KMS, invariant 20, virtual keys, RLS ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32),[#75](https://github.com/hrishikeshdkakkad/fluidbox/issues/75)) ([3bb321d](https://github.com/hrishikeshdkakkad/fluidbox/commit/3bb321dcf19ea18e6460eb6988afebd54cdc1305))
* **codex:** codex-runner image + app-server supervisor; facade strips server tools (Phase 6 step 6) ([b13a8ab](https://github.com/hrishikeshdkakkad/fluidbox/commit/b13a8abfa90c165ef773b5a356e1774c7bd8984a))
* **connectors:** Phase 5.5 — connector catalog & OAuth credential custody ([81e1887](https://github.com/hrishikeshdkakkad/fluidbox/commit/81e18876780dcac6092c8fafe8aa6e7b1dfc1127))
* **core,server:** frozen-schema argument enforcement at the gate ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([708cecc](https://github.com/hrishikeshdkakkad/fluidbox/commit/708ceccf495648de7ed823330edc231948a696e1))
* **core:** connection requirements + run-binding fields on RunSpec ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([d72aedc](https://github.com/hrishikeshdkakkad/fluidbox/commit/d72aedce28639e5e82b110adb69e52c9b657c6c7))
* **core:** event invocation context + github result destinations + TrustTier::as_str ([a6ed044](https://github.com/hrishikeshdkakkad/fluidbox/commit/a6ed044ec9481bf5ff97fa5c18ab800d0a29ec6d))
* **core:** read-only trust tier classifier (fork events review, never write) ([b9af0a8](https://github.com/hrishikeshdkakkad/fluidbox/commit/b9af0a8d6d49530bf8cfa7d6678426b61495438a))
* **db,server,chart:** remove the ceilings that made 300 concurrent runs impossible ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([e7ecb3d](https://github.com/hrishikeshdkakkad/fluidbox/commit/e7ecb3dc03701bdd17dc95ea36e0dfed04ca7d3f))
* **db:** 0013 appendix — legacy brokered bundles to connection requirements, subscriptions repointed ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([4de4e9c](https://github.com/hrishikeshdkakkad/fluidbox/commit/4de4e9c20c6a6855eb6169c1d16425372f698665))
* **db:** atomic subscription+schedule update with stale guard ([042655c](https://github.com/hrishikeshdkakkad/fluidbox/commit/042655c780da1a6becaac940b5551c15af00b375))
* **db:** event delivery/dispatch/external-result tables + trust-tier & dispatch binding (migration 0005) ([0891d45](https://github.com/hrishikeshdkakkad/fluidbox/commit/0891d45edfa90a73458df70266ffc1958836b018))
* **db:** identity layer — migration 0012, TenantScope, identity repositories ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([86395a8](https://github.com/hrishikeshdkakkad/fluidbox/commit/86395a8ba90c6132a7d874621a33a9db61c08387))
* **db:** migration 0013 — connection ownership, tool snapshots, run resource bindings ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([b632736](https://github.com/hrishikeshdkakkad/fluidbox/commit/b632736fbf1d8534cb52d001eab05a73e055a5e3))
* **db:** RLS policies + tenant GUC plumbing, wave A ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32),[#75](https://github.com/hrishikeshdkakkad/fluidbox/issues/75)) ([9f27a47](https://github.com/hrishikeshdkakkad/fluidbox/commit/9f27a4710e0d015bbd4b931a283c86362134aba9))
* **db:** RLS wave B — identity + audited system_worker bypass ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32),[#75](https://github.com/hrishikeshdkakkad/fluidbox/issues/75)) ([cd5f00d](https://github.com/hrishikeshdkakkad/fluidbox/commit/cd5f00d8e89033ac6fd55568eb736432311a3460))
* **demo:** fixture repo + demo compose ([3c1f5c9](https://github.com/hrishikeshdkakkad/fluidbox/commit/3c1f5c987988384f316eb0f2f188202e688754a0))
* **demo:** just demo — five-minute no-key first-run + validation drills ([007da29](https://github.com/hrishikeshdkakkad/fluidbox/commit/007da290f09bc970a1dd4979292326aa4f9f23ea))
* **dev:** local Postgres container replaces Neon for local development ([21c5b03](https://github.com/hrishikeshdkakkad/fluidbox/commit/21c5b03feaa3deb15b50f873161ed722484c1220))
* **docs,web:** public /docs platform — relocated engine, search, new guides ([f3b4454](https://github.com/hrishikeshdkakkad/fluidbox/commit/f3b4454deb8b3d1cb32acfd88dfc6018c6d93c38))
* **docs,web:** repo docs tree + in-app /developer docs engine ([7865c42](https://github.com/hrishikeshdkakkad/fluidbox/commit/7865c4237e8a278a309adffe469e37c9410b9a25))
* durable automation API contract, PATCH /v1/triggers/{id}, self-explanatory template box ([db19dba](https://github.com/hrishikeshdkakkad/fluidbox/commit/db19dbacf1b33f4f63ab03435124f0018f04fd5d))
* **dx:** one-command bootstrap (just setup) + environment preflight (just doctor) ([d4bb3b9](https://github.com/hrishikeshdkakkad/fluidbox/commit/d4bb3b90f26b24c22565bc15b8bd2ef3423f88ac))
* **dx:** one-command bootstrap (just setup) + environment preflight (just doctor) ([3ae195c](https://github.com/hrishikeshdkakkad/fluidbox/commit/3ae195c6516826dc6bf14f04ebc7d38e1a45e0ac))
* **e2e:** codex phase 10 (protocol replay + no-model probes + live tier) + deploy wiring (Phase 6 step 8) ([95abec5](https://github.com/hrishikeshdkakkad/fluidbox/commit/95abec519adf1814544a7521fcfc628f0d91d422))
* **facade+gate:** second dialect enforcement boundary, OpenAI metering, intent-based tool budget, approval digest binding (Phase 6 step 4) ([955bc57](https://github.com/hrishikeshdkakkad/fluidbox/commit/955bc570edad29339325c85ce2c34f325e3106f2))
* **github:** expose updated_at/pushed_at in the repo picker projection ([c3c12f1](https://github.com/hrishikeshdkakkad/fluidbox/commit/c3c12f12a56573a4e35f0d86ded0381158f2a9f3))
* **github:** Phase 5.6 — seamless GitHub connect via App manifest + install dances ([c56638f](https://github.com/hrishikeshdkakkad/fluidbox/commit/c56638f2405f249c2ebd603877e9883e87371afa))
* **governance:** the Governance page — per-tool permissions matrix + managed overrides ([#36](https://github.com/hrishikeshdkakkad/fluidbox/issues/36)) ([e7a253f](https://github.com/hrishikeshdkakkad/fluidbox/commit/e7a253f5f9cf4f7d41a557892d8a0fdcd7e4a7f7))
* **governor,db:** cross-replica egress governance — durable rate windows + breaker ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([023c151](https://github.com/hrishikeshdkakkad/fluidbox/commit/023c151eeffcdd6b1f7acaf2a71f2ef9b133aa5f))
* **harness:** server-side harness registry; per-harness API defaults; orchestrator env seam (Phase 6 steps 1-3) ([fd2b266](https://github.com/hrishikeshdkakkad/fluidbox/commit/fd2b2667aa29bdbc3291a05bd267ff96372e4f0e))
* **k8s:** Phase 0 — provider seam + collection hardening (Docker-only) ([#49](https://github.com/hrishikeshdkakkad/fluidbox/issues/49)) ([7930e96](https://github.com/hrishikeshdkakkad/fluidbox/commit/7930e96fd9d207062f5521d8828222a7e2998018))
* **k8s:** Phase 1 — KubernetesProvider + workspaced collector + dual listener ([#50](https://github.com/hrishikeshdkakkad/fluidbox/issues/50)) ([223e5e8](https://github.com/hrishikeshdkakkad/fluidbox/commit/223e5e88b0d08819f831c174e399aa1aaf8f07ff))
* **k8s:** Phase 2 — Helm chart + verified network hardening + per-cloud presets ([#51](https://github.com/hrishikeshdkakkad/fluidbox/issues/51)) ([336bc92](https://github.com/hrishikeshdkakkad/fluidbox/commit/336bc92c79c6a8cdf81cf8bd4578ce545fcf177b))
* **k8s:** Phase 3 — CI + provider conformance ([#52](https://github.com/hrishikeshdkakkad/fluidbox/issues/52)) ([8c54b7b](https://github.com/hrishikeshdkakkad/fluidbox/commit/8c54b7bbe4f35a635c272dcb127199d31c70b386))
* **phase-f:** Codex review gate fixes + operational metrics ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([54df7e0](https://github.com/hrishikeshdkakkad/fluidbox/commit/54df7e0127c2ab8541a13fa5ea519a44931bfd2b))
* **policies:** append-only policy_versions — migration 0026 + storage ([eb1232b](https://github.com/hrishikeshdkakkad/fluidbox/commit/eb1232bdd8757611147b7a882660a80a1dd503d3))
* **policies:** codex-review hardening — CAS publishes, strict drafts, enforced append-only ([b72f35a](https://github.com/hrishikeshdkakkad/fluidbox/commit/b72f35aa9b4f20fde2a8c5e0e45df0dd9798e729))
* **policies:** DB-native policies — versioned storage, structured authoring, attachment (§17 [#11](https://github.com/hrishikeshdkakkad/fluidbox/issues/11)) ([eb0d426](https://github.com/hrishikeshdkakkad/fluidbox/commit/eb0d426e13ecaceef1866e694b23f9d103659f25))
* **policies:** fold managed overrides into head rules in the engine ([45eda12](https://github.com/hrishikeshdkakkad/fluidbox/commit/45eda129d692ccbd1592b9a635da41818ecf8340))
* **policies:** retire policy-sync; governance e2e for the versioned model ([319679e](https://github.com/hrishikeshdkakkad/fluidbox/commit/319679e94fcc8b250af588d2f7b4faa15ea9404a))
* **redact,codex:** scrub OpenAI project keys + fbx session/trigger tokens; codex-runner package.json (Phase 6 step 6 prep) ([5fea3e2](https://github.com/hrishikeshdkakkad/fluidbox/commit/5fea3e227c169d4d06bb4d4614c2bbc2facadaa3))
* **replay-runner:** deterministic replay driver + transcript ([d14c77e](https://github.com/hrishikeshdkakkad/fluidbox/commit/d14c77eb266b5e9152f0ca605bf4315f7719c5ff))
* **replay-runner:** image + just replay-build ([a40639b](https://github.com/hrishikeshdkakkad/fluidbox/commit/a40639bfea8ba9c25b41decf035cccf02b64750e))
* **runner:** move the control token off the environment before exec ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([a9a5bea](https://github.com/hrishikeshdkakkad/fluidbox/commit/a9a5bea7683f9c95211473efc7555bb0aa114c40))
* **runner:** shared runner-lib (contract + shims) + token-renew loop + server-side renew hardening (Phase 6 step 5) ([ffc57fe](https://github.com/hrishikeshdkakkad/fluidbox/commit/ffc57fe97d3769bd1befd06bbde103a2c94e2688))
* **scripts:** db-clean-tests — a scalpel for test residue, not a reset ([#46](https://github.com/hrishikeshdkakkad/fluidbox/issues/46)) ([ee9bfb5](https://github.com/hrishikeshdkakkad/fluidbox/commit/ee9bfb5d061f3f48e7ae9e917f8629a3f692ae4e))
* **server,db:** approval single-emission + pg_notify, session lease/epoch fencing, delivery claims ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([800f8c3](https://github.com/hrishikeshdkakkad/fluidbox/commit/800f8c35d613904063978e7aa7246ba099f51b0c))
* **server,db:** durable four-state execution claims around brokered dispatch ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([33dcf45](https://github.com/hrishikeshdkakkad/fluidbox/commit/33dcf4598b185bf6eb92490adbc01e0d3ecaf085))
* **server,db:** durable request-keyed LLM budget reservations ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([757d87e](https://github.com/hrishikeshdkakkad/fluidbox/commit/757d87e2da5cfa6cee0c3a88a355dd0ad74086b7))
* **server,db:** one-time browser-bound OAuth state rows ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([ab6f82e](https://github.com/hrishikeshdkakkad/fluidbox/commit/ab6f82e79497466c2483933ac91ed74b681a6d34))
* **server,db:** reusable OAuth client registrations ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([f075a8c](https://github.com/hrishikeshdkakkad/fluidbox/commit/f075a8c18d5ef0c3fac647562de7f55edab54958))
* **server,db:** versioned envelope sealing with per-tenant DEKs ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([34d4898](https://github.com/hrishikeshdkakkad/fluidbox/commit/34d48988cd0826f47c04bbfd9aa82659e070e181))
* **server,workspace:** workload identity, archive object store, load harness ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([33fefb8](https://github.com/hrishikeshdkakkad/fluidbox/commit/33fefb8979743e9e3e0f2fad847392d48de105d5))
* **server:** /v1/admin/orgs — break-glass, IdP lifecycle, issuer migration ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([c1906bb](https://github.com/hrishikeshdkakkad/fluidbox/commit/c1906bbdca2ec9d49b3f19263e89078b40057984))
* **server:** /v1/auth — IdP-agnostic OIDC login, sessions, switch, logout ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([c659a45](https://github.com/hrishikeshdkakkad/fluidbox/commit/c659a4503c50445eb55154c4702e09dc88842340))
* **server:** binding consumers — broker/workspace/publish rechecks, approval authority ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([3c003e7](https://github.com/hrishikeshdkakkad/fluidbox/commit/3c003e7f479c9c15084293363bf250d70b9e16e1))
* **server:** binding resolution service — requirements to frozen run resource bindings ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([b301e3f](https://github.com/hrishikeshdkakkad/fluidbox/commit/b301e3f903a85bb18f2aafec70126c5712b25cb1))
* **server:** connection ownership — personal/organization owners, use authorization, /auth/me user_id ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([e09388e](https://github.com/hrishikeshdkakkad/fluidbox/commit/e09388e7e407005f568ccbfdfcf52668a342f32e))
* **server:** connection tool snapshots — forced-negotiation photograph, bundle cutover, generation custody ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([ba08d91](https://github.com/hrishikeshdkakkad/fluidbox/commit/ba08d916ec108fa49e1966a49ec177d76c71f1da))
* **server:** contract URL + ingress helpers on trigger get/list/rotate ([de85bf0](https://github.com/hrishikeshdkakkad/fluidbox/commit/de85bf04a3f20e2269b426410d1ac02bc7f5e8f4))
* **server:** event trigger subscriptions — connection binding, $17 [#2](https://github.com/hrishikeshdkakkad/fluidbox/issues/2) default events, publish modes ([273922d](https://github.com/hrishikeshdkakkad/fluidbox/commit/273922ddfbcc46482169af5465b17c7dee799c0f))
* **server:** fork trust tier is real — read-only enforcement at the permission gate ([7a070dd](https://github.com/hrishikeshdkakkad/fluidbox/commit/7a070dd5e055e2a812e3728b969e44e80a9e2f3c))
* **server:** github app connections — rs256 jwt, installation tokens, sealed webhook secret ([e3b869f](https://github.com/hrishikeshdkakkad/fluidbox/commit/e3b869ff12dfdc1548c9e68f68b7a1b122103a84))
* **server:** github connector — webhook verify + PR normalize behind the seam ([74390cc](https://github.com/hrishikeshdkakkad/fluidbox/commit/74390ccd01cc9c9fa280c5ff18ee04e95aea9fd3))
* **server:** outbound rate limits + per-connection circuit breakers ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([79dc55b](https://github.com/hrishikeshdkakkad/fluidbox/commit/79dc55b4b68974375bbf184d01414a6b8f6ee8dc))
* **server:** PATCH /v1/triggers/{id} for the mutable subscription surface ([3c48b8e](https://github.com/hrishikeshdkakkad/fluidbox/commit/3c48b8e2e535635961faa51129294531b6fac29b))
* **server:** per-run MCP session manager + 2025-11-25 conformance ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([89dbaa9](https://github.com/hrishikeshdkakkad/fluidbox/commit/89dbaa90ae06ca9c9fc2a4307db73bbc82fc550f))
* **server:** per-tenant LiteLLM virtual keys; master key confined to provisioning ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([1275ae2](https://github.com/hrishikeshdkakkad/fluidbox/commit/1275ae240b2adce59f73c29e404e9886ff03318c))
* **server:** PR comment/check publishers — stable update-in-place identity, App-only ([74fd34e](https://github.com/hrishikeshdkakkad/fluidbox/commit/74fd34e815362eaebec78308fd2653691d1b3a20))
* **server:** Principal resolver, RBAC, PATs, CSRF — identity enforcement ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([e469d09](https://github.com/hrishikeshdkakkad/fluidbox/commit/e469d0975c28103f32b10fb25ba7b3519acd6f5f))
* **server:** provider-ignorant event spine — ingress, two-level dedup, subscription fan-out ([f339538](https://github.com/hrishikeshdkakkad/fluidbox/commit/f3395387c303331ab2d3d4dbea10fe808a560eee))
* **server:** pure PATCH resolution for trigger subscriptions ([973d83a](https://github.com/hrishikeshdkakkad/fluidbox/commit/973d83aad1406258ceadf5cddd13a1f52e4eb565))
* **server:** resumable legacy→KMS re-seal with count parity ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([b39b5dd](https://github.com/hrishikeshdkakkad/fluidbox/commit/b39b5dd05998e4da225e544b660922580f2ca7ce))
* **server:** shared egress boundary — SSRF-hardened clients + clone admission ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([739f6b2](https://github.com/hrishikeshdkakkad/fluidbox/commit/739f6b214f06469d4e190f02cf5a7084df25d208))
* **web:** app-store composer — unified AppPicker, guardrail presets, plain language ([9e90e45](https://github.com/hrishikeshdkakkad/fluidbox/commit/9e90e45d5e8cded0ca4723738ff4c2315ca84409))
* **web:** bundle picker for agent attach — select registered capabilities instead of typing refs ([ba4269a](https://github.com/hrishikeshdkakkad/fluidbox/commit/ba4269adc78bc8e54a27288c0d6d96e314eb18f9))
* **web:** connection ownership, tool snapshots, requirements editor, explicit bindings ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([f599f1b](https://github.com/hrishikeshdkakkad/fluidbox/commit/f599f1bf29d4bbd13f3602b43d13ed5f32cc5b03))
* **web:** dashboard redesign — 5-item IA, dark design system, app-store integrations ([c6eb415](https://github.com/hrishikeshdkakkad/fluidbox/commit/c6eb415f024fedf0ea793bcf8015e0d5c7eda888))
* **web:** durable /automations/{id} page with live API contract ([680083b](https://github.com/hrishikeshdkakkad/fluidbox/commit/680083bee932adfbf4fcef43701ee2b8f5c0b468))
* **web:** edit template and settings on the automation detail page ([8a57fc9](https://github.com/hrishikeshdkakkad/fluidbox/commit/8a57fc93cc94af729b546093b60e6d268f196001))
* **web:** enable codex harness; per-harness models reset on switch (Phase 6 step 9) ([0c3170f](https://github.com/hrishikeshdkakkad/fluidbox/commit/0c3170fc6ac24519a68764795e9bd66504d0cabc))
* **web:** extract pure automation-contract helpers ([a2f67d1](https://github.com/hrishikeshdkakkad/fluidbox/commit/a2f67d10ff7686147065b6b5a5445a1c3157539f))
* **web:** FLUIDBOX_WEB_MODE sso proxy, login page, session shell ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([2991ace](https://github.com/hrishikeshdkakkad/fluidbox/commit/2991ace5011fff8e9b0bc3e7d6b53d9d0131ba4a))
* **web:** homepage v2 — patterns grid + real-product visibility section ([9319363](https://github.com/hrishikeshdkakkad/fluidbox/commit/9319363a8684b2908bc7c18ce3f8f32c61fa220e))
* **web:** improve control-plane UX and resilience ([709114f](https://github.com/hrishikeshdkakkad/fluidbox/commit/709114fba98adf5bf99854f96cb25be81d3791c7))
* **web:** marketing site redesign — dark editorial system, film hero, end-user pass ([1b9e52c](https://github.com/hrishikeshdkakkad/fluidbox/commit/1b9e52cdc3dc3b23f6997e65a6a6a11ad9e5609b))
* **web:** move the dashboard under /app — the public/app boundary ([293ba74](https://github.com/hrishikeshdkakkad/fluidbox/commit/293ba74bc2e67fe7460cc9ff4bbf2f7dd676e317))
* **web:** policy attachment + structured authoring (specs A & C) ([0c8ba6e](https://github.com/hrishikeshdkakkad/fluidbox/commit/0c8ba6ebc05c6dd4808a2558ad890f35aff79bf1))
* **web:** public marketing site — home, product, open-source, security, pricing, changelog ([3d8eb25](https://github.com/hrishikeshdkakkad/fluidbox/commit/3d8eb25c9b00771d2e2ba6f1d8d5c88041eb68b4))
* **web:** self-explanatory template box + pre-save API preview ([42d44dc](https://github.com/hrishikeshdkakkad/fluidbox/commit/42d44dc82270212210acfd0fd61393bd98b2558f))
* **web:** SEO surface — sitemap, robots, OG/Twitter card, noindex boundaries ([21db1ea](https://github.com/hrishikeshdkakkad/fluidbox/commit/21db1ea42c3e49351bc0718d2abae6ad39fed252))
* **web:** server-side auth gate — sso login wall, session-aware /login, deep-link return ([93f6ed6](https://github.com/hrishikeshdkakkad/fluidbox/commit/93f6ed6a5d2b3abefffda9aa604a412b7c3def38))
* **web:** shared AutomationContract; secrets modal is secrets-only ([2d0f5af](https://github.com/hrishikeshdkakkad/fluidbox/commit/2d0f5af5ad710bd8fea4716e8741d6de6ee00757))
* **web:** surface the brokered execution outcome in the run timeline ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([3d97cf5](https://github.com/hrishikeshdkakkad/fluidbox/commit/3d97cf5df7dc68351b7d75ca6f70b3c27036fcfc))
* **web:** unify dashboard and run workflows ([#26](https://github.com/hrishikeshdkakkad/fluidbox/issues/26)) ([e3a475d](https://github.com/hrishikeshdkakkad/fluidbox/commit/e3a475dd38dbfb5f1f9401a1c7f5a3b6a06b240a))
* **web:** WorkOS AuthKit web-tier gate for /app (FLUIDBOX_WEB_AUTH=workos) ([04019dc](https://github.com/hrishikeshdkakkad/fluidbox/commit/04019dc4a3560f0e518fa3e5aa133aa442bd734c))


### Fixed

* **capabilities:** admit real-vendor tool manuals in the photograph screen ([738d758](https://github.com/hrishikeshdkakkad/fluidbox/commit/738d758c46886a40cec08032bb2c24cdae5d7333))
* **ci,docs:** strengthen false-green asserts; correct the go_url residual disclosure ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([fb65948](https://github.com/hrishikeshdkakkad/fluidbox/commit/fb659488016cead2c12e489686f5642bf54c493d))
* **ci:** bindings-e2e — instant provisioning failure via dead-registry image ref; settle budget 300s ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([033ace0](https://github.com/hrishikeshdkakkad/fluidbox/commit/033ace0837a56bb02b75037c86b1f36fc42cb0d6))
* **ci:** CI round 2 — __Host- flow cookie, DB fixture shapes, family lockstep, AWS SDK rustls stack ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([2d7657b](https://github.com/hrishikeshdkakkad/fluidbox/commit/2d7657b4be1e10a6c16d88b678e6f20a51dab68c))
* **ci:** identity-e2e — curl -w composition, psql tuple-only captures, fail-fast preconditions ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([196e2a7](https://github.com/hrishikeshdkakkad/fluidbox/commit/196e2a7a7d93fe82bd50e4b1e9bffd707dfda17b))
* **ci:** read gate-proof evidence through a container, not from the host ([23a44ab](https://github.com/hrishikeshdkakkad/fluidbox/commit/23a44abdef4079d12ae035df5276d7e9ad94b0f2))
* close the three P2s, pin the runner supply chain, gate publishing ([#112](https://github.com/hrishikeshdkakkad/fluidbox/issues/112)) ([19b7f7d](https://github.com/hrishikeshdkakkad/fluidbox/commit/19b7f7d7c32e25b482c623ddd98c8e96eb289429))
* **codex:** correct item/tool/requestUserInput response schema to {answers:{}} (Step 6 re-review) ([b68a300](https://github.com/hrishikeshdkakkad/fluidbox/commit/b68a300a049409b9d66fc940baaa1506b6764257))
* **codex:** incorporate Step 6 review — governance completeness, move-path, state dirs, schemas (codex/gpt-5.6-sol) ([d080064](https://github.com/hrishikeshdkakkad/fluidbox/commit/d080064f124dce278883281d570bb7d350816150))
* **codex:** make the codex harness actually start (it never did) ([b7a4d8f](https://github.com/hrishikeshdkakkad/fluidbox/commit/b7a4d8f3de677fc3ad7c5d92c918ff97e369ab38))
* **core:** govern every tool the pinned CLI advertises; deny sub-execution ([c0aa531](https://github.com/hrishikeshdkakkad/fluidbox/commit/c0aa531e0500a7187489dedc8c196913705e38b3))
* **core:** register ToolSearch in the canonical tool vocabulary ([92fec3c](https://github.com/hrishikeshdkakkad/fluidbox/commit/92fec3c1e75778d2fea9fde0a843e03413d19425))
* **db,ci,docs:** final-review wave — RLS blast radius, e2e port, runtime-role coverage ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([6c0e5f9](https://github.com/hrishikeshdkakkad/fluidbox/commit/6c0e5f93314a1a69e6168d8bbec32b8dba088fbc))
* **db,server:** Codex verify — ingress scope-after-verify, switch config-lock, residual predicates ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([5549e5b](https://github.com/hrishikeshdkakkad/fluidbox/commit/5549e5b8e57b5bb7f14a91d7d8c37f3e708243ca))
* **db,server:** drop the unused delivery-claim index; scope the epoch-fence claim ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([b626ba8](https://github.com/hrishikeshdkakkad/fluidbox/commit/b626ba899b0e9c45038c48db879d32ae72330d8d))
* **db,tools:** catalog importer targets the global partial slug index; isolate mcp-shape CHECK negative ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([ff6c74e](https://github.com/hrishikeshdkakkad/fluidbox/commit/ff6c74e1e38d6ad8ce58d4c425ce81d0fbdb6981))
* **db:** 0013 conversion — branch coverage tests, mixed-bundle drop notice, safe string-pin parse ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([357762c](https://github.com/hrishikeshdkakkad/fluidbox/commit/357762c82948951fa08d39de78f83f494a166f66))
* **db:** 0013 conversion — floating keep-lists, append-only clone for sandbox-latest ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([f622fb7](https://github.com/hrishikeshdkakkad/fluidbox/commit/f622fb78dd200d78cf9b5d07afe9453941d082a6))
* **db:** 0013 conversion — fresh next-rev per appended revision ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([9c99601](https://github.com/hrishikeshdkakkad/fluidbox/commit/9c996016a6ea416d8374743ca16305561fe8ce89))
* **db:** 0013 conversion — per-source revisions, keep-list-preserving repoints ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([eafad54](https://github.com/hrishikeshdkakkad/fluidbox/commit/eafad54ecbe4726beb3bbf3c55bd0d8b5793bb46))
* **db:** Codex round-1a — write-side tenant proofs, switch-claim hardening, audit truncate guard ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([187fb6d](https://github.com/hrishikeshdkakkad/fluidbox/commit/187fb6d73e67c5dfacc8f53eb48a1cd203e8d9f8))
* **db:** final-review minors — projections, user_status symmetry, bootstrap/migrate test gaps ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([581f26f](https://github.com/hrishikeshdkakkad/fluidbox/commit/581f26f31f675e6598932ead70da80dd790f2134))
* **db:** RLS review wave — role posture validation, enumerated grants, audit tenant floor ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([09e1cdf](https://github.com/hrishikeshdkakkad/fluidbox/commit/09e1cdfba4782c2fd1c8a70dfdfbb09afb5b7be2))
* **db:** scope the sweeper tests to their own session ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([d4fb57d](https://github.com/hrishikeshdkakkad/fluidbox/commit/d4fb57d686eaebecc812913cd6de23347a28046b))
* **db:** switch-claim takes the config lock first; jwks cache active-only ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([d00d348](https://github.com/hrishikeshdkakkad/fluidbox/commit/d00d3487da04b2e90f8012322a2628ce59421aef))
* **db:** the 0013 conversion is a GLOBAL scan — confine the tests to one tenant ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([2932aa9](https://github.com/hrishikeshdkakkad/fluidbox/commit/2932aa9cca83c15244259ee881f036b008cc11c2))
* **demo:** fail when the run fails; agree with the server on the docker daemon ([40ce3c9](https://github.com/hrishikeshdkakkad/fluidbox/commit/40ce3c93a14b24fd4a9d1ef3c4a45e70dc1473ca))
* **demo:** prove the daemon can read the checkout before running ([18fc153](https://github.com/hrishikeshdkakkad/fluidbox/commit/18fc1533d9a1706e774b612c06524a531ac70d75))
* **demo:** the from-source first run was broken; add static self-checks ([b52a554](https://github.com/hrishikeshdkakkad/fluidbox/commit/b52a554823889dc68f4f7db006ea21e412fd53a8))
* **e2e,core:** three SCRIPT defects behind the first hardening run ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([14d6f64](https://github.com/hrishikeshdkakkad/fluidbox/commit/14d6f64280a108a98a437efb10288f4b82289b4d))
* **e2e,ledger:** codex phase green (16/16) — summarize() lists edit paths; replay assertion counts ([41a3081](https://github.com/hrishikeshdkakkad/fluidbox/commit/41a3081bb0410e13668325a5f50e0013f6d3c9d7))
* **e2e:** deflake trigger rotation race; align github phase with [#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33) identities ([9817bf1](https://github.com/hrishikeshdkakkad/fluidbox/commit/9817bf1d24513b316ccfa623ad1450b9d4d2d644))
* **e2e:** make no-live mode zero-spend and deterministic (closes the CI flake class) ([#23](https://github.com/hrishikeshdkakkad/fluidbox/issues/23)) ([89f518c](https://github.com/hrishikeshdkakkad/fluidbox/commit/89f518c12b17ce8a0c96b569ae7fcf1ad46d0106))
* **e2e:** strip stray ellipsis byte that broke e2e.sh preflight under set -u ([8c4657a](https://github.com/hrishikeshdkakkad/fluidbox/commit/8c4657acb749293e3bb629b425574822165456db))
* **e2e:** suite fixes surfaced by the full local run (611/0 across the five phase suites) ([ccaf199](https://github.com/hrishikeshdkakkad/fluidbox/commit/ccaf1990573b6b951d9ed49036c584d130e12d35))
* **e2e:** WRONG ASSERTION — (i.4) demanded 'cancelling' its own fixture cannot produce ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([0f0da8e](https://github.com/hrishikeshdkakkad/fluidbox/commit/0f0da8eb6e1a60a8fe796af1875f15ae995c967e))
* **eval:** quote the required-token message, and make the guard parse the file ([4377c96](https://github.com/hrishikeshdkakkad/fluidbox/commit/4377c96f8bf54c72237dcd6f099d2b10aca5039b))
* **eval:** require an admin token; loopback the dashboard; guard both in CI ([3bbf73b](https://github.com/hrishikeshdkakkad/fluidbox/commit/3bbf73bf3eea1851d863f6dea88ed53e35994059))
* **facade,e2e,web:** post-ship Phase 6 correctness review ([894cbc4](https://github.com/hrishikeshdkakkad/fluidbox/commit/894cbc41657b1b11580305db7f3e8488757d9b2c))
* **facade+gate:** incorporate Step 4 review — dup-key differential, verdict CAS, NULL-digest fail-closed, dialect errors, SSE cap (gpt-5.6-sol xhigh) ([30bc78c](https://github.com/hrishikeshdkakkad/fluidbox/commit/30bc78cc29a49ddf3f93b637afebc46cb88d90d8))
* final-review follow-ups — preserve next_fire_at on cadence-neutral PATCH, no-op {} schedule, clearer errors/hints ([37ac1db](https://github.com/hrishikeshdkakkad/fluidbox/commit/37ac1db4a3429e6f716f343d9c87db5bfb53e0b1))
* **gate:** CAS-first on the budget + approval-timeout paths (Step 4 re-review) ([c9e5d75](https://github.com/hrishikeshdkakkad/fluidbox/commit/c9e5d7553b5209e2a3deea6454f40d8d0e723891))
* **gate:** server-side /result idempotency across revoke + /permission terminal check (Step 5 re-review) ([94a854a](https://github.com/hrishikeshdkakkad/fluidbox/commit/94a854a63b5589bfb658cd97a8197027bf56b26a))
* **github:** drop default_events with the webhook on non-public deployments ([9185202](https://github.com/hrishikeshdkakkad/fluidbox/commit/9185202632bdd769d5df6aec22e9c7b0fda08768))
* **github:** omit the webhook from manifests on non-public FLUIDBOX_PUBLIC_URL ([6de3334](https://github.com/hrishikeshdkakkad/fluidbox/commit/6de3334d5f577cb52d53dca8d768aecca181e503))
* **k8s:** archive streaming — pack to disk with a size cap, stream the GET, reclaim leaks (M4, L3) ([1b238a2](https://github.com/hrishikeshdkakkad/fluidbox/commit/1b238a2887dde5e1dd8798b56c577bf7133a0b63))
* **k8s:** batch-5 Codex round 2 — toleration fidelity, render-time validation, release binding tightened ([c45f90b](https://github.com/hrishikeshdkakkad/fluidbox/commit/c45f90b5e2f4178deddd57b59274040726cddbb2))
* **k8s:** batch-5 Codex round 3 — strict toleration fields, semver tag guard, doc truth ([09bab0d](https://github.com/hrishikeshdkakkad/fluidbox/commit/09bab0d9a6d80823a3b1b014ad0f2187f73a34d4))
* **k8s:** batch-6 Codex round 2 — pod-side streaming, atomic pack, fail-closed caps, safer archive lifecycle ([bed3217](https://github.com/hrishikeshdkakkad/fluidbox/commit/bed32177d058a62895987b79cdc0fefcb088876f))
* **k8s:** batch-6 Codex round 3 — symlink-entry ceiling, session-state-aware TTL sweep, quieter-never-silent failures ([8b945be](https://github.com/hrishikeshdkakkad/fluidbox/commit/8b945bec632092981587ed6cb90e15540ac46c0a))
* **k8s:** batch-7 Codex round 2 — rolling-deploy-safe reconcile, guarded adoption, honest no-handle collection ([8a6a2af](https://github.com/hrishikeshdkakkad/fluidbox/commit/8a6a2af0d30a263b0b79250954732692b74f9fee))
* **k8s:** batch-7 Codex round 3 — boot-sweep parse parity, honest label mismatch, launch-mins floor ([732334e](https://github.com/hrishikeshdkakkad/fluidbox/commit/732334ed48f0409e92b39a35da7d77cb8e40590d))
* **k8s:** buffer the archive file reader in workspaced init ([7ddacad](https://github.com/hrishikeshdkakkad/fluidbox/commit/7ddacada4d669de71afd0af7e04381d26648de84))
* **k8s:** cleanups — fail-closed gate resolution, UID-guarded deletes and collection, quiesce replay (L2, L10, L11) ([8c78339](https://github.com/hrishikeshdkakkad/fluidbox/commit/8c78339725720e9b9a9a9275d0a0f23d33a1dcf0))
* **k8s:** cleanups — fail-closed gate resolution, UID-guarded deletes, quiesce replay (L2, L10, L11) ([4ec0b09](https://github.com/hrishikeshdkakkad/fluidbox/commit/4ec0b09927c2e8e4435b0bb85f93e60cb22ca600))
* **k8s:** close the Codex round-2 findings on the finalizer (M1 pre-handle window + 8 defects) ([8d01bfe](https://github.com/hrishikeshdkakkad/fluidbox/commit/8d01bfe74b5d873091084a088118c01e939e0c86))
* **k8s:** close the netpol admission race with a bounded observation protocol ([95e8459](https://github.com/hrishikeshdkakkad/fluidbox/commit/95e8459c3f1351e569ff9a20dd4219485a9fad19))
* **k8s:** enforce a fresh destination before extract/copy (Codex batch-3v3) ([98f4ebb](https://github.com/hrishikeshdkakkad/fluidbox/commit/98f4ebb986ade996098ac6efa645e8a474d0ff84))
* **k8s:** extract in-tree symlinks in the workspace archive (H4, L4-pack) ([db11f77](https://github.com/hrishikeshdkakkad/fluidbox/commit/db11f77b4fae35f70d9441787bc9b5673e56a340))
* **k8s:** extract in-tree symlinks in the workspace archive (H4, L4-pack) ([09230b6](https://github.com/hrishikeshdkakkad/fluidbox/commit/09230b63b0b3a08408f1d8cf73df29275b7db2a8))
* **k8s:** finalizer durability — winning intent is the single source of truth (H2,H3,H5,M1,L6,L7) ([f10e3ce](https://github.com/hrishikeshdkakkad/fluidbox/commit/f10e3ce06ad7c0be5abb6ceed04c0387e4ddb19e))
* **k8s:** harden symlink extraction + preserve links in copy_tree (Codex review of [#61](https://github.com/hrishikeshdkakkad/fluidbox/issues/61)) ([a0fa0a8](https://github.com/hrishikeshdkakkad/fluidbox/commit/a0fa0a840edf70c1a110a330c101cd5aed90c7a6))
* **k8s:** helm↔provider wiring — sandbox values reach the provider, digests render, probe gate parity (M3, M9, M10, L12) ([428a5dd](https://github.com/hrishikeshdkakkad/fluidbox/commit/428a5ddee67b34db527f7e1f99104d53ecbae934))
* **k8s:** helm↔provider wiring — sandbox values reach the provider, digests render, the boot probe gains gate parity (M3, M9, M10, L12) ([9adb745](https://github.com/hrishikeshdkakkad/fluidbox/commit/9adb7455ba84916465c017fc501b3494e6a4e6bc))
* **k8s:** install ring CryptoProvider so the Kubernetes provider boots ([3fc508e](https://github.com/hrishikeshdkakkad/fluidbox/commit/3fc508e3b9d91ae8d825c006745ab2e6dbab5fea))
* **k8s:** install ring CryptoProvider so the Kubernetes provider boots ([54a292b](https://github.com/hrishikeshdkakkad/fluidbox/commit/54a292b6bf5c689ce3c6f3baa3984a3f0f63ea9f))
* **k8s:** integrity-check exec-collected diffs, resume dropped streams (M2, L4-exec) ([7e8e95c](https://github.com/hrishikeshdkakkad/fluidbox/commit/7e8e95ccdf636193de4abe5400e10f7be744ccf5))
* **k8s:** listener hardening — no /internal on the public plane under K8s (M8, L1, L5, L8) ([4453b11](https://github.com/hrishikeshdkakkad/fluidbox/commit/4453b11f42f225653e0a280929a3eec23b5c0b57))
* **k8s:** make canonicalize the sole symlink-containment authority (Codex re-review) ([06f518c](https://github.com/hrishikeshdkakkad/fluidbox/commit/06f518ce12ae1ed5079b60e1f274c8f23ce624fa))
* **k8s:** make the kind-calico CI tier a real check (H1) ([#60](https://github.com/hrishikeshdkakkad/fluidbox/issues/60)) ([e84ea64](https://github.com/hrishikeshdkakkad/fluidbox/commit/e84ea64eb415102f8b3c174dc3ea558416730c1e))
* **k8s:** numeric runAsUser for bundled LiteLLM ([365e657](https://github.com/hrishikeshdkakkad/fluidbox/commit/365e6573402dc180ac657b96d9b9907162b1150e))
* **k8s:** numeric runAsUser for bundled LiteLLM (root image + runAsNonRoot) ([319a8b3](https://github.com/hrishikeshdkakkad/fluidbox/commit/319a8b32f25d95a3053987cbe9aa997f6e4bab21))
* **k8s:** reconcile — periodic adopt-or-terminate sweep, graded config errors, node-loss visibility, Docker-parity pre-launch diffs (M5, M6, M7, L9) ([bd4fdeb](https://github.com/hrishikeshdkakkad/fluidbox/commit/bd4fdeb900c5fe956e336c3764473b7a042ec819))
* **k8s:** reconcile — periodic adopt-or-terminate sweep, graded config errors, node-loss visibility, Docker-parity pre-launch diffs (M5, M6, M7, L9) ([f80b74b](https://github.com/hrishikeshdkakkad/fluidbox/commit/f80b74bf0248417ede9640bbfa976b5192b7a993))
* **k8s:** refuse a symlinked destination in clear_dir_contents (Codex batch-3v4) ([f3276c8](https://github.com/hrishikeshdkakkad/fluidbox/commit/f3276c848cb1288fb34bf9b04dc536ef60454124))
* **k8s:** remove a duplicated match line that broke the build (batch-3 docs commit) ([1c6bc5c](https://github.com/hrishikeshdkakkad/fluidbox/commit/1c6bc5cf17917a79b767e363f3035c3714ed4c65))
* **k8s:** round-3 finalizer hardening — durable budget sweep, settle-window, verified RunResult ([1efca79](https://github.com/hrishikeshdkakkad/fluidbox/commit/1efca79041ad74e0a2bf0877742023e2a1138f79))
* **k8s:** round-6 — transactional attach fence, evidence-preserving abandon ([7a225f6](https://github.com/hrishikeshdkakkad/fluidbox/commit/7a225f6ae9291f9e9701cc4bda722d19740e8a7a))
* **k8s:** rounds 4-5 finalizer convergence — intent-aware launch ownership, gated collection, self-cleaning losers ([799ff63](https://github.com/hrishikeshdkakkad/fluidbox/commit/799ff630b4d4c37c4db6ed396fca64fef74b71c9))
* make an audience mismatch fail loudly; tighten audience disclosures ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([787396e](https://github.com/hrishikeshdkakkad/fluidbox/commit/787396ecc4a9db4fc0d5b0f082e64707c8b27ae4))
* **oauth:** gate CIMD on a fetchable public URL; re-resolve stale client identities ([f55a588](https://github.com/hrishikeshdkakkad/fluidbox/commit/f55a588813273625a8dd736126667d9f196d5c59))
* **policies:** codex confirmation nits — fail-closed seeds, direct RLS probe, sharper e2e pins ([5ddebeb](https://github.com/hrishikeshdkakkad/fluidbox/commit/5ddebeb8f7ff38a96a04f4d4770e925e3926537b))
* **policies:** codex final-review fixes — divergent YAML, preview staleness, strict imports ([b688960](https://github.com/hrishikeshdkakkad/fluidbox/commit/b68896091e4af73254cde4878e6f6d58e8f6ddca))
* **policies:** review-response hardening — proportional seed refusal, policy delete, precise wildcard fold ([adaa74c](https://github.com/hrishikeshdkakkad/fluidbox/commit/adaa74c69c56e304ad765284facc74cb717abf5e))
* **release:** close the three RC verification blockers ([7647357](https://github.com/hrishikeshdkakkad/fluidbox/commit/7647357343cc2bbe1925f72d0d1f91a63f6e341d))
* **release:** don't let the Cargo.lock step mask the real release-please error ([#110](https://github.com/hrishikeshdkakkad/fluidbox/issues/110)) ([1f28e3e](https://github.com/hrishikeshdkakkad/fluidbox/commit/1f28e3e9e31cc62ed29dc5e89826394bcef358c4))
* **release:** drop README.md from release-please extra-files ([2d10b5d](https://github.com/hrishikeshdkakkad/fluidbox/commit/2d10b5d4c972bd60e6c29d946a3dac32ee3f5315))
* **release:** let the version guard express a prerelease ([4d6abf3](https://github.com/hrishikeshdkakkad/fluidbox/commit/4d6abf3b9f4699c37033695938a5dd36ceb0e0ca))
* **release:** make release-please work with a virtual cargo workspace ([#109](https://github.com/hrishikeshdkakkad/fluidbox/issues/109)) ([f699bbe](https://github.com/hrishikeshdkakkad/fluidbox/commit/f699bbe0983cb412faf6664a7ca9badf54ce33d7))
* **review:** address PR [#27](https://github.com/hrishikeshdkakkad/fluidbox/issues/27) whole-branch external review — 4 P1s, 3 P2s, 3 minors ([0bec91a](https://github.com/hrishikeshdkakkad/fluidbox/commit/0bec91a14a651515b3130d24cbdfaa028b6a0e76))
* **runner-test:** an unopened fd is a platform assumption, not a fact ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([b74d990](https://github.com/hrishikeshdkakkad/fluidbox/commit/b74d9909102d97751d5c87d4221fc0858a92d7a1))
* **runner+e2e:** Step 5 review — e2e build context, self-rescheduling renew, /result ack-on-revoke (gpt-5.6-sol) ([1540d77](https://github.com/hrishikeshdkakkad/fluidbox/commit/1540d779d307d601b1990ac61df641b3f7d1cb37))
* **runner:** gate EVERY Claude tool call via a PreToolUse hook ([66e0bb2](https://github.com/hrishikeshdkakkad/fluidbox/commit/66e0bb239adda842fbc734137b03696dfa3b34d7))
* **scale-e2e:** bound each concurrent gate request ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([b53fa43](https://github.com/hrishikeshdkakkad/fluidbox/commit/b53fa439eab94a4799869348af611b0a463bdca1))
* **scale-e2e:** wait on the burst PIDs, not the whole job set ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([aee65df](https://github.com/hrishikeshdkakkad/fluidbox/commit/aee65dfd5c5d3d1bc06d44b4228a65ca6b3371db))
* **scripts:** governance e2e runs from any cwd; .env.example uses reachable bind ([9d6dd7b](https://github.com/hrishikeshdkakkad/fluidbox/commit/9d6dd7bf72a0b772155a8e8079831af66d9d902b))
* **seed:** bootstrap policies insert-if-absent so UI edits survive reboot ([fc770ba](https://github.com/hrishikeshdkakkad/fluidbox/commit/fc770baf8802e8028dcd49bc23c7f423440d80ee))
* **seed:** source the curated agent's harness id + defaults through the registry (steps 1-3 review) ([38a2f7d](https://github.com/hrishikeshdkakkad/fluidbox/commit/38a2f7df92d4fc8092ea21e8c4872dced1efc3ec))
* **server,ci,docs:** refresh-singleflight bug, restore-drill fixture, global-row RLS asserts, runbook truth ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([ff9b00c](https://github.com/hrishikeshdkakkad/fluidbox/commit/ff9b00caabed26f77d8ab358ccb5849a77c22e4a))
* **server,ci:** audited JSON rejections; SSE exit-code assertion; comment accuracy ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([4562053](https://github.com/hrishikeshdkakkad/fluidbox/commit/456205325d7be7d01b367e7e0568e29978bd1642))
* **server,ci:** oauth critical section on one pooled connection; AS error log sanitization; per-bearer init assertion after refresh ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([d533f24](https://github.com/hrishikeshdkakkad/fluidbox/commit/d533f2496087b3e74d069f874f890a0fbe5ded9f))
* **server,ci:** socket-peer client IP unless trusted proxy; e2e readiness path ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([1718a26](https://github.com/hrishikeshdkakkad/fluidbox/commit/1718a26ab92b7c4e853afecb026e56a8224b5c60))
* **server,core:** bound schema validation cost; close ambient-proxy, git-env and OAuth redirect holes ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([478707d](https://github.com/hrishikeshdkakkad/fluidbox/commit/478707d259dac5fae68c91ac07f55cf9d84f460d))
* **server,core:** linear SSE parsing, capped server-request replies, bounded OAuth reads ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([8de3630](https://github.com/hrishikeshdkakkad/fluidbox/commit/8de3630e69eb4976b2a18c7aa81936f01e40b5e4))
* **server,db,ci:** connector_oauth_flows verifier joins the sealed-family lockstep ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([518a2bc](https://github.com/hrishikeshdkakkad/fluidbox/commit/518a2bc4d312fed2b72d989d31ead0cf3f81d792))
* **server,db,runner:** adopt durable outcomes on lost CAS; tenant-partition the governor; stable shim idempotency ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([d5a974e](https://github.com/hrishikeshdkakkad/fluidbox/commit/d5a974e666b3124917ec54ed0c2d1f95362c5040))
* **server,db:** bound claim churn, unify the terminal refusal, gate the legacy path ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([3846b38](https://github.com/hrishikeshdkakkad/fluidbox/commit/3846b38253388db3e6221d8522e565cf41499949))
* **server,db:** charge only on a durable usage write; repair two false-green guards ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([aa9e9ca](https://github.com/hrishikeshdkakkad/fluidbox/commit/aa9e9ca5ef9525ab017da3e6544419de60e7506a))
* **server,db:** codex round findings — recheck seam, oauth atomicity, snapshot guards, xss ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([51f739c](https://github.com/hrishikeshdkakkad/fluidbox/commit/51f739ce33da7c141fab8442cbd1e505c4f4c608))
* **server,db:** land the OAuth custody bag inside the start's lock-holding txn ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([2e945ab](https://github.com/hrishikeshdkakkad/fluidbox/commit/2e945ab3bcdf4f2efe23f526069a666ec9fa934d))
* **server,db:** oauth bump-in-update + post-lock generation gate; sanitized upstream errors; capped discovery reads; trigger-token principal ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([d87fb88](https://github.com/hrishikeshdkakkad/fluidbox/commit/d87fb88610fbcc14954866944cfad973d3ff4485))
* **server,db:** OAuth review wave — activation CAS, bounded key recovery, mint cleanup ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([27bcc43](https://github.com/hrishikeshdkakkad/fluidbox/commit/27bcc43e4eed8208cc32b82c4fb75fc45951b88c))
* **server,web,ci:** Codex round-1c — arming locks, strict PATCH, proxy strictness, acceptance tightening ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([fa72847](https://github.com/hrishikeshdkakkad/fluidbox/commit/fa7284756ccce68a60c332847c7541bd6976c0c7))
* **server,web,ci:** Codex verify 1c — lock-coherent PATCH/deactivation, audited refusals, interleaving tests ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([07058cb](https://github.com/hrishikeshdkakkad/fluidbox/commit/07058cb7903bb6d4eee20b5c4f5afc7f8d124ad7))
* **server,web:** tenant-scoped GitHub App flows; Phase C UI cutover fixes ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([8207972](https://github.com/hrishikeshdkakkad/fluidbox/commit/8207972979902347c2fb9631158d62c7233bbd5e))
* **server:** approval decide_own excludes brokered calls; strict Decision body ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([89d5762](https://github.com/hrishikeshdkakkad/fluidbox/commit/89d5762976736bf157a5ddd71743d14ddf7107e0))
* **server:** authorize the terminal MCP session DELETE ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([2dbe42b](https://github.com/hrishikeshdkakkad/fluidbox/commit/2dbe42be42780a8a459cb24ed4bc7ad9055c6a30))
* **server:** bind the CAS to the real start epoch; tighten key-rejection classification ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([6a5989f](https://github.com/hrishikeshdkakkad/fluidbox/commit/6a5989f090f2b25310a68a0e4ff0785a8d6df438))
* **server:** bindings — reject unknown explicit slots, github_app publish assert, authority-branch tests ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([40dd6e0](https://github.com/hrishikeshdkakkad/fluidbox/commit/40dd6e0a9777f5ed4f20fc32204e662b080fb613))
* **server:** CIMD arm adopts existing registration identity ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([0ab091d](https://github.com/hrishikeshdkakkad/fluidbox/commit/0ab091dd477c6696841acceac8f4625f19eee129))
* **server:** claim a deployment KEK identity before serving; sweep expired DEKs ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([7fda061](https://github.com/hrishikeshdkakkad/fluidbox/commit/7fda0617817007cb32cb89383d5407e74e4e0443))
* **server:** close the connector-OAuth SSRF pre-flight gap; admission layer + hardening asserts ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([dbdc7ed](https://github.com/hrishikeshdkakkad/fluidbox/commit/dbdc7ed1e782ca7089d3d1354ed51834170bc78d))
* **server:** Codex round-1b — artifact scoping, JWKS/claims hardening, redirect canonicalization, SSE bound ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([c6da453](https://github.com/hrishikeshdkakkad/fluidbox/commit/c6da453ae4b4e2fc93bd7320ab1f6455f61ea2a9))
* **server:** Codex verify 1b — JWKS pairing/persistence, null claims, alg canonicality, SSE bound ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([797f255](https://github.com/hrishikeshdkakkad/fluidbox/commit/797f25522b1799c07de3bd989a481777e9b3d24e))
* **server:** conservative reservation bound; no duplicate GitHub effects; fence the launch writes ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([343c80d](https://github.com/hrishikeshdkakkad/fluidbox/commit/343c80dac4a671a556be465a729d34c6f9a63974))
* **server:** final-review wave — retirement gate quadrant, registration FK + heal semantics, transit AAD purpose, tenant-key 401 recovery ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([b51cdb2](https://github.com/hrishikeshdkakkad/fluidbox/commit/b51cdb2bfbb6bcde1102745a64767e25cfd9af64))
* **server:** KMS review wave — KEK compatibility gate, DEK singleflight, bounded cache, audit fidelity ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([6950f21](https://github.com/hrishikeshdkakkad/fluidbox/commit/6950f21655e666f5c640eec08b03d3359b2a89c2))
* **server:** oauth custody commits are checked — fail closed, never cache on ambiguity ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([1b830fe](https://github.com/hrishikeshdkakkad/fluidbox/commit/1b830fead53ba37799aa2e4f9c91325267c38c69))
* **server:** oauth refresh — commit check dominates both result branches ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([d11d0bd](https://github.com/hrishikeshdkakkad/fluidbox/commit/d11d0bdcce1c4133e5ba36435658b15d0b4bb985))
* **server:** owner-role grants take the config lock; audit label + doc nits ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([cfe24d2](https://github.com/hrishikeshdkakkad/fluidbox/commit/cfe24d21048835c9e988abe52eebf9ceb43d2f20))
* **server:** per-hop SSRF client for identity fetches; JWKS negative-cache scoping ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([f5cd53e](https://github.com/hrishikeshdkakkad/fluidbox/commit/f5cd53ebef00ded992b8e6122108304e4eff76e5))
* **server:** re-stamp delivery claims per attempt; tighten Task 6 disclosures ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([a9d27de](https://github.com/hrishikeshdkakkad/fluidbox/commit/a9d27de3dddc5b4ac0ff46eafbf195403abc28ad))
* **server:** release the finalization claim when the driver lacks the lease ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([ea11853](https://github.com/hrishikeshdkakkad/fluidbox/commit/ea1185321e381c79947ae28d36d497d22a1c48ff))
* **server:** route global registration writes through the audited bypass ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([2dd59d3](https://github.com/hrishikeshdkakkad/fluidbox/commit/2dd59d3689c14b00de3740f8e94b81da0c094672))
* **server:** SSE re-auth bound holds across query awaits and backoff ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([0a4f6d2](https://github.com/hrishikeshdkakkad/fluidbox/commit/0a4f6d2e4c03a3f9b1bf03850726ddb08b5df1a9))
* **web,ci:** add-server wizard shapes; bindings-e2e coverage — ambiguity, publish binding, exact negotiation ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([24f50be](https://github.com/hrishikeshdkakkad/fluidbox/commit/24f50beada8c3c966de5e9854a52b8b9b39ed89a))
* **web,ci:** requirement owner-aware binding mode; wizard snapshot settling; e2e — signature verification, workspace consumer proof, per-photograph negotiation ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([f927641](https://github.com/hrishikeshdkakkad/fluidbox/commit/f9276419550e34d358b7686da417fc9751503444))
* **web:** extract + test proxy security helpers; bare login route; apiPatch ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([a3acc5e](https://github.com/hrishikeshdkakkad/fluidbox/commit/a3acc5e80fda72a3d7d797ba603e5d81b1eb2b1e))
* **web:** hide revoked registrations/connections; e2e leaves no live fixtures ([6b70d02](https://github.com/hrishikeshdkakkad/fluidbox/commit/6b70d0268ccac6f2908ff2a4d77a27f30d987541))
* **web:** label credentialless connections "no auth", not "api key" ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([90b20db](https://github.com/hrishikeshdkakkad/fluidbox/commit/90b20dbbd5934e9803efaabeb9b228fae8465892))
* **workers:** sweep sessions stalled before launch; allow Created→Failed ([b7d56f4](https://github.com/hrishikeshdkakkad/fluidbox/commit/b7d56f49cf753a88d9b5c6cbf44cd33fc307ec68))
* **workspace,scale-e2e:** two stale comments the whole-branch review caught ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([9019a48](https://github.com/hrishikeshdkakkad/fluidbox/commit/9019a4864abc1eb1535c625b7fe1aebaaeaebfe5))


### Changed

* **db,server:** TenantScope wave A — sessions, events, approvals, workers ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([9ad0abe](https://github.com/hrishikeshdkakkad/fluidbox/commit/9ad0abe76f669aae895757c020a53c3cc5b68e95))
* **db,server:** TenantScope wave B — agents, connections, triggers, create_run ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([6d3bff7](https://github.com/hrishikeshdkakkad/fluidbox/commit/6d3bff787de04e5bf7f4d18a47d1c31a2c9a3d11))


### Documentation

* $17 [#1](https://github.com/hrishikeshdkakkad/fluidbox/issues/1)-[#3](https://github.com/hrishikeshdkakkad/fluidbox/issues/3) recorded settled; event-spine invariant + env seams in CLAUDE.md/.env.example ([a5bb7f9](https://github.com/hrishikeshdkakkad/fluidbox/commit/a5bb7f9ec80863030860dac96a47b12b7c529ce8))
* add a full Kubernetes deployment guide ([acdb27a](https://github.com/hrishikeshdkakkad/fluidbox/commit/acdb27a8a87a7989bbfad8495dd8727aeb72c9c2))
* add root CLAUDE.md for future Claude Code instances ([81eb75d](https://github.com/hrishikeshdkakkad/fluidbox/commit/81eb75d6c554a309f83e48aff55634f3446e484e))
* CHANGELOG 0.2.0 section + EKS-acceptance handover ([3d33a2f](https://github.com/hrishikeshdkakkad/fluidbox/commit/3d33a2fcd16648f452ae3f0009a4411a93753649))
* CHANGELOG 0.2.0 section + EKS-acceptance session handover ([1c533a1](https://github.com/hrishikeshdkakkad/fluidbox/commit/1c533a1cc27df333258c6cc5541fdec8804472f3))
* **claude:** harness registry + canonical-tool-vocabulary invariant + two-image note (Phase 6) ([f1ba07e](https://github.com/hrishikeshdkakkad/fluidbox/commit/f1ba07ef09f0c55dd2b088adb76a5643ca497fb4))
* connector-catalog & OAuth-custody slice — research findings + dense session brief (user-selected next, ahead of Phase 6) ([ff4b53f](https://github.com/hrishikeshdkakkad/fluidbox/commit/ff4b53fbb6dd3041b893b0d7a213372dc8371dd9))
* correct four stale claims in the Phase E handover ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([ab484cd](https://github.com/hrishikeshdkakkad/fluidbox/commit/ab484cd39d94efcb8747b02c5159a23b93514bef))
* correct Phase D truth-pass overstatements ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([d775dcb](https://github.com/hrishikeshdkakkad/fluidbox/commit/d775dcbac76c18c5d644d0d7b664fe1b53354c5b))
* correct the gate, egress and acceptance claims to what is actually proven ([c8c61cc](https://github.com/hrishikeshdkakkad/fluidbox/commit/c8c61cc4727f7b5c0c70f58827a78b02af37452c))
* correct the scale-hang root cause in the handover ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([26ff201](https://github.com/hrishikeshdkakkad/fluidbox/commit/26ff2011a024c8fc7d172740bb851e3e0f5d351f))
* **db:** add insert_audit_standalone to the bypass inventory ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([5836e14](https://github.com/hrishikeshdkakkad/fluidbox/commit/5836e1497ee27fe0d074a3a0c8647777ebc76d31))
* **db:** the migrate! reminder was stale for four migrations ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([76760d4](https://github.com/hrishikeshdkakkad/fluidbox/commit/76760d47715dc03ba33570510b5a7f65003e0757))
* design agent workspaces and trigger integrations ([fb1f4d3](https://github.com/hrishikeshdkakkad/fluidbox/commit/fb1f4d3dd4e5d5c7ab34be020ac09beefe4e592d))
* design for the five-minute first-run demo + launch media ([4e415b6](https://github.com/hrishikeshdkakkad/fluidbox/commit/4e415b6a9c308d1d6366e9f8e252598e4bad048a))
* document the outbound rate-limit and circuit-breaker knobs ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([aa3491c](https://github.com/hrishikeshdkakkad/fluidbox/commit/aa3491c4591335774336351daf0c132adc354f22))
* drop references to the removed source-spec file ([4ec6037](https://github.com/hrishikeshdkakkad/fluidbox/commit/4ec60374cf18b165a80aa73ccf95bebae30c468c))
* **eks:** Phase-F live EKS acceptance — PASS, zero-orphan audited ([f6bf7b9](https://github.com/hrishikeshdkakkad/fluidbox/commit/f6bf7b94fc18f9b548f03df6aba497568509f9b0))
* full Kubernetes deployment guide ([c967192](https://github.com/hrishikeshdkakkad/fluidbox/commit/c96719226ad6d30194c3c1c2557e7bbda379c6b6))
* handover — 6.A hardening shipped; next is borrow-the-agent (user decision) ([67e83b8](https://github.com/hrishikeshdkakkad/fluidbox/commit/67e83b87c76446a4d1bda3c5e4578c839274bbd7))
* handover — Phase 3 (scheduled borrowing) design intent + §17 [#5](https://github.com/hrishikeshdkakkad/fluidbox/issues/5) recommendation ([1fb37e9](https://github.com/hrishikeshdkakkad/fluidbox/commit/1fb37e9e7b685783e87cc1438b20d2f343ea2631))
* handover rev 4 — design-doc Phase 2 (API triggers + signed callbacks) shipped ([0d8cd78](https://github.com/hrishikeshdkakkad/fluidbox/commit/0d8cd786d1d14be6923fe288bad1392dab525b95))
* handover rev 5 — design-doc Phase 3 (scheduled borrowing) shipped; §17 [#5](https://github.com/hrishikeshdkakkad/fluidbox/issues/5) settled defaults recorded ([95177e5](https://github.com/hrishikeshdkakkad/fluidbox/commit/95177e5799e8ab5740661250571ea6efd3df9a55))
* handover rev 6 — design-doc Phase 4 shipped (github pr-review fan-out on the connector seam) ([01a7f17](https://github.com/hrishikeshdkakkad/fluidbox/commit/01a7f17da62e2ce2c519f0fa1272aa9ab1956a96))
* **handover:** rev 10 — Codex (second harness, Phase 6) shipped ([31ebd84](https://github.com/hrishikeshdkakkad/fluidbox/commit/31ebd8498afcef2efc61b17ee5c8c376d79a3730))
* **handovers:** 2026-07-13 governance/GTM brief + 2026-07-14 codex-MCP debug session ([#53](https://github.com/hrishikeshdkakkad/fluidbox/issues/53)) ([1eaf724](https://github.com/hrishikeshdkakkad/fluidbox/commit/1eaf7241839b90f8a68b9c25dcfc5fb2f08994e3))
* **hosted:** incorporate Codex adversarial review round 1 (11 findings) ([539e818](https://github.com/hrishikeshdkakkad/fluidbox/commit/539e8188c7e04931e1975b914e48861568c9cc2d))
* **hosted:** incorporate Codex adversarial review round 2 (5 findings) ([f58cf0e](https://github.com/hrishikeshdkakkad/fluidbox/commit/f58cf0efc1c4eb7ba249d4dbf49220ce428eda49))
* **hosted:** incorporate Codex adversarial review round 3 (2 findings) ([8ff83c0](https://github.com/hrishikeshdkakkad/fluidbox/commit/8ff83c0f60bde1e475da772801e82311a05efa5e))
* **hosted:** incorporate independent fidelity review (3 findings) ([74e14c8](https://github.com/hrishikeshdkakkad/fluidbox/commit/74e14c8e596f2e6f53f699e27ff740b88b77114b))
* **hosted:** Phase A draft — hosted product boundary (matrix, admission policy, network, threat model) ([0cab245](https://github.com/hrishikeshdkakkad/fluidbox/commit/0cab24545e9822b3a09ac6478b1beaa2d5f4eb83))
* **hosted:** rollout gates with checkable exit criteria ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([ba5c6b7](https://github.com/hrishikeshdkakkad/fluidbox/commit/ba5c6b78400524540414da727f1d0f4210d91ca8))
* implementation plan for automation API contract + template clarity ([b6b6be9](https://github.com/hrishikeshdkakkad/fluidbox/commit/b6b6be9935b59e05f7aa76c01eecbb4de6a8ff6e))
* implementation plan for the five-minute demo + launch clips ([742992b](https://github.com/hrishikeshdkakkad/fluidbox/commit/742992b21eceaffc17968190484c17daddaeed96))
* independent prime-time red-team assessment (reports only) ([3faaac3](https://github.com/hrishikeshdkakkad/fluidbox/commit/3faaac3d3e2ee347299c9e1505da4cdc1e2690cb))
* **k8s:** continuance handover for the PR [#47](https://github.com/hrishikeshdkakkad/fluidbox/issues/47) fix series (batches 5-7) ([329765b](https://github.com/hrishikeshdkakkad/fluidbox/commit/329765bc179f532fa885c67ec37b7e32ba90507e))
* **k8s:** document the residual symlinked-dest hardening as a follow-up (L15) ([0e2ddc4](https://github.com/hrishikeshdkakkad/fluidbox/commit/0e2ddc4db5aef0e522192c681f05ca14d890cc11))
* live EKS acceptance for the Kubernetes-native provider (closes [#48](https://github.com/hrishikeshdkakkad/fluidbox/issues/48)) ([e8a162c](https://github.com/hrishikeshdkakkad/fluidbox/commit/e8a162c2fdd46845d91a38175fa6daf1f3e1b10e))
* mark the red-team findings superseded by this integration ([72f572d](https://github.com/hrishikeshdkakkad/fluidbox/commit/72f572d1df470010b4df7b7ad4071be2f87ea346))
* minimal hatchet-style README — link out, don't inline ([b62ed76](https://github.com/hrishikeshdkakkad/fluidbox/commit/b62ed76bad7fcd9c0e034b3c04032a332544f797))
* next-session brief for design-doc Phase 4 (GitHub PR-review fan-out) ([5fec7ba](https://github.com/hrishikeshdkakkad/fluidbox/commit/5fec7ba68c97e31dcc7e24a177263ff79ec67ae9))
* next-session brief for design-doc Phase 5 (capability & MCP catalog) ([357281e](https://github.com/hrishikeshdkakkad/fluidbox/commit/357281e2bcb2380cf1975fe58f032d89b57d0937))
* overnight integration review — four branches, independently verified ([2e57b5c](https://github.com/hrishikeshdkakkad/fluidbox/commit/2e57b5c1da112e9160efae61f1169950234a600c))
* phase 4 brief — condense paste block to &lt;=4000 chars ([8ce4902](https://github.com/hrishikeshdkakkad/fluidbox/commit/8ce4902f8c2ca027659851de222375ef0c5af42e))
* phase 4 brief — emphasize the connector seam (GitHub as first tenant of the five-duty boundary) ([4639cbd](https://github.com/hrishikeshdkakkad/fluidbox/commit/4639cbdbf8f5d215708980d4fe9f71947a0852df))
* phase 4 brief — pin the current pushed HEAD ([97b33a6](https://github.com/hrishikeshdkakkad/fluidbox/commit/97b33a6cdf48135690b774ce5afc4f40a2198f00))
* phase 4 brief — self-stable tree-state wording (code-freeze hash only) ([23851e5](https://github.com/hrishikeshdkakkad/fluidbox/commit/23851e5166010d9d23c54a1a4c09f9327ea71d07))
* phase 5 brief — add MCP-ecosystem research-first step ([5915965](https://github.com/hrishikeshdkakkad/fluidbox/commit/591596566eb421e6cf7e4e725f2745221df41e47))
* Phase 6 codex-harness design (approved) + session brief; phase 4 review record ([68bfc56](https://github.com/hrishikeshdkakkad/fluidbox/commit/68bfc56e0c6d8bab95995817a5bfda689912d0a2))
* Phase 6 live bring-up + post-ship review round (HANDOVER rev 11) ([3421257](https://github.com/hrishikeshdkakkad/fluidbox/commit/342125765dfac9aa37ff637f2f7e89fe8fd07e2a))
* Phase B shipped-surface truth pass ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([57be435](https://github.com/hrishikeshdkakkad/fluidbox/commit/57be435bf8752d3b6d8ed77e9e12be3934bf4904))
* Phase C shipped-surface truth pass ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([3b14d4c](https://github.com/hrishikeshdkakkad/fluidbox/commit/3b14d4c04d90217d0b4d7a6fff435cd5cadbf46b))
* Phase D session handover ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([634ffd6](https://github.com/hrishikeshdkakkad/fluidbox/commit/634ffd619cb16e055229a00d9d87f765fbb88ad1))
* Phase D truth pass ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([b6f832e](https://github.com/hrishikeshdkakkad/fluidbox/commit/b6f832e650888ccc08c54edf91f947854ad6d089))
* Phase E handover — CI fully green ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([246450f](https://github.com/hrishikeshdkakkad/fluidbox/commit/246450f5e9af811c2856761e22d4b3ca519b1ddd))
* Phase E handover — closeout state and corrected lessons ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([491d226](https://github.com/hrishikeshdkakkad/fluidbox/commit/491d2267fca253655c1439d984a97a42659776ea))
* Phase E truth pass + handover ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([35e8c4d](https://github.com/hrishikeshdkakkad/fluidbox/commit/35e8c4d83a9eb868147d3487ce36b6a3c41b8510))
* Phase F handover ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([71a4fc5](https://github.com/hrishikeshdkakkad/fluidbox/commit/71a4fc59e363f9ef8dd268c9bfd911c3cd9c9338))
* **plans:** identity design v2 — incorporate Codex adversarial round 1 ([336ad28](https://github.com/hrishikeshdkakkad/fluidbox/commit/336ad2884627378b1ee9ea945db22d8296277856))
* **plans:** identity design v3 — incorporate Codex adversarial round 2 ([9df9582](https://github.com/hrishikeshdkakkad/fluidbox/commit/9df9582dbac638189cf0238f143d1220901c8d2c))
* **plans:** identity design v4 — incorporate Codex adversarial round 3 ([563f1dc](https://github.com/hrishikeshdkakkad/fluidbox/commit/563f1dc3b21f7ad8082169bda698190f5b97f936))
* **plans:** identity design v5 — fix the bootstrap RETURNING defect (Codex round 4) ([15a30ed](https://github.com/hrishikeshdkakkad/fluidbox/commit/15a30edb3fc0b419529c95f210d87058a66ce7c6))
* **plans:** k8s design v1.1 — dual-provider permanence (settled Q17) ([c6ab3a5](https://github.com/hrishikeshdkakkad/fluidbox/commit/c6ab3a5d5bf161670a38812294b6f300bcd80fe3))
* **plans:** k8s design v1.2 — operator journeys + per-cloud presets incl. DOKS ([56b1565](https://github.com/hrishikeshdkakkad/fluidbox/commit/56b156521a29eb67960e358d4d6f20935b0aa5fd))
* **plans:** kubernetes-native execution provider + Helm deployability design ([65641b9](https://github.com/hrishikeshdkakkad/fluidbox/commit/65641b929f3223730772b4d1b59326c329f8c727))
* **plans:** multi-user MCP control plane design — FINALIZED v2 ([8553873](https://github.com/hrishikeshdkakkad/fluidbox/commit/85538737d9542b48b8fe854de8c3cb1615f4ec40))
* **plans:** multi-user MCP v3 — browser-bound OAuth callbacks, 4-state execution claims, missing migrations ([76acb01](https://github.com/hrishikeshdkakkad/fluidbox/commit/76acb0166da85c80e7c3a2b0d320674314699e6e))
* **plans:** multi-user v4 re-baseline + IdP-agnostic identity companion design ([9bc0a8e](https://github.com/hrishikeshdkakkad/fluidbox/commit/9bc0a8e70fee48fba7447c69caddd9159e9ae2fd))
* **plans:** public site + docs platform + WorkOS /app boundary design ([a42ea49](https://github.com/hrishikeshdkakkad/fluidbox/commit/a42ea491557cc10bdac1faf906cd83f2af71ddec))
* point next-phase handover at the user's workspaces/triggers design doc ([0b75bd8](https://github.com/hrishikeshdkakkad/fluidbox/commit/0b75bd8241575123afbc1cdcc9d1b173eea9dc6c))
* **policies:** close the live-agent gap — real run proves the governance loop ([a0342a8](https://github.com/hrishikeshdkakkad/fluidbox/commit/a0342a8a8b17de6f1a0433418e7304bbdcb7fbcd))
* **policies:** correct two errors in my own validation output ([d74755f](https://github.com/hrishikeshdkakkad/fluidbox/commit/d74755f2867b72622ba8aa557177c4b471bb3049))
* **policies:** design DB-native policies — versioned storage + structured authoring ([80c950a](https://github.com/hrishikeshdkakkad/fluidbox/commit/80c950aacdde413e501d0d333bd946417089c139))
* **policies:** prove the governance loop on Kubernetes too, and explain the EKS 503 ([a5681b6](https://github.com/hrishikeshdkakkad/fluidbox/commit/a5681b6e2cc552635296cf20cb0073a6ed91d38c))
* **policies:** route every unfixed finding to a tracking item ([69d0df6](https://github.com/hrishikeshdkakkad/fluidbox/commit/69d0df6f139e4016a149a23c144d67a3fd82bdc3))
* **policies:** run the loop on REAL EKS; correct my own EKS 503 explanation ([31702cf](https://github.com/hrishikeshdkakkad/fluidbox/commit/31702cf071c8bbf6ada8be539f15a01b717050a3))
* **policies:** two-environment validation report + correct the upgrade guidance ([0f0f662](https://github.com/hrishikeshdkakkad/fluidbox/commit/0f0f66260d7e63fd3da79a67d12cc0dd1c854cdf))
* professional open-source pass — community health files, templates, metadata ([548cacc](https://github.com/hrishikeshdkakkad/fluidbox/commit/548caccc7527156d74b5ee3a9c78d0deaf9d7d1b))
* **readme:** lead with the product film instead of a still ([881dec4](https://github.com/hrishikeshdkakkad/fluidbox/commit/881dec4a4bb22324a3a559a449dff3e26748a4f0))
* **readme:** lead with the product film instead of a still ([ec1d301](https://github.com/hrishikeshdkakkad/fluidbox/commit/ec1d301e4a58c14d900398d4df85d6b947f16ee1))
* **readme:** raise the product film above the fold ([c49c526](https://github.com/hrishikeshdkakkad/fluidbox/commit/c49c5266d4b9f8713d72d2f907b91361d84656b9))
* **readme:** raise the product film above the fold ([01ec08a](https://github.com/hrishikeshdkakkad/fluidbox/commit/01ec08a5d7ae66b8a9cf2962a73d9eb35105c298))
* record Step 5 review resolution (ACCEPT after 3 passes) ([cbb17d2](https://github.com/hrishikeshdkakkad/fluidbox/commit/cbb17d2af72715aadd2585d45ce6ba7df6e1cc22))
* record the scale job's first real execution ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([c005350](https://github.com/hrishikeshdkakkad/fluidbox/commit/c00535003785746cd466088d6b5b2f60f99f1a20))
* record whole-branch review outcome in the handover ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([fc3d231](https://github.com/hrishikeshdkakkad/fluidbox/commit/fc3d23122868d63e866679202419302a5fbd7a1b))
* reframe README around the agent control plane ([#70](https://github.com/hrishikeshdkakkad/fluidbox/issues/70)) ([046c5dc](https://github.com/hrishikeshdkakkad/fluidbox/commit/046c5dc2101a8d11e9f5a2cb2fb3ae79f85b28e7))
* **release:** claims matrix, compatibility matrix, upgrade guide, beta package ([3a4a5af](https://github.com/hrishikeshdkakkad/fluidbox/commit/3a4a5af8c1816eecff31693693f8b49ac7e92efe))
* **release:** correct the commit inventory in the readiness report ([f59a6ec](https://github.com/hrishikeshdkakkad/fluidbox/commit/f59a6ec3024eda9d26ff0aef0eab0d089897d733))
* **release:** Linux/amd64 is validated for CI-executed paths ([ae12b9e](https://github.com/hrishikeshdkakkad/fluidbox/commit/ae12b9e96e366234bcdafb2f70d74758f81ecdba))
* **release:** pin the next release to 0.4.0 and explain why ([#116](https://github.com/hrishikeshdkakkad/fluidbox/issues/116)) ([dcbe1e1](https://github.com/hrishikeshdkakkad/fluidbox/commit/dcbe1e1a6a46f74cc54910ae90710dfa5e19d425))
* **release:** v0.1.0 changelog + dashboard screenshot in the README ([07749b8](https://github.com/hrishikeshdkakkad/fluidbox/commit/07749b88327a88bbdcc62f1a401263bebea768f1))
* **review:** adversarial verification of the RC readiness report ([6545868](https://github.com/hrishikeshdkakkad/fluidbox/commit/6545868ec38e9db3e10ccd634ff7228631f63f6a))
* revise automation-contract plan per external review (rev 2) ([7db471f](https://github.com/hrishikeshdkakkad/fluidbox/commit/7db471f6314ae4df82e798e4d598d4d5ce78a5e3))
* **rls:** document the runtime-role posture gates, bypass opt-out, and audit tenant floor ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([42dffd5](https://github.com/hrishikeshdkakkad/fluidbox/commit/42dffd534df8fb00b0c04ea3d1eb8bcfb96a4375))
* scale job is green — record the fix and what it proved ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([e01e4ae](https://github.com/hrishikeshdkakkad/fluidbox/commit/e01e4ae8eccfd90e4f18198e53eefad33d96f775))
* session handover (state, running services, decisions, next steps) ([29e2bcd](https://github.com/hrishikeshdkakkad/fluidbox/commit/29e2bcd7a4baa6c3895d8e9aba74f6a74c18567b))
* spec for durable automation API contract + template clarity ([96a5224](https://github.com/hrishikeshdkakkad/fluidbox/commit/96a5224c5c4ecab9daaa8cf5a130b96d533b91c5))
* surface just demo as the no-key first-run path ([5b45838](https://github.com/hrishikeshdkakkad/fluidbox/commit/5b45838b89dc67cbe2da860466ccdb22a7f7eded))
* **threat-model:** two Phase F residuals narrowed, honestly ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([c1982d7](https://github.com/hrishikeshdkakkad/fluidbox/commit/c1982d7ef34f44448de806d25b55a8a499208c33))
* update multi-user release README ([646ac3d](https://github.com/hrishikeshdkakkad/fluidbox/commit/646ac3d419411235503d7d25c53aefa1a1269e07))
* **web:** run-composer pickers — unleak connections, one card vocabulary, working + new ([#42](https://github.com/hrishikeshdkakkad/fluidbox/issues/42)) ([a9ead8f](https://github.com/hrishikeshdkakkad/fluidbox/commit/a9ead8f187779d09e61853619b225220c5b7d812))

## [Unreleased]

## [0.4.0-rc.1] — 2026-07-30 (release candidate, not published)

**A release candidate whose headline is a security fix, and whose second headline is that the fix is now provable without spending a cent on a model.**

### Security

- **The permission gate is now enforced for EVERY tool call on the Claude harness.** It was not. `canUseTool` — the callback the runner had wired correctly the whole time — is not an interception point: the Agent SDK translates it into the Claude Code CLI's `--permission-prompt-tool`, which the CLI consults only for calls it decides to **ask** about. Anything it approved first (its read-only and safe-command classifications) executed with the callback never running and **zero** `tool.requested`/`tool.decision` events in the ledger. Measured with an unfabricatable nonce: an agent returned the SHA-256 of a value minted seconds earlier while the governing policy required a human approval that was never requested. Fixed with a mandatory, unscoped `PreToolUse` hook — upstream's own documented remedy — that answers `ask`, forcing every call back onto the existing, well-tested gate. A second layer, `GateWitness`, reconciles observed `tool_use` blocks against decisions and aborts the run (`EXIT_UNGOVERNED_TOOL`, no `/result`) if a result arrives for a call nothing decided.

  **What this changes for you:** the gate now sees tool names it never saw before. See *Upgrade notes*.

- **`scripts/gate-proof.sh` — the acceptance test this defect got past, and it costs nothing to run.** The suites that existed could not have caught it: `governance-e2e` kills the real runner and drives `/permission` itself (validates the server, structurally cannot validate the harness), and the only live-agent suite was `workflow_dispatch`-only *and* needed model credits. The new proof drives the **real** runner image and the **real** pinned CLI against a mock upstream that returns a canned `tool_use` and a mock control plane whose verdict each scenario chooses — then asserts on evidence that cannot be faked: a real filesystem side effect in the bind-mounted workspace, and, for read-only-classified commands, the digest of a freshly-minted nonce. 14 assertions including allow-path positive controls (without which every "nothing happened" result would be unfalsifiable), a held-verdict ordering proof, and five fail-closed variants. **It runs on every pull request.**

- **The eval quickstart no longer ships a working admin credential.** `FLUIDBOX_ADMIN_TOKEN` defaulted to `fluidbox-eval-only`, a literal published in this repository, while the API port was published on all interfaces and the Docker socket was mounted into the server — so any host on the same network segment had full admin authority, and from there host-file disclosure via an operator `local_copy` workspace. The token is now **required**: `docker compose up` refuses to start without one. The dashboard moved to loopback. The API port **cannot** move to loopback (sandboxes are sibling containers reaching the control plane over `host.docker.internal`, the host gateway, so a loopback publish breaks every run) — that residual is now stated in the file and in the README instead of being implied away, and `FLUIDBOX_EVAL_API_BIND` lets you pin the interface. `deploy/compose-assertions.sh` guards all of it in CI; nothing guarded the compose files before.

- **Kubernetes: the NetworkPolicy enforcement race is closed at both layers.** The certification probe sampled its two assertions once, at container start — inside the window where AWS VPC CNI `standard` mode has not yet programmed policy and **fails open**. Every retry created a fresh pod that re-entered the same window, so on the configuration `scripts/eks-cluster.yaml` prescribes the boot gate could never pass and **every `POST /v1/sessions` returned 503**. Worse, the same window applied to real sandbox pods, so an untrusted runner could execute with unrestricted egress for its first seconds. Replaced with a bounded observation protocol (poll once per second; succeed only when positive-reachable **and** negative-blocked hold in the *same* observation; fail closed at the deadline with the original exit-code contract) plus a new `netpol-gate` init container that is **first** in every sandbox pod, so the untrusted runner cannot start until the pod's **own** network is observed enforced. No fixed sleeps anywhere. Validated 12/12 on kind + Calico and 9/9 on real EKS 1.33, including reproducing the vulnerability natively before the fix.

### Added

- **`just demo` — a five-minute first run with no API key.** A deterministic replay drives the **real** control plane, the **real** policy gate, and a real sandbox container, ending in a real diff and cost report. Fully isolated from `just dev`: its own compose project, ports 19790/19791/15434, its own Postgres volume, state under `.demo/`. `just demo-down` removes everything.
- **`just gate-proof`** — the gate proof above, runnable locally.
- **23 tool names registered in the canonical vocabulary**, each with an explicit seed-policy disposition (see *Changed*).
- **DB-native policies (§17 #11)** — policies are now versioned, authorable, and attachable from the dashboard. Every edit is an immutable `policy_versions` row (author, summary, date; migration `0026`); publish/revert/clone ride optimistic concurrency (`base_version` → 409 on a moved head) and a strict parser (an unknown field is a 422, never a silently-weaker policy); history is append-only at the database level (the runtime role can only read and append). The Governance page gains a draft rule editor (ordered rules, path/shell constraints, budgets/approvals/autonomy/egress forms), version history with diff and one-click revert, New policy (clone or blank), and Delete; the run composer gains a policy select and disables autonomy when the policy forbids it. `managed_overrides` folds into ordinary head rules (verdict-preserving, property-tested); `just policy-sync` is retired — YAML survives as a boot seed and an idempotent import/export format (`POST /v1/policies`).
- **`DELETE /v1/policies/{name}`** — removes a policy and cascades its version history. Refused (409) while any agent revision names it, including historical revisions, which stay immutable. Runs are never affected: each froze its own policy snapshot.

### Changed

- **The seed policy now states an opinion about every tool the pinned CLI advertises.** A consequence of making the gate mandatory: 23 advertised tools had no rule, and an unmatched tool falls to `defaults.tool_action` — `approve`, which pauses every supervised run, and `deny` in autonomous runs. They are now grouped by what they actually do: observational tools (`EnterPlanMode`, `ExitPlanMode`, `AskUserQuestion`, `ReportFindings`, `Monitor`, `TaskGet/List/Output`, `CronList`) are **allowed**; effects that outlive the run (`CronCreate/Delete`, `ScheduleWakeup`, `PushNotification`, `SendMessage`, `TaskStop/Update`, `EnterWorktree`/`ExitWorktree`) **ask a human**; `DesignSync` is **denied** with the other egress tools.
- **Sub-execution is DENIED by the seed policy.** `Agent`, `Task`, `Workflow`, `Skill`, and `TaskCreate` start execution whose nested tool calls may never surface as top-level blocks — so they would be neither routed by the hook nor caught by the tripwire, which documents itself as a knowingly incomplete detector for exactly this case. `approve` would mean one human click authorising an unbounded, unobserved tool tree, so the seed fails closed instead. **This also removes a latent bypass:** the previous seed *allowed* `Task`, inert only because this CLI names the tool `Agent` — an allow-rule waiting for an upstream rename.
- **`just demo` fails when the run fails.** It exited **0** and printed a success-shaped receipt — including the self-refuting line *"every tool call crossed the server-side gate: 0 decisions"* — followed by a cheerful next-steps block, on a run that never completed. The watcher's deliberate "non-completed terminal state" code was being accepted as success, along with any unhandled exception in the watcher. It now prints a failure banner, names the terminal state, replaces next-steps with troubleshooting, and exits non-zero. The security receipt reports what was *measured* and says so loudly when zero decisions were recorded.
- **`just demo` and the control plane now agree on which Docker daemon they are using.** The preflight used the docker **CLI** (which honours `docker context`); the server uses bollard (which reads `DOCKER_HOST` and otherwise the default socket, and does not know contexts exist). On any machine whose active context is not the default socket, preflight passed against one daemon and the run then failed against another with `No such image`. The endpoint is now resolved once and exported, so every docker call and the server inherit the same one.
- **Seed policy files are parsed STRICTLY, and an invalid one can refuse the boot.** `policies/*.yaml` now goes through the same strict parser as the API, so an unknown key is an error rather than a silently-dropped field. The refusal is scoped to where it matters: if the policy does **not yet exist in the database**, the file is its only source and the server refuses to start (naming the file, the key, and the policy); if the policy **already exists**, its stored versions govern, the file writes nothing, and the server logs a warning and boots. Upgrading with a hand-edited policies directory: run `POST /v1/policies/validate` against each file first, or expect a startup warning.
- **`scripts/version-check.sh` can express a prerelease.** It extracted the first `X.Y.Z` from each annotated line and compared exactly, so a canonical version of `0.4.0-rc.1` yielded `0.4.0` and the guard failed on all six annotated sites — i.e. `just check` and the CI version gate failed on precisely the versions a release is supposed to be staged through. The charset now matches the SemVer gate in `release.yml`.

### Fixed

- The replay-runner test suite ran in **no** pipeline (the CI node-test glob is single-level under `images/runner-lib/`). It now runs on every PR — it covers the driver that `just demo` puts in front of every new user.
- Two gate-test mutations that fully restored the bypass passed the suite 12/12; a third, found during this pass, deleted the tripwire's only **call site** and still passed 14/14 (the assertion tested for the identifier's *presence*, which the function's own declaration satisfies). All three are closed and red-green verified.
- `.gitignore` named `.demo-bin/`, a directory the demo never creates, leaving the real `.demo/` state directory — which holds a live admin token — untracked but visible.

### Upgrade notes

- **The seed policy does not re-apply to an existing deployment.** `seed_policy_if_absent` never overwrites a stored policy, so the new rules land only on a **fresh** database. An existing deployment upgrading to this runner image will start seeing previously-invisible tool names arrive at the gate and fall to its own `defaults.tool_action`: **every supervised run will pause on ordinary agent tooling, and autonomous runs will deny it.** Before deploying, add the new rules to your policy — import `policies/default.yaml` with `POST /v1/policies` (it appends a version; byte-equal content is a no-op) or edit them on the Governance page.
- **The eval compose now requires `FLUIDBOX_ADMIN_TOKEN`.** Any script that relied on the default will fail with a message naming the fix. Generate one: `export FLUIDBOX_ADMIN_TOKEN=$(openssl rand -hex 32)`.
- Migration `0026` drops `policies.{parsed,yaml_source,managed_overrides,version}`, so this is **stop the old binary, migrate, then deploy** (the `0018` posture) and there is no binary rollback past it — a pre-0026 binary refuses to boot against a 0026 database (`migration 26 was previously applied but is missing in the resolved migrations`), so the failure is loud rather than silent.
  - **Helm, default values — no action needed.** `server.archiveStore: ""` (the default) and `values/eks.yaml` render `strategy: Recreate` with `replicas: 1`, which satisfies stop-the-old-binary by construction: the old pod is fully terminated before the new one starts, so `0026` runs only after the old binary is gone. Cost is ~30s of downtime, not a correctness risk.
  - **Helm, `server.archiveStore: "s3"` — act before upgrading.** Only that configuration (the multi-replica shape) renders `RollingUpdate`, where old and new pods coexist. **Scale the server Deployment to zero, upgrade, then scale back up.** Note there is no values knob for this: the strategy is derived from `archiveStore` alone (`values.yaml:57`), so it cannot be forced to `Recreate` for one release, and patching the Deployment does not help because the same `helm upgrade` rewrites the field. Without the scale-to-zero, surviving old replicas answer policy queries with `column "version" does not exist` (42703) until they are replaced, and their in-flight transactions can block the migration's `ACCESS EXCLUSIVE` DDL against its 5s `lock_timeout`.
- A `managed_overrides` entry naming a **wildcard** tool (e.g. `mcp__*`) is dropped with a warning rather than folded. Such an entry was unreachable — the retired engine matched overrides by exact name — and folding it into a rule would have matched the whole namespace. The API never allowed one, so this should log nothing.

### Known limitations in this candidate

Stated here rather than discovered later. Full detail in [`docs/reviews/release-candidate-readiness.md`](./docs/reviews/release-candidate-readiness.md).

- **No live-model validation was possible.** The available Anthropic key is out of credit (HTTP 400, confirmed directly and through the gateway), so no live Claude run was exercised for this candidate. The gate proof is a *stronger* witness for the security property and does not need a model, but it is **not** a substitute for "a real model completes a real task".
- **Nested sub-execution routing is untested**, which is why the seed denies it.
- **An older pinned `runner_image` on a newer server still routes nothing**, and there is no server-side detection of a terminal run with a non-empty diff and zero `tool.decision` events.
- **Supply chain unchanged:** no lockfile for either runner image, `npm install` rather than `npm ci`, no Dependabot npm entry for the runner directories, and release artifacts are unsigned with no SBOM or attested provenance.
- **The two earlier EKS acceptances predate the NetworkPolicy fix** and have not been re-run against this candidate.

## [0.3.0] — 2026-07-24

**Multi-user MCP control plane.** Six phases (A–F) and migrations `0011`→`0025` turn fluidbox from a single-admin control plane into one that can host many organizations, many users, and many separately-owned credentials without ever letting a model pick an identity. Every hosted capability is **opt-in behind a flag, and the default single-admin Docker deployment is byte-for-byte the same product** — `FLUIDBOX_REQUIRE_SSO` unset means today's behavior, unchanged.

The organizing idea: **connector definition ≠ credential-bearing connection ≠ agent connection requirement ≠ per-run resource binding.** An agent declares *what* it requires, never *whose* credential satisfies it. Run creation resolves each requirement to an explicit, frozen authority source before any model spend. The model picks tools; it can never pick an identity.

Highlights:

- **Per-organization, IdP-agnostic identity** — `FLUIDBOX_REQUIRE_SSO=1` confines the admin token to `/v1/admin/*` as break-glass and introduces three principals: Operator (admin token), User (`__Host-fbx_web` session cookie), and Pat (`fbx_pat_` bearer). Any conformant OIDC issuer is configured **per org** (issuer + client + sealed secret + claim mappings); logins are two-phase and browser-bound; sessions are server-side with idle/absolute/re-auth windows. No IdP configured ⇒ single-admin mode.
- **Tenant isolation with a database floor** — every tenant-owned `fluidbox-db` method now takes a `TenantScope` that carries its id into a `tenant_id = $n` predicate, so isolation is a *signature requirement* rather than a remember-to-filter convention. Migration `0018` adds the floor underneath: 37 tables `ENABLE`+`FORCE` row-level security keyed on a transaction-local `fluidbox.tenant_id` GUC, with `FLUIDBOX_RUNTIME_ROLE=fluidbox_runtime` splitting the pool onto a non-owner role holding enumerated per-table grants. Cross-tenant access exists only through a short, named, grep-able set of audited bypasses.
- **Connection ownership and per-run resource bindings** — brokered MCP tools moved off capability bundles onto four objects: catalog connector definition → **connection** (owns the credential, plus append-only tool snapshots) → agent-revision **`connection_requirements`** → per-run **`run_resource_bindings`** (migration `0013`), resolved to a tagged authority (`connection` | `subscription_secret` | `none`) across typed slots (`mcp` | `workspace_fetch` | `result_publish`) *before* provisioning. Connections gained personal vs. organization ownership; a personal-connection approval is decidable **only by its owner-who-invoked** — no role, admin, or operator override.
- **Versioned envelope sealing with a real key-retirement path** — migration `0014` makes every sealed column carry a `_key_version` companion: `1` is the legacy `FLUIDBOX_CREDENTIAL_KEY` format, `2` is a per-tenant DEK wrapped by a KEK (`FLUIDBOX_KMS_MODE=off|static|aws`) with AAD binding `fbx:v2:{tenant}:{table.column}` so a blob is untransplantable across tenants *or* columns. Thirteen sealed families; a resumable, CAS-guarded `POST /v1/admin/reseal` migrates v1→v2; two boot gates fail closed in both directions. Runbook: `docs/hosted/kms-operations.md`.
- **One hardened egress boundary for all control-plane traffic** — two filtering-resolver clients plus a pure `admit_url` pre-flight that blocks private/loopback/link-local/multicast/reserved and cloud-metadata address classes at every dial site (reqwest dials an IP literal without consulting a resolver, so the pre-flight is what actually stops `169.254.169.254`). Broker, delivery callbacks, and both connector-OAuth token legs ride a client that **refuses redirects outright**. Git gets its own out-of-process policy. `FLUIDBOX_EGRESS_ALLOW_CIDRS` opts specific CIDRs back in; `FLUIDBOX_EGRESS_PROXY` re-points everything, including the git subprocess, through one waypoint.
- **MCP `2025-11-25` conformance, with version drift denying the call** — upstream MCP is now a per-run session (`initialize` + `notifications/initialized` before every call, `MCP-Protocol-Version` on every request, credential re-resolved live on the terminal `DELETE`). A run's negotiated version must match its frozen surface exactly or the call is denied with a message naming the refresh endpoint. SSE is a real incremental assembler with per-event and total ceilings; `outputSchema`/`structuredContent` are preserved.
- **Frozen tool schemas enforced server-side** — arguments are validated against the schema photographed at freeze time, with the JSON Schema dialect chosen by the snapshot's protocol version (`2025-11-25` ⇒ 2020-12 per SEP-1613, otherwise draft-07). The schema is untrusted input, so it is pre-guarded (size, depth, local-`$ref`-only) before compilation; a violation makes the tool un-callable rather than being silently ignored. This inserts exactly one new stage into the permission gate and moves nothing else.
- **At-most-once brokered dispatch** — migration `0019` wraps every brokered call in a durable four-state execution claim keyed `(session, tool_call_id, input_digest)`. `failed_before_send` requires positive proof nothing was written and is the only re-claimable state; a definitive upstream response is terminal; timeouts and mid-stream failures are recorded as `ambiguous` rather than retried. Decision idempotency and execution idempotency are now distinct properties.
- **Audience-scoped sandbox credentials** — migration `0020` splits the sandbox's single bearer into four tokens (`llm` | `tool` | `control` | `workspace`), each checked as the first statement of its handler. Kubernetes ships one Secret with four keys routed per container, so the workspace init container never sees the others.
- **Replica coordination primitives** — migration `0021`: approval emission rides the deciding CAS inside one transaction (only the winner emits) with cross-replica `pg_notify` wakeups and the poll floor kept as a missed-notify backstop; sessions carry an orchestrator lease + epoch so a fenced-out driver cannot mutate lifecycle while a user's cancel stays deliberately unfenced; deliveries claim rows `FOR UPDATE SKIP LOCKED`, and the GitHub double-post window closes by reconcile-before-create on both comments and checks.
- **Durable LLM budget admission** — migration `0022` replaces best-effort budget checks with a request-keyed reservation whose primary key *is* the usage entry's external id, which is what makes a 401 replay and a late drain idempotent. Booking uses a deliberately-high upper bound; release happens only on positively-proven non-dispatch; charging requires a durable usage write before the CAS.
- **Operations** — a bounded-cardinality metrics registry at admin-gated `GET /v1/admin/metrics` (plus optional unauthenticated `FLUIDBOX_METRICS_BIND`), durable cross-replica egress governance and capacity ceilings (`0023`), cross-replica MCP session teardown (`0024`), workload identity (`0025`), S3-compatible archive storage alongside the filesystem backend, and a guarded load harness (`fluidbox-loadgen`) with its own manual `scale` CI job.

Validation: five hermetic acceptance suites green against CI-identical throwaway databases — identity **87/0**, bindings **104/0**, secrets **128/0**, hardening **274/0**, scale **18/0** = **611/0** — plus live Docker-provider tiers (demo A, Codex) and a second live EKS acceptance on arm64/Graviton with the runtime-role RLS split active and an AWS-audited zero-orphan teardown (`docs/reviews/2026-07-22-eks-acceptance-phase-f.md`).

Still deferred: the gated 60/150/300-seat load campaign and the final two rollout gates (owner approval + cost estimate) remain open on [#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34) — real spend, tracked separately from code. The hosted OAuth Connect flow also carries one documented residual: a deliberately-shared *start* URL can still route a victim's grant into the initiating connection, closed only by moving the browser-facing leg onto the dashboard origin (full write-up in `docs/hosted/threat-model.md`).

### Added

- **Identity and access** — per-org OIDC login (`/v1/auth/*`), logout, `/v1/auth/me`, PAT mint/list/revoke, org + IdP-config lifecycle and membership roles (`/v1/admin/orgs*`), break-glass owner arming, and staged issuer migration. All three token shapes (`fbx_sess_`, `fbx_web_`, `fbx_pat_`) are sha256-only at rest and scrubbed by the ledger redactor.
- **Dashboard SSO mode** — `FLUIDBOX_WEB_MODE=admin|sso` (static per deployment). In `sso` the proxy carries no admin token and forwards the session cookie plus a CSRF header on same-origin non-GETs; `apps/web/proxy.ts` redirects sessionless browsers to `/login?next=…` before first paint while authority stays in the control plane.
- **Per-tenant LLM keys** — `FLUIDBOX_LLM_KEY_MODE=tenant` (migration `0017`) mints a per-tenant LiteLLM virtual key and confines the master key to provisioning; `POST /v1/admin/orgs/{slug}/llm-key/rotate`. Requires a LiteLLM backed by its own Postgres, so local deployments stay on `shared`.
- **Connection tool snapshots** — a forced-`initialize` photograph per connection (`GET /v1/connections/{id}/tools`, `POST /v1/connections/{id}/tools/refresh`) recording the negotiated protocol version, with cursor caps fail-closed.
- **Hosted operator documentation** — `docs/hosted/`: product compatibility matrix, threat model, network architecture, connector admission policy, rollout gates, and KMS operations runbook. Plus `docs/guides/kubernetes.md`, a zero-to-certified-cluster guide with real cloud acceptance costs and gotchas.

### Changed

- **Brokered tools no longer ride capability bundles.** `capability_bundles` survives for sandbox stdio tools only; registering a `class:brokered` server is refused with a cutover error. Migration `0013` appends converted agent revisions and repoints pinned subscriptions; a revision still pinning a brokered bundle is refused at run creation. Mixed brokered+sandbox bundles drop whole, with a raise-notice.
- **Custom connector-catalog entries are tenant-scoped.** Curated and imported entries stay deployment-global; a tenant's custom entry shadows a same-slug global one. Migration `0013` backfills the single boot tenant, otherwise disabling the row.
- **Connector OAuth is a one-time, browser-bound flow.** `oauth/start` returns only a `go_url`; navigating it sets a `__Host-` flow cookie whose hash sits inside the atomic single-use claim, so a leaked authorization URL can neither complete nor burn a flow. Endpoints, resolved client, `resource`, sealed PKCE verifier, and expected generation are frozen at start and the callback exchanges against that row. Client identities are shared per `(issuer, redirect_uri)`, DCR singleflighted by advisory lock. The stateless `seal_state`/`open_state` helpers are gone.
- **`authorization_generation` bumps on reconnect of ever-activated OAuth connections**, so stale-generation bindings refuse mid-run. Rotation within a generation is unaffected, and GitHub App lifecycle never bumps.
- Multi-user boot now **refuses** a pool role that bypasses RLS (`SUPERUSER`/`BYPASSRLS`, e.g. Neon's default owner) unless `FLUIDBOX_ALLOW_RLS_BYPASS=1`; single-user only warns. `just doctor` inspects the role the server will actually run as and fails on every unbootable combination.

### Security

- Prompts still never reach the ledger, and the redactor now also scrubs every session, web-session, and PAT token shape.
- The permission gate grew exactly one stage (frozen-schema argument validation) and reordered nothing: budget → frozen-set availability → schema → trust tier → policy → approvals.
- Before any brokered secret access, binding status, `authorization_generation`, and — for personal connections — owner-membership-active are re-verified fail-closed.
- Both connector-OAuth token legs ride the no-redirect client on purpose: a 307/308 replays the request body, which would forward an authorization code plus PKCE verifier, or a refresh token, to the redirect target. A source-grep test pins this.

### Upgrading

Migration `0018` (RLS enforcement) is **stop the old binary, migrate, then deploy** — not a rolling upgrade. A pre-`0018` binary sets no tenant GUC and would therefore see zero rows, and it holds transactions across outbound HTTP that would block the migration's `ACCESS EXCLUSIVE` locks.

Do not drop `FLUIDBOX_CREDENTIAL_KEY` when enabling `FLUIDBOX_KMS_MODE`: run `POST /v1/admin/reseal` and let boot prove zero remaining v1 rows first. From the moment any v2 row exists, **the KEK is the root of custody and losing it is unrecoverable** — back it up before enabling.

## [0.2.0] — 2026-07-17

**Kubernetes-native execution provider.** Runs now execute as bare Pods in a dedicated, zero-egress sandbox namespace — additive to Docker (dual-provider permanence: Docker stays the default and fully supported). Highlights:

- **`FLUIDBOX_PROVIDER=kubernetes`** — one Pod per run (init → runner → collector), per-run Secrets with ownerRef GC, UID-preconditioned mutations, immutable workspace archives pulled by the pod, and in-pod diff collection against a pristine `.git` baseline (agent-mutated git state is never executed).
- **Helm chart on OCI** — `helm install fluidbox oci://ghcr.io/hrishikeshdkakkad/charts/fluidbox --version 0.2.0` works out of the box: chart `appVersion` is bound to the release images at package time; digest pinning (`images.*.digest`) validated at render time; per-cloud presets (`values/{eks,gke,aks,doks,kind}.yaml`); Ingress routes `/` → dashboard, `/v1` → API.
- **Verified network enforcement, fail-closed** — a boot probe (carrying the sandbox's own placement) plus `helm test` must prove the CNI enforces NetworkPolicy (+:8788 / −:8787) before any run is admitted.
- **Durable finalization** — every terminal path funnels through a persisted intent; collection happens before the terminal transition; crash-recovery re-drives interrupted finalizations; `/result` is no longer lossy. Fixes land on the Docker path too.
- **Self-healing reconciliation** — a periodic adopt-or-terminate sweep heals crash windows (orphaned pods, handle-less sessions) in ≤60 s; node loss maps to `Unknown` instead of live-forever; rolling-deploy-safe strict status parsing.
- **Streaming archives with safety ceilings** — pack/serve/download never hold the archive in RAM; `FLUIDBOX_MAX_ARCHIVE_BYTES` fails oversized runs at zero model spend (malformed caps fail boot); atomic `.partial`+rename writes; a session-state-aware TTL sweep reclaims leaks.
- **Hardening series** — all 30 findings (5 High / 10 Medium / 15 Low) from a three-round joint Claude+Codex review of the epic fixed or explicitly dispositioned (`docs/reviews/2026-07-16-pr47-k8s-review-findings.md`): symlink-safe extraction with `canonicalize` as the sole containment authority, integrity-checked exec collection with resume, dual-listener isolation (no `/internal` on the public plane under K8s), UID-guarded deletes, quiesce replay, and more.
- **New crates/images** — `fluidbox-workspace`, `fluidbox-provider-k8s`, `workspaced` (+ the `fluidbox-workspaced` image, published multi-arch from this release); kind+Calico CI tier green on fresh installs.

Still deferred: live EKS acceptance + teardown (kind+Calico is CI-proven; one managed cloud remains the epic's acceptance bar).

### Added

- **Connector-catalog bulk import (schema + tooling)** — the catalog is now import-ready without importing a single row. A `provenance` column (migration 0009) makes every entry auditable and refreshable; curated seeds carry `{"source":"fluidbox"}` and can never be clobbered by an import. A new reference-only transport, `rest_action`, lets an imported entry that has no hosted MCP endpoint to photograph show up as a browsable Store card whose **Connect is refused** (`400`, "reference-only"); `GET /v1/catalog` now derives a `connectable` flag per entry so the dashboard can badge those cards. An offline dev tool, `just catalog-import-registry` (`crates/fluidbox-catalog-import`), imports from **two Apache-2.0 sources**: the official **[MCP Registry](https://github.com/modelcontextprotocol/registry)** (primary — real MCP servers; entries with a `streamable-http` remote import **connectable today** through the existing broker/photograph path) and **[open-connector](https://github.com/oomol-lab/open-connector)** (supplement — REST-only reference cards). It pages the Registry live (or from a pinned snapshot), keeps only `active`/latest servers, merges Registry-wins on slug collision, runs the SAME poison screen as capability registration over every imported string (offenders drop their whole entry), and emits a deterministic, append-only, sorted `INSERT … ON CONFLICT` migration of untrusted **community**-tier rows — each provenance-tagged with its source + pinned snapshot/commit. The tool never runs at boot or request time and is not in the server crate graph; attribution is recorded in `NOTICE`. The actual breadth (the generated import migration) is a separate, legally-gated merge.
- **Bring your own MCP server** — a guided "Add your own server" flow on the Capabilities page: paste a URL, and a non-committing probe (`POST /v1/mcp/probe`) detects whether it needs no auth, an API key, or OAuth and previews its tools without storing anything or sending a secret; one confirm (`POST /v1/mcp/servers`) registers a `tier=custom` catalog entry and connects it in a single call, rolling the entry back if the connect fails so no orphan card survives. Bundle rows now expand to show their photographed tools.
- **Server-authoritative harness/model catalog** — `GET /v1/harnesses` is the single source of truth for the supported harness + model set; the dashboard's pickers fetch it instead of hardcoding models, and `create_agent`/`add_revision` now reject a model that doesn't belong to its harness with a clean **422** at agent-write time instead of a murky failure at the first model call.
- **CI now tells the truth** — the rust job runs against a real Postgres service (the DB tests no longer silently self-skip), an `e2e` job builds both runner images and runs the full no-model acceptance suite (closes the vacuous-green gap of #14), and `cargo deny check` (advisories/licenses/bans/sources, `deny.toml`) gates the supply chain. The `e2e` job is **manual-only** (`workflow_dispatch`) — it costs real Actions minutes, so it never runs on a PR or push; the cheap gates (rust/web/deny) still run on every PR. Live model tiers stay local/manual — CI never spends credits. Coverage (lcov artifact) runs on main pushes.
- **Property tests for the policy engine** — generated-input invariants in `fluidbox-core`: an autonomous run can never surface `RequireApproval`, autonomy rewrites exactly the approval verdicts (original always ledgered), the read-only tier denies any shell metacharacter and any unlisted tool, shell prefixes are token-bounded, first match wins.
- **Try-it-with-Docker distribution** — `deploy/server.Dockerfile` + `deploy/web.Dockerfile` (Next standalone output), a `release` workflow publishing multi-arch images to GHCR on version tags or manual dispatch, and `deploy/docker-compose.eval.yml`: bundled Postgres + LiteLLM + server + dashboard in one `docker compose up`.
- **User guides** (`docs/guides/`) — writing policies, triggers/schedules/signed results (with the HMAC verification recipe and a pinned test vector), and capabilities (sandbox vs brokered MCP tools, pinning, the connector catalog).
- **`ROADMAP.md`** — the public distillation of `PLAN.md` §7.

- **`just setup`** — one-command idempotent bootstrap for a fresh clone: tools check, `.env` with generated secrets (`FLUIDBOX_ADMIN_TOKEN`, `FLUIDBOX_CREDENTIAL_KEY`, `LITELLM_MASTER_KEY`), dashboard env (`apps/web/.env.local`) kept in sync, `pnpm install`, and the sandbox runner image build. Only fills placeholders — never overwrites values you set.
- **`just doctor`** — environment preflight (#13): validates every documented gotcha (pooled vs direct `DATABASE_URL`, loopback `FLUIDBOX_BIND`, credential key shape, missing runner images, dashboard token drift, missing web deps) and prints the exact fix per failure; exits non-zero only on hard failures, never echoes secret values.

### Changed

- `just neon-setup` now writes the DIRECT connection string into `.env` when `DATABASE_URL` is still the placeholder (an existing value is never clobbered).
- README quickstart, CONTRIBUTING dev setup, and the dashboard README (`apps/web/README.md`) rewritten around the `just setup` → `just neon-setup` → `just dev` flow.

## [0.1.0] — 2026-07-12

The first tagged release: the complete governed vertical slice, verified by a 10-phase live-inclusive acceptance suite (468 checks).

### Highlights

- **Governed agent runs end to end** — frozen RunSpecs, fresh sandboxes, live timelines, policy-gated tool calls with human approvals, and a diff + cost report per run.
- **Two harnesses behind one contract** — Claude Agent SDK and Codex, with an in-server LLM facade that meters usage and keeps provider keys out of every sandbox.
- **Borrow the agent, on demand** — API triggers, signed webhooks, cron schedules, and GitHub PR fan-out, all converging on one governed run path.

### Added

- **Governed runs end to end** — versioned agent definitions, immutable per-run `RunSpec` snapshots (model, prompts, policy, capability pins), fresh Docker sandboxes per run, live SSE event timelines with `Last-Event-ID` resume, and a final diff + cost report.
- **Policy engine & human approvals** — YAML policies evaluated on every tool call (allow / deny / require-approval), idempotent restart-safe approvals with expiry, and an autonomous mode that rewrites approval verdicts to a policy fallback while recording both verdicts.
- **Append-only audit ledger** — redaction enforced at the type level; prompts never reach the database, only digests, usage, cost, and decisions, with gapless per-session sequencing.
- **Two agent harnesses** — Claude Agent SDK and Codex runner images behind one HTTP runner contract; the LLM facade speaks both the Anthropic Messages and OpenAI Responses dialects.
- **Credential inversion** — the sandbox's `ANTHROPIC_API_KEY` is a session token; an in-server LLM facade validates it, enforces budget stops, meters streamed usage, and swaps in the real upstream credential held only by the LiteLLM gateway.
- **Git workspaces** — credentialed fetch/copy happens control-plane-side before the agent starts; sandboxes only ever see a bind-mounted copy and stay egress-free.
- **Triggers** — subscription-scoped API tokens, signed webhook ingress with two-level dedup that heals partial fan-outs, cron schedules with exactly-once firing and explicit missed-run/concurrency policies, and HMAC-signed result delivery with retry/backoff.
- **GitHub integration** — seamless GitHub App connect (manifest + install flows), PR fan-out with one stable comment per PR and one check per head SHA, and fork PRs frozen to `ReadOnly` trust with no approval escape.
- **Capability catalog** — append-only versioned MCP tool bundles pinned at run creation; sandbox tools run as contained stdio subprocesses while brokered tools execute on the control plane with sealed credentials the sandbox never sees.
- **Connector catalog + OAuth** — catalog-driven connect flows with PKCE (S256), RFC 8707 resource indicators, DCR/CIMD client identity, sealed refresh tokens with atomic rotation, and fail-closed error states.
- **Dashboard** — Next.js UI (Runs, Agents, Integrations, Automations, Settings); presentation-only, all logic in the Rust API.
- **CLI** — `fluidbox run --repo … --task …` to drive runs from the terminal.
- **Ops** — `just` recipes for the full dev loop, an end-to-end acceptance suite (`just e2e`), Neon setup and DB-cleanup scripts, and CI (fmt, clippy `-D warnings`, tests, dashboard build).

### Changed

- Dependency refresh: `sha2` 0.11, `hmac` 0.13, `chacha20poly1305` 0.11, `jsonwebtoken` 10 (pinned to the pure-Rust `rust_crypto` provider), React 19.2.7, TypeScript 6, and current GitHub Actions. The sealed-credential wire format (`nonce ‖ ciphertext`) is unchanged — existing sealed credentials open fine.
