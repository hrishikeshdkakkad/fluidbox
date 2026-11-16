# Changelog

All notable, user-visible changes to fluidbox are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org).

## [0.8.0](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.7.0...v0.8.0) (2026-08-15)


### Added

* **web:** six-section IA — real activity/resources routes, derived breadcrumbs, focus ([4fe2da6](https://github.com/hrishikeshdkakkad/fluidbox/commit/4fe2da639cfdcd097aecb1c3ceb5316dfbb48755))
* **web:** the delight pass — activity workbench, warm kernel, real tables ([35f4a47](https://github.com/hrishikeshdkakkad/fluidbox/commit/35f4a475d8e7266298a9bf979a8cf741b4f3324f))
* **web:** the delight pass — activity workbench, warm kernel, real tables ([f1100e9](https://github.com/hrishikeshdkakkad/fluidbox/commit/f1100e98f5fa44810df096ce75bf68f896fc7994))
* **web:** the public/private boundary — one product, chrome that knows you ([76cd91d](https://github.com/hrishikeshdkakkad/fluidbox/commit/76cd91dfc6e39fb9d964f8c1b4dfe1445ccb8671))


### Fixed

* **web,login:** confirm destructive revokes, give the sign-in refusal a way back ([c23ac36](https://github.com/hrishikeshdkakkad/fluidbox/commit/c23ac368ebdd83112ceaeb07b6b7539c53095d8d))
* **web:** gate the design scales and fix four user-visible defects ([3fce2ec](https://github.com/hrishikeshdkakkad/fluidbox/commit/3fce2ec3d9dbba46a0128546e49ce6fcb8739e98))
* **web:** gate the design scales, fix four user-visible defects, and close three high-severity findings ([c28a176](https://github.com/hrishikeshdkakkad/fluidbox/commit/c28a17646d017d9a4724041d6a6c27a091d7d61a))
* **web:** restore the run primary and stop the email overlapping the toggle ([60c1d63](https://github.com/hrishikeshdkakkad/fluidbox/commit/60c1d636448ae74419fdad529a2cf05dea4f740a))


### Changed

* **web:** fold the 47 duplicate selectors, ratchet the CSS gate 59 -&gt; 10 ([1d05170](https://github.com/hrishikeshdkakkad/fluidbox/commit/1d051700fc7740d270fcf56acd3f73527656915d))
* **web:** retire 239 of the 298 gated CSS warnings, ratchet 298 -&gt; 59 ([1bc2bc2](https://github.com/hrishikeshdkakkad/fluidbox/commit/1bc2bc216ac0001bd9c5a8a56aea4ca32d613fc2))

## [0.7.0](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.6.0...v0.7.0) (2026-08-13)


### Added

* **db:** backfill the default policy into every tenant (0030) ([44537bb](https://github.com/hrishikeshdkakkad/fluidbox/commit/44537bb52d9eeab491b6bb40127728fa5ea6d67c))
* **db:** backfill tiered policies into existing tenants (0029) ([91eb5e8](https://github.com/hrishikeshdkakkad/fluidbox/commit/91eb5e87f0dd2b72d6bb190e877ea1fda53ae095))
* **policy:** add open, standard, and governed seed policy tiers ([7a2d47b](https://github.com/hrishikeshdkakkad/fluidbox/commit/7a2d47b71c682270725bc2a6683e760708941beb))
* **policy:** rename the open tier to unrestricted (0031) ([262b34e](https://github.com/hrishikeshdkakkad/fluidbox/commit/262b34ece095ce41390f4720841ad866022e68ca))
* **policy:** tiered seed policies — unrestricted / standard / governed ([19a2774](https://github.com/hrishikeshdkakkad/fluidbox/commit/19a2774e0139ab06d61b10ca9acc66ccb3c8bf00))
* **web:** make an agent's declared egress visible, and declarable at creation ([81b9980](https://github.com/hrishikeshdkakkad/fluidbox/commit/81b9980aee482b398e6916a97e4cbdfe23d5e73c))
* **web:** make an agent's declared egress visible, and declarable at creation ([058da50](https://github.com/hrishikeshdkakkad/fluidbox/commit/058da50930f14e063d775081e5ee99c84c0e0a83))


### Fixed

* **cloud,web:** cold-start enforcement deadline + collapse the grant card on Overview ([9f3359e](https://github.com/hrishikeshdkakkad/fluidbox/commit/9f3359e3b64c9442bb0f82ea294f382de0a06e00))
* **cloud,web:** cold-start enforcement deadline + E2E scenario matrix evidence ([6a5fbbf](https://github.com/hrishikeshdkakkad/fluidbox/commit/6a5fbbf87ea4216b501c649a5c71fa5dd93a5964))
* **doctor:** repair the RLS check, which could never pass ([332d01e](https://github.com/hrishikeshdkakkad/fluidbox/commit/332d01e69cf462c9d820103c7a971c96517ea094))
* **doctor:** repair the RLS check, which could never pass ([23348bb](https://github.com/hrishikeshdkakkad/fluidbox/commit/23348bb9bfa83d053275b238b2e620a0d47871ba))
* **orgs:** seed default and tiered policies when an org is created ([15402f6](https://github.com/hrishikeshdkakkad/fluidbox/commit/15402f61af4a034587a40c91c464637846379be9))
* **policy:** close the governed shell hole and three review findings ([cf21ddd](https://github.com/hrishikeshdkakkad/fluidbox/commit/cf21dddfd595cdbf562ae251ea8c88a27ddc4bcc))
* **web:** close the network-grant UI review findings ([c704cea](https://github.com/hrishikeshdkakkad/fluidbox/commit/c704cea30009251b19c0ce0e75d63b57061e2516))
* **web:** close the network-grant UI review findings ([e36887f](https://github.com/hrishikeshdkakkad/fluidbox/commit/e36887f2c9603670a9daa2b8fecdc10032ab4255))


### Documentation

* **cloud:** cold-start regression test confirms the netpol deadline fix ([95355f0](https://github.com/hrishikeshdkakkad/fluidbox/commit/95355f0a3e80169314ac62edf7c8a3ef0c3dccb5))
* **cloud:** live acceptance — a granted run reaches the internet ([37e455d](https://github.com/hrishikeshdkakkad/fluidbox/commit/37e455d83f8dbf5a82b0f0e24f64fda4d16d964c))
* **cloud:** network-grant UI live acceptance evidence ([d8f5618](https://github.com/hrishikeshdkakkad/fluidbox/commit/d8f56186206c66d7b244ae07318b07021aff8398))

## [Unreleased]

### Changed

- **The web surface — marketing site, docs, and dashboard — is rebranded to a kernel.sh-inspired design language.** Warm beige canvas with charcoal dark passages (the dashboard's dark theme becomes the charcoal variant, and light is now the default), Inter + IBM Plex Mono replacing Geist, ultra-light lowercase chrome type with positive letter-spacing, hairline borders instead of shadows, and a single chartreuse accent that floods interactive surfaces on hover. Presentation only: no API, route, or behavior changes, and code/user content keep their original case. `apps/web/app/kernel.css` replaces `geist.css` as the dashboard skin layer.

## [0.6.0](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.5.1...v0.6.0) (2026-08-05)


### Added

* **api:** report the resolved network enforcer so the dashboard cannot offer what it cannot enforce ([b241fde](https://github.com/hrishikeshdkakkad/fluidbox/commit/b241fded3116c4cd196e37111609d42b32bfbfc8))
* **cloud:** turn on governed network access — chart 0.5.1 + the Cilium enforcer ([51624bf](https://github.com/hrishikeshdkakkad/fluidbox/commit/51624bf13f3a98130baf3ef1ee1c03fb1ebfdeb6))
* network-grant dashboard UI — govern sandbox egress from the dashboard ([9ff948e](https://github.com/hrishikeshdkakkad/fluidbox/commit/9ff948ea0d9145961baceb11a50f000296a65f13))
* **web:** authorize a parked network grant from the timeline ([ca0ecbd](https://github.com/hrishikeshdkakkad/fluidbox/commit/ca0ecbdbd3c51417f03ef07ce8c475008116964d))
* **web:** declare an agent's network needs on a revision ([c76b1ca](https://github.com/hrishikeshdkakkad/fluidbox/commit/c76b1ca313823dd5fb937754879ebec4b21f8c91))
* **web:** edit the sandbox egress ceiling in Governance ([a09fc7a](https://github.com/hrishikeshdkakkad/fluidbox/commit/a09fc7a92e83ceed384c2f7d1fc483248484b266))
* **web:** narrow a single run to offline from the composer ([22167d9](https://github.com/hrishikeshdkakkad/fluidbox/commit/22167d9797048d42b5a0e60cba3dc4aab7ef3c72))
* **web:** shared target editor for network grant rules ([4358389](https://github.com/hrishikeshdkakkad/fluidbox/commit/4358389b249fb2f3014e3207f77bfb0d6cbf4fb4))
* **web:** type mirrors and presentation helpers for network grants ([a4b085f](https://github.com/hrishikeshdkakkad/fluidbox/commit/a4b085f6eb6140cdaace8db02aa5db67a075d049))


### Fixed

* **web,api:** review fixes — preserve the allow catalog across ceiling switches, never fabricate a declaration, persist and reset the run narrowing choice, pin enforcer delegation ([4f455ab](https://github.com/hrishikeshdkakkad/fluidbox/commit/4f455ab9e318eade633bf2e23f234dccab8de4b6))


### Documentation

* **cloud:** record the Cilium cutover, its two upstream bugs, and the last mile ([7ba2e1b](https://github.com/hrishikeshdkakkad/fluidbox/commit/7ba2e1b47054919c2926924a5a483ed50b44b557))
* **plan:** implementation plan for the network-grant dashboard UI ([aa11c8a](https://github.com/hrishikeshdkakkad/fluidbox/commit/aa11c8a5e30292669570b2fe3fb6450e5b1d239d))
* **spec:** governed sandbox egress, selectable in the dashboard ([094ad5c](https://github.com/hrishikeshdkakkad/fluidbox/commit/094ad5cbbeeb099396b9b3aee6ad7c67408e361a))

## [0.5.1](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.5.0...v0.5.1) (2026-08-04)


### Fixed

* **chart:** the controlled resolver could not exec — grant it NET_BIND_SERVICE ([4db76f3](https://github.com/hrishikeshdkakkad/fluidbox/commit/4db76f342cd95bf0216e8d7a34e86198a401c075))
* **chart:** the controlled resolver could not exec — grant it NET_BIND_SERVICE ([e759e67](https://github.com/hrishikeshdkakkad/fluidbox/commit/e759e67188b05de3cb14d35f88b1a4faef562f7b))
* **network:** a CAS answers "did I win", never "is there work left" ([f540232](https://github.com/hrishikeshdkakkad/fluidbox/commit/f54023291b60d068dac270a10bfc5d3afdbc3976))
* **network:** a CAS loser must distinguish "someone else won" from "resolved away" ([bd397b2](https://github.com/hrishikeshdkakkad/fluidbox/commit/bd397b261c10eca4feebcee1d78c955223dac565))
* **network:** a DNS deny Cilium cannot express, plus the third review's blockers ([c1961df](https://github.com/hrishikeshdkakkad/fluidbox/commit/c1961df91aa9857556fc936a6edc5555e2ed3b7b))
* **network:** close the review's blocking findings ([f2b4638](https://github.com/hrishikeshdkakkad/fluidbox/commit/f2b4638fcb89bec8624e52dc66ef3c586bca3c7d))
* **network:** close the second review's blockers, including a race my own fix added ([ab46c93](https://github.com/hrishikeshdkakkad/fluidbox/commit/ab46c931463d6037069f12b62df9f0762e9c9ee7))
* **network:** disambiguate legacy deny snapshots, and reconcile live grants ([581d3a9](https://github.com/hrishikeshdkakkad/fluidbox/commit/581d3a906d7210c40f295a5fe8d4a5fdd6fcae34))
* **network:** fail closed at the renderer, and align adoption with ownership ([de79066](https://github.com/hrishikeshdkakkad/fluidbox/commit/de790660d50e3d19cd29edc7c8c4afbbc25471ef))
* **network:** reconcile from the datapath, and bound the schema in both directions ([02f99b5](https://github.com/hrishikeshdkakkad/fluidbox/commit/02f99b5bce515237923884b739cc1620a88dd429))
* **network:** scope DNS lookups to the grant, align the deny wall, correct the order ([3592145](https://github.com/hrishikeshdkakkad/fluidbox/commit/35921457b0b1848f74be46f1c9180857e45f0930))
* **network:** ten security fixes for governed network access (nine review rounds) ([6967280](https://github.com/hrishikeshdkakkad/fluidbox/commit/6967280e62f82a3883d236c8a76ef9ffda11078d))

## [0.5.0](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.4.0...v0.5.0) (2026-08-04)


### Added

* **core:** bounded denied-flow observation + EKS acceptance runbook ([54232f2](https://github.com/hrishikeshdkakkad/fluidbox/commit/54232f2706be4cfd575d5bf3b3595bf9589ef641))
* **core:** network grant domain, authorization pause, Cilium spike findings ([afb4082](https://github.com/hrishikeshdkakkad/fluidbox/commit/afb4082288492347bc2488193c868445e0692a9f))
* Enterprise Recipes — versioned templates that stamp governed automations ([c0cbbf8](https://github.com/hrishikeshdkakkad/fluidbox/commit/c0cbbf8467115371379a2c4fdb4942ad26ff8271))
* governed sandbox network access ([7affc62](https://github.com/hrishikeshdkakkad/fluidbox/commit/7affc6245e17d3b68dad2f6cff6a1c54cb92c8bd))
* **k8s:** actually program the per-run network policy at provision ([962347e](https://github.com/hrishikeshdkakkad/fluidbox/commit/962347ea6fa42d4c764c1668124be7a07881e89c))
* **k8s:** Cilium enforcer + verify() at provision ([be8021f](https://github.com/hrishikeshdkakkad/fluidbox/commit/be8021fa032a4d7f49db45c7b00e4af2d16cdc63))
* **k8s:** Cilium provider seam, per-run policy lowering, chart-static wall ([f06af1b](https://github.com/hrishikeshdkakkad/fluidbox/commit/f06af1bb5fb05d64ec805e62088aa71a854ab65a))
* **k8s:** implement the Cilium enforcer and invoke verify() at provision ([b4a0b0f](https://github.com/hrishikeshdkakkad/fluidbox/commit/b4a0b0f2a0b6672e5c2c74549b863f0414f45f0b))
* **server:** resolve, park, and revoke sandbox network grants ([c3438f3](https://github.com/hrishikeshdkakkad/fluidbox/commit/c3438f3b276a6cd55053f2ba7a87c4096e3e16c1))


### Documentation

* network-grant runbook, design doc, threat-model residuals, claim fixes ([51e97ca](https://github.com/hrishikeshdkakkad/fluidbox/commit/51e97caa1f93422116e36f96662f292384996176))

## [0.4.0](https://github.com/hrishikeshdkakkad/fluidbox/compare/v0.4.0-rc.1...v0.4.0) (2026-07-31)


### ⚠ BREAKING CHANGES

* **policies:** fold managed overrides into head rules in the engine

### Added

* audience-scoped sandbox credentials — llm/tool/control/workspace split ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([436d202](https://github.com/hrishikeshdkakkad/fluidbox/commit/436d202e1318f65048751f67b3117a77fe04c5d4))
* bring your own MCP server, intuitively + authoritative harness/model ([#24](https://github.com/hrishikeshdkakkad/fluidbox/issues/24)) ([f1a05a0](https://github.com/hrishikeshdkakkad/fluidbox/commit/f1a05a043a592febb7364fbe6e63fdbcaa1bb764))
* **broker,db:** tear down upstream MCP sessions from any replica ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([357c024](https://github.com/hrishikeshdkakkad/fluidbox/commit/357c024638c0f8cbe7284b736415f4898d41a4fd))
* **capabilities:** design-doc Phase 5 — capability & MCP catalog ([f6cac41](https://github.com/hrishikeshdkakkad/fluidbox/commit/f6cac41856f3742acfc408a07d69431cd45b5e58))
* **catalog:** connector-catalog bulk import — MCP Registry (primary) + open-connector (supplement) ([#25](https://github.com/hrishikeshdkakkad/fluidbox/issues/25)) ([27f0810](https://github.com/hrishikeshdkakkad/fluidbox/commit/27f0810e2a40174c397fc3073eb0e238074d79bd))
* **catalog:** decorate entries with live connection/bundle state; connected cards get Disconnect/Reconnect ([2e88277](https://github.com/hrishikeshdkakkad/fluidbox/commit/2e88277ad7629141396345d6552549c8725007e0))
* **chart:** archive object store and replica declaration ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([1b2f8e7](https://github.com/hrishikeshdkakkad/fluidbox/commit/1b2f8e712896c4d3f0fddc19789e7eab3a7f1181))
* **ci,dx:** non-vacuous CI, supply-chain gate, GHCR distribution, user guides, policy proptests ([#22](https://github.com/hrishikeshdkakkad/fluidbox/issues/22)) ([23e2594](https://github.com/hrishikeshdkakkad/fluidbox/commit/23e25948ace6eaa5bc55c8643516597ceedd8e41))
* **ci:** prove the permission gate with no model spend, and gate it on every PR ([59d1a89](https://github.com/hrishikeshdkakkad/fluidbox/commit/59d1a893d1f54ecc5da9d3b1d28f41783bce2554))
* **ci:** secrets acceptance matrix — KMS, invariant 20, virtual keys, RLS ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32),[#75](https://github.com/hrishikeshdkakkad/fluidbox/issues/75)) ([252fea1](https://github.com/hrishikeshdkakkad/fluidbox/commit/252fea155dc2e71735ae9cdec2cf0666b73af3cf))
* **codex:** codex-runner image + app-server supervisor; facade strips server tools (Phase 6 step 6) ([942fb56](https://github.com/hrishikeshdkakkad/fluidbox/commit/942fb5644104a808ec31cdb682a7d046eaea62fe))
* **connectors:** Phase 5.5 — connector catalog & OAuth credential custody ([a388707](https://github.com/hrishikeshdkakkad/fluidbox/commit/a38870709526857f38c4609d9b27b0647551fd9c))
* **core,server:** frozen-schema argument enforcement at the gate ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([f1d22da](https://github.com/hrishikeshdkakkad/fluidbox/commit/f1d22da97ec9a387cb70f061c2af7260ac098eb6))
* **core:** connection requirements + run-binding fields on RunSpec ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([7f1017d](https://github.com/hrishikeshdkakkad/fluidbox/commit/7f1017d05bf238325fddd7cc19e29b7618fc6b3d))
* **core:** event invocation context + github result destinations + TrustTier::as_str ([c82a12a](https://github.com/hrishikeshdkakkad/fluidbox/commit/c82a12aedbd2d00e0d2e66d93f1104b3b4c94ea7))
* **core:** read-only trust tier classifier (fork events review, never write) ([02e3525](https://github.com/hrishikeshdkakkad/fluidbox/commit/02e352544f07106a52f6887ab81a4aa96259ec64))
* **db,server,chart:** remove the ceilings that made 300 concurrent runs impossible ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([8bb654a](https://github.com/hrishikeshdkakkad/fluidbox/commit/8bb654af69c0c981fd45622b2fbc8c227d8337c3))
* **db:** 0013 appendix — legacy brokered bundles to connection requirements, subscriptions repointed ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([af2d267](https://github.com/hrishikeshdkakkad/fluidbox/commit/af2d26796326fd9dc20a4ee407878650e5c19b86))
* **db:** atomic subscription+schedule update with stale guard ([9d937dd](https://github.com/hrishikeshdkakkad/fluidbox/commit/9d937ddfb0a55f9247b6ef2e2b688e207c63f7bf))
* **db:** event delivery/dispatch/external-result tables + trust-tier & dispatch binding (migration 0005) ([dca1f5b](https://github.com/hrishikeshdkakkad/fluidbox/commit/dca1f5ba0968a7f76b5c84c0de71b641e0111f8e))
* **db:** identity layer — migration 0012, TenantScope, identity repositories ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([4d308e9](https://github.com/hrishikeshdkakkad/fluidbox/commit/4d308e90e759b51c36f7396a059a29f33fa63fe5))
* **db:** migration 0013 — connection ownership, tool snapshots, run resource bindings ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([0f00c0b](https://github.com/hrishikeshdkakkad/fluidbox/commit/0f00c0b9d7fc4144a30edccab36856438d8a5468))
* **db:** RLS policies + tenant GUC plumbing, wave A ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32),[#75](https://github.com/hrishikeshdkakkad/fluidbox/issues/75)) ([f291ed4](https://github.com/hrishikeshdkakkad/fluidbox/commit/f291ed443263d4175f13ded3db1ed4fa2dc93075))
* **db:** RLS wave B — identity + audited system_worker bypass ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32),[#75](https://github.com/hrishikeshdkakkad/fluidbox/issues/75)) ([5383d32](https://github.com/hrishikeshdkakkad/fluidbox/commit/5383d323c0ad5dec2466d7523d65cc8d234a477b))
* **demo:** fixture repo + demo compose ([083be71](https://github.com/hrishikeshdkakkad/fluidbox/commit/083be71e8cdedda0c0f14d6d24164a6cd39de9ee))
* **demo:** just demo — five-minute no-key first-run + validation drills ([9676120](https://github.com/hrishikeshdkakkad/fluidbox/commit/967612013575edf698fc6f8bfdec8bcd7d2880a0))
* **dev:** local Postgres container replaces Neon for local development ([7e5896d](https://github.com/hrishikeshdkakkad/fluidbox/commit/7e5896de66cdaa5fa709657e010ccd190311b79a))
* **docs,web:** public /docs platform — relocated engine, search, new guides ([f3ce7cd](https://github.com/hrishikeshdkakkad/fluidbox/commit/f3ce7cd77a0a5b67dc2804e1d5ba44a8ff08243d))
* **docs,web:** repo docs tree + in-app /developer docs engine ([2a18ea7](https://github.com/hrishikeshdkakkad/fluidbox/commit/2a18ea7c3bf3ce7a887acefe968c4c43891c769c))
* durable automation API contract, PATCH /v1/triggers/{id}, self-explanatory template box ([84b3cd6](https://github.com/hrishikeshdkakkad/fluidbox/commit/84b3cd634473e8144ce2a2161713191744f19469))
* **dx:** one-command bootstrap (just setup) + environment preflight (just doctor) ([6cbe82c](https://github.com/hrishikeshdkakkad/fluidbox/commit/6cbe82c4b58fdc2d1c922be1bace32256dfaae71))
* **dx:** one-command bootstrap (just setup) + environment preflight (just doctor) ([f5e8a2a](https://github.com/hrishikeshdkakkad/fluidbox/commit/f5e8a2a228021630e219e0b586a25ba08bb3d62f))
* **e2e:** codex phase 10 (protocol replay + no-model probes + live tier) + deploy wiring (Phase 6 step 8) ([8197dc5](https://github.com/hrishikeshdkakkad/fluidbox/commit/8197dc5b4441886b9685325db2cbcacc4b0d0923))
* **facade+gate:** second dialect enforcement boundary, OpenAI metering, intent-based tool budget, approval digest binding (Phase 6 step 4) ([fa862b8](https://github.com/hrishikeshdkakkad/fluidbox/commit/fa862b8055c1a2e048de4c965b3352fd4aea960f))
* **github:** expose updated_at/pushed_at in the repo picker projection ([f8c695a](https://github.com/hrishikeshdkakkad/fluidbox/commit/f8c695acbc071597b4f4136fd76b2012d32dbfa3))
* **github:** Phase 5.6 — seamless GitHub connect via App manifest + install dances ([62eda60](https://github.com/hrishikeshdkakkad/fluidbox/commit/62eda60d29da368667d6c93cf10fa3a9bfff1273))
* **governance:** the Governance page — per-tool permissions matrix + managed overrides ([#36](https://github.com/hrishikeshdkakkad/fluidbox/issues/36)) ([fc9e68c](https://github.com/hrishikeshdkakkad/fluidbox/commit/fc9e68c6002acf2cb6dd1aab7deab8bf38b3844d))
* **governor,db:** cross-replica egress governance — durable rate windows + breaker ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([810ed14](https://github.com/hrishikeshdkakkad/fluidbox/commit/810ed14cd406a63d6c10649720eb6b025883563f))
* **harness:** server-side harness registry; per-harness API defaults; orchestrator env seam (Phase 6 steps 1-3) ([8e0f969](https://github.com/hrishikeshdkakkad/fluidbox/commit/8e0f96980dd1e10dff1f6a86b22e18cf10247dd8))
* **k8s:** Phase 0 — provider seam + collection hardening (Docker-only) ([#49](https://github.com/hrishikeshdkakkad/fluidbox/issues/49)) ([ae26a73](https://github.com/hrishikeshdkakkad/fluidbox/commit/ae26a7373805e91504f4ea8cdd1add0f473302b7))
* **k8s:** Phase 1 — KubernetesProvider + workspaced collector + dual listener ([#50](https://github.com/hrishikeshdkakkad/fluidbox/issues/50)) ([05b5d41](https://github.com/hrishikeshdkakkad/fluidbox/commit/05b5d41bed9102fbca0d110c486811813453bb27))
* **k8s:** Phase 2 — Helm chart + verified network hardening + per-cloud presets ([#51](https://github.com/hrishikeshdkakkad/fluidbox/issues/51)) ([9c2c174](https://github.com/hrishikeshdkakkad/fluidbox/commit/9c2c174103c23968e127ddb91e719501dbd4e3c2))
* **k8s:** Phase 3 — CI + provider conformance ([#52](https://github.com/hrishikeshdkakkad/fluidbox/issues/52)) ([25e7ea6](https://github.com/hrishikeshdkakkad/fluidbox/commit/25e7ea6e5d8a2b29039037f95f8681fb9663548d))
* **phase-f:** review gate fixes + operational metrics ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([5fceba1](https://github.com/hrishikeshdkakkad/fluidbox/commit/5fceba1fae66a7e309773cc328af585300695046))
* **policies:** append-only policy_versions — migration 0026 + storage ([6e4b1d9](https://github.com/hrishikeshdkakkad/fluidbox/commit/6e4b1d99f3e830a47967c6c09cc19ee2faf92988))
* **policies:** review hardening — CAS publishes, strict drafts, enforced append-only ([3e8b5fe](https://github.com/hrishikeshdkakkad/fluidbox/commit/3e8b5fe5e65a14a5aec358acb603a9b9b1827b72))
* **policies:** DB-native policies — versioned storage, structured authoring, attachment (§17 [#11](https://github.com/hrishikeshdkakkad/fluidbox/issues/11)) ([cb900b4](https://github.com/hrishikeshdkakkad/fluidbox/commit/cb900b464d44359975c36c240af41bb561027848))
* **policies:** fold managed overrides into head rules in the engine ([a3c506d](https://github.com/hrishikeshdkakkad/fluidbox/commit/a3c506ddd1b4133fd2202c045455afd40894187d))
* **policies:** retire policy-sync; governance e2e for the versioned model ([ea05cc0](https://github.com/hrishikeshdkakkad/fluidbox/commit/ea05cc07bb19967e92b2040f0a91de467061d7ea))
* **redact,codex:** scrub OpenAI project keys + fbx session/trigger tokens; codex-runner package.json (Phase 6 step 6 prep) ([9baff81](https://github.com/hrishikeshdkakkad/fluidbox/commit/9baff818e8a16d93ae8047abb97ac9fd0bb37fc9))
* **replay-runner:** deterministic replay driver + transcript ([5ba04f5](https://github.com/hrishikeshdkakkad/fluidbox/commit/5ba04f5ea8942eb04c4852088bb5febd20cd921c))
* **replay-runner:** image + just replay-build ([cd5202d](https://github.com/hrishikeshdkakkad/fluidbox/commit/cd5202d0f971d2e57cba09b63a2a2fc59396c848))
* **runner:** move the control token off the environment before exec ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([31a7688](https://github.com/hrishikeshdkakkad/fluidbox/commit/31a768895abcdb98bd8f7c91e422c610fb9c73de))
* **runner:** shared runner-lib (contract + shims) + token-renew loop + server-side renew hardening (Phase 6 step 5) ([3248645](https://github.com/hrishikeshdkakkad/fluidbox/commit/324864595822a9228f7d7453b5aebbfcae5f56fc))
* **scripts:** db-clean-tests — a scalpel for test residue, not a reset ([#46](https://github.com/hrishikeshdkakkad/fluidbox/issues/46)) ([aa8be4b](https://github.com/hrishikeshdkakkad/fluidbox/commit/aa8be4bcafc6abe6bfd79d394673fa2217032624))
* **server,db:** approval single-emission + pg_notify, session lease/epoch fencing, delivery claims ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([568162a](https://github.com/hrishikeshdkakkad/fluidbox/commit/568162a22e3e5392af3fd2e57c423f71a2367556))
* **server,db:** durable four-state execution claims around brokered dispatch ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([68877e9](https://github.com/hrishikeshdkakkad/fluidbox/commit/68877e944d955773f240e13a05f893bafa553115))
* **server,db:** durable request-keyed LLM budget reservations ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([c175a54](https://github.com/hrishikeshdkakkad/fluidbox/commit/c175a5412011fdc0520a4435f8dead323a2c0cde))
* **server,db:** one-time browser-bound OAuth state rows ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([56d9f69](https://github.com/hrishikeshdkakkad/fluidbox/commit/56d9f696871e59d23762250acd9e0129aad5f70f))
* **server,db:** reusable OAuth client registrations ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([88bd6e4](https://github.com/hrishikeshdkakkad/fluidbox/commit/88bd6e4e77974b486ccfbbae0b87bee7f16b0cbf))
* **server,db:** versioned envelope sealing with per-tenant DEKs ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([5a48b5f](https://github.com/hrishikeshdkakkad/fluidbox/commit/5a48b5f7a3f772a9a1a183b7d64204e230223cc3))
* **server,workspace:** workload identity, archive object store, load harness ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([b4890b9](https://github.com/hrishikeshdkakkad/fluidbox/commit/b4890b9a272b8efdcdaca6503b67cbd4f1724c1f))
* **server:** /v1/admin/orgs — break-glass, IdP lifecycle, issuer migration ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([860e90a](https://github.com/hrishikeshdkakkad/fluidbox/commit/860e90ad478c3871f308a7a459f2d6382fe966ae))
* **server:** /v1/auth — IdP-agnostic OIDC login, sessions, switch, logout ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([d072ae2](https://github.com/hrishikeshdkakkad/fluidbox/commit/d072ae25680a2ba7a1148b5d7fe1f85188314f70))
* **server:** binding consumers — broker/workspace/publish rechecks, approval authority ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([1d476ce](https://github.com/hrishikeshdkakkad/fluidbox/commit/1d476cec730e8e2dfd9c35db726e33c94938c3f1))
* **server:** binding resolution service — requirements to frozen run resource bindings ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([2e9fa75](https://github.com/hrishikeshdkakkad/fluidbox/commit/2e9fa752efb6156708d20aac01a1fa7ca1d7223f))
* **server:** connection ownership — personal/organization owners, use authorization, /auth/me user_id ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([cde13ae](https://github.com/hrishikeshdkakkad/fluidbox/commit/cde13aeff9b8b3d8b7c07451dc0929939d0944a5))
* **server:** connection tool snapshots — forced-negotiation photograph, bundle cutover, generation custody ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([739da1d](https://github.com/hrishikeshdkakkad/fluidbox/commit/739da1db4d2190d2705ee4f220aad98ad578b5e9))
* **server:** contract URL + ingress helpers on trigger get/list/rotate ([9df9515](https://github.com/hrishikeshdkakkad/fluidbox/commit/9df9515dc5582667b17a948f3e12423bc9ce5f7d))
* **server:** event trigger subscriptions — connection binding, $17 [#2](https://github.com/hrishikeshdkakkad/fluidbox/issues/2) default events, publish modes ([271f877](https://github.com/hrishikeshdkakkad/fluidbox/commit/271f877b617d22d08babbeea16b623e179cfcf66))
* **server:** fork trust tier is real — read-only enforcement at the permission gate ([dc07e67](https://github.com/hrishikeshdkakkad/fluidbox/commit/dc07e679883a120e74eb0afa8479d84f8282854f))
* **server:** github app connections — rs256 jwt, installation tokens, sealed webhook secret ([1b17190](https://github.com/hrishikeshdkakkad/fluidbox/commit/1b171908799e8758bfc89c983fc5b684bad5c78f))
* **server:** github connector — webhook verify + PR normalize behind the seam ([184e11f](https://github.com/hrishikeshdkakkad/fluidbox/commit/184e11f84e6178482ccfe17347df2e0b3018cd1c))
* **server:** outbound rate limits + per-connection circuit breakers ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([f729c7c](https://github.com/hrishikeshdkakkad/fluidbox/commit/f729c7c07122ed8285267112413b96328cbdf8f9))
* **server:** PATCH /v1/triggers/{id} for the mutable subscription surface ([2d0f3bb](https://github.com/hrishikeshdkakkad/fluidbox/commit/2d0f3bbc221b376511afdb6711a079ea5f65768e))
* **server:** per-run MCP session manager + 2025-11-25 conformance ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([1e91de2](https://github.com/hrishikeshdkakkad/fluidbox/commit/1e91de20452d0988dade805c765732b2cde73163))
* **server:** per-tenant LiteLLM virtual keys; master key confined to provisioning ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([590a55a](https://github.com/hrishikeshdkakkad/fluidbox/commit/590a55a12af7716f1f6a5313bac6f5b35080faaa))
* **server:** PR comment/check publishers — stable update-in-place identity, App-only ([f5dd292](https://github.com/hrishikeshdkakkad/fluidbox/commit/f5dd2924685073056db2fbfb38ffc26e8dd04c8a))
* **server:** Principal resolver, RBAC, PATs, CSRF — identity enforcement ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([f914126](https://github.com/hrishikeshdkakkad/fluidbox/commit/f914126e55b565071cd1f75c45ce9c68019c3e9d))
* **server:** provider-ignorant event spine — ingress, two-level dedup, subscription fan-out ([6d73a3b](https://github.com/hrishikeshdkakkad/fluidbox/commit/6d73a3bd6b3cb1280cd3cd3295f4546033b795cd))
* **server:** pure PATCH resolution for trigger subscriptions ([d9d34b0](https://github.com/hrishikeshdkakkad/fluidbox/commit/d9d34b00e634e339a06fdebaea7863f44bcfc913))
* **server:** resumable legacy→KMS re-seal with count parity ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([08e8edb](https://github.com/hrishikeshdkakkad/fluidbox/commit/08e8edb7c299b6b4c31dc2f7e886018edee5edd9))
* **server:** shared egress boundary — SSRF-hardened clients + clone admission ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([2437878](https://github.com/hrishikeshdkakkad/fluidbox/commit/243787833db17df72025a6d8140e16e29b89c7e4))
* **web:** app-store composer — unified AppPicker, guardrail presets, plain language ([64ce380](https://github.com/hrishikeshdkakkad/fluidbox/commit/64ce3801a4ab7bc5610a2f69f24bc7b4bb403a30))
* **web:** bundle picker for agent attach — select registered capabilities instead of typing refs ([576d3f3](https://github.com/hrishikeshdkakkad/fluidbox/commit/576d3f31fdfad096ac91307e8c6032490b167e43))
* **web:** connection ownership, tool snapshots, requirements editor, explicit bindings ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([2b8a6c6](https://github.com/hrishikeshdkakkad/fluidbox/commit/2b8a6c65fde1117ea7545b17bb63a98a0ccabc51))
* **web:** dashboard redesign — 5-item IA, dark design system, app-store integrations ([7386476](https://github.com/hrishikeshdkakkad/fluidbox/commit/7386476a67715f818a3d7c9884563708bcfc4400))
* **web:** durable /automations/{id} page with live API contract ([8df1dc2](https://github.com/hrishikeshdkakkad/fluidbox/commit/8df1dc2b5ba0512aad0464021572a5cf15e7f563))
* **web:** edit template and settings on the automation detail page ([ddae3f1](https://github.com/hrishikeshdkakkad/fluidbox/commit/ddae3f19afaf532ae2de7dca4c13e2dd183bcc13))
* **web:** enable codex harness; per-harness models reset on switch (Phase 6 step 9) ([7750eb7](https://github.com/hrishikeshdkakkad/fluidbox/commit/7750eb7b6f175646f9ce0f5ca53678ce3a6a2547))
* **web:** extract pure automation-contract helpers ([4293c72](https://github.com/hrishikeshdkakkad/fluidbox/commit/4293c727487f67283f59e22c09b22c1c61742333))
* **web:** FLUIDBOX_WEB_MODE sso proxy, login page, session shell ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([b3f187f](https://github.com/hrishikeshdkakkad/fluidbox/commit/b3f187ffb319271c188ea0e7081d2129045b0c68))
* **web:** homepage v2 — patterns grid + real-product visibility section ([d22dd5f](https://github.com/hrishikeshdkakkad/fluidbox/commit/d22dd5f6802fab63e1cd404f5b3d5ea3edb69bc8))
* **web:** improve control-plane UX and resilience ([cf1e1d2](https://github.com/hrishikeshdkakkad/fluidbox/commit/cf1e1d209cebec8890c883a4aab52ce32f6c8b7c))
* **web:** marketing site redesign — dark editorial system, film hero, end-user pass ([dc007fc](https://github.com/hrishikeshdkakkad/fluidbox/commit/dc007fcf7dec0f55989370aa9595ac845a780961))
* **web:** move the dashboard under /app — the public/app boundary ([3203627](https://github.com/hrishikeshdkakkad/fluidbox/commit/320362710dabe061fe0dddd019fc3e8de9a1994a))
* **web:** policy attachment + structured authoring (specs A & C) ([940cea0](https://github.com/hrishikeshdkakkad/fluidbox/commit/940cea05467e7bfd351a83e8f9a39bdae750de2a))
* **web:** public marketing site — home, product, open-source, security, pricing, changelog ([c9ae3e5](https://github.com/hrishikeshdkakkad/fluidbox/commit/c9ae3e5caccdc090ff0423e67580ef5c593a36ad))
* **web:** self-explanatory template box + pre-save API preview ([d64957f](https://github.com/hrishikeshdkakkad/fluidbox/commit/d64957ffb2a16a77bc2908f14fbdf502182bfb55))
* **web:** SEO surface — sitemap, robots, OG/Twitter card, noindex boundaries ([92d130f](https://github.com/hrishikeshdkakkad/fluidbox/commit/92d130f379510e6c12824fece5963b11e673c9cc))
* **web:** server-side auth gate — sso login wall, session-aware /login, deep-link return ([f96d1a7](https://github.com/hrishikeshdkakkad/fluidbox/commit/f96d1a7d461a3f53e6051e250af1248b0d3b2374))
* **web:** shared AutomationContract; secrets modal is secrets-only ([33ee67f](https://github.com/hrishikeshdkakkad/fluidbox/commit/33ee67f697e05b6a072fe8c2a54711c68c2a758b))
* **web:** surface the brokered execution outcome in the run timeline ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([fc8b159](https://github.com/hrishikeshdkakkad/fluidbox/commit/fc8b15995e44559250a522d50692cd3b8c96efc5))
* **web:** unify dashboard and run workflows ([#26](https://github.com/hrishikeshdkakkad/fluidbox/issues/26)) ([ba44962](https://github.com/hrishikeshdkakkad/fluidbox/commit/ba44962e8597601d341b40a7e3b7754ca8d6f34e))
* **web:** WorkOS AuthKit web-tier gate for /app (FLUIDBOX_WEB_AUTH=workos) ([52d7279](https://github.com/hrishikeshdkakkad/fluidbox/commit/52d72790b8941e5eafe43f57e9bf6b60903b5088))


### Fixed

* **capabilities:** admit real-vendor tool manuals in the photograph screen ([df7afd1](https://github.com/hrishikeshdkakkad/fluidbox/commit/df7afd1cb5119d01426e650ed621bc88edaccb93))
* **ci,docs:** strengthen false-green asserts; correct the go_url residual disclosure ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([fb3c7ad](https://github.com/hrishikeshdkakkad/fluidbox/commit/fb3c7ada4cdc68613c07ef433b24cfac0acf4a95))
* **ci:** bindings-e2e — instant provisioning failure via dead-registry image ref; settle budget 300s ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([2fd8ec3](https://github.com/hrishikeshdkakkad/fluidbox/commit/2fd8ec3741f4592622e360df296003e0892234f7))
* **ci:** CI round 2 — __Host- flow cookie, DB fixture shapes, family lockstep, AWS SDK rustls stack ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([226d7a5](https://github.com/hrishikeshdkakkad/fluidbox/commit/226d7a59d84d12cc4a16edb1a2d605ee1c08cbdf))
* **ci:** identity-e2e — curl -w composition, psql tuple-only captures, fail-fast preconditions ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([96ef5e0](https://github.com/hrishikeshdkakkad/fluidbox/commit/96ef5e0ed93eefd324509765740e370c07eddb0a))
* **ci:** read gate-proof evidence through a container, not from the host ([c94fac7](https://github.com/hrishikeshdkakkad/fluidbox/commit/c94fac768ab0e0ed1e6f8f5d71c453e001b2eeb5))
* close the three P2s, pin the runner supply chain, gate publishing ([#112](https://github.com/hrishikeshdkakkad/fluidbox/issues/112)) ([936d671](https://github.com/hrishikeshdkakkad/fluidbox/commit/936d671a1b0df6c9a34c4191c039b43e139f1b10))
* **codex:** correct item/tool/requestUserInput response schema to {answers:{}} (Step 6 re-review) ([3a1ad2f](https://github.com/hrishikeshdkakkad/fluidbox/commit/3a1ad2fa2d02a3ce27f9cf46457ef85f62c0908b))
* **codex:** incorporate Step 6 review — governance completeness, move-path, state dirs, schemas ([3ba5066](https://github.com/hrishikeshdkakkad/fluidbox/commit/3ba5066901f6dd87cd15826aba1985ea25856fc8))
* **codex:** make the codex harness actually start (it never did) ([c8ad396](https://github.com/hrishikeshdkakkad/fluidbox/commit/c8ad39694c91f407994f0989f0c00aad4e9fd61f))
* **core:** govern every tool the pinned CLI advertises; deny sub-execution ([6003619](https://github.com/hrishikeshdkakkad/fluidbox/commit/60036193ab87cb2d2b04d50d55eedb6a14605644))
* **core:** register ToolSearch in the canonical tool vocabulary ([22ce53e](https://github.com/hrishikeshdkakkad/fluidbox/commit/22ce53e967450e2d15e5b246a06fc8cdf2d3eea2))
* **db,ci,docs:** final-review wave — RLS blast radius, e2e port, runtime-role coverage ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([293c25a](https://github.com/hrishikeshdkakkad/fluidbox/commit/293c25a42161b14d01db302e0bf370274e0ef25f))
* **db,server:** Codex verify — ingress scope-after-verify, switch config-lock, residual predicates ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([15152d8](https://github.com/hrishikeshdkakkad/fluidbox/commit/15152d8ff346fbebfec004f376280f766f05cb35))
* **db,server:** drop the unused delivery-claim index; scope the epoch-fence claim ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([3777d24](https://github.com/hrishikeshdkakkad/fluidbox/commit/3777d240d3ae0d4acef3ada4e5eb7bb2c6732e8c))
* **db,tools:** catalog importer targets the global partial slug index; isolate mcp-shape CHECK negative ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([63f05c2](https://github.com/hrishikeshdkakkad/fluidbox/commit/63f05c22074a7c7648513bf5be362f2923a29e9e))
* **db:** 0013 conversion — branch coverage tests, mixed-bundle drop notice, safe string-pin parse ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([0b01842](https://github.com/hrishikeshdkakkad/fluidbox/commit/0b01842878ca9c28b8487ed27ee20d4c612baa28))
* **db:** 0013 conversion — floating keep-lists, append-only clone for sandbox-latest ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([3044639](https://github.com/hrishikeshdkakkad/fluidbox/commit/3044639e2a87e8fbeabb252af31be430a9436c75))
* **db:** 0013 conversion — fresh next-rev per appended revision ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([8572f11](https://github.com/hrishikeshdkakkad/fluidbox/commit/8572f11f6bf260bfebe0138f8ac0733f40b19090))
* **db:** 0013 conversion — per-source revisions, keep-list-preserving repoints ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([d930f8a](https://github.com/hrishikeshdkakkad/fluidbox/commit/d930f8accd7f3657ee86a11bbe216fa5b0e1373f))
* **db:** review round-1a — write-side tenant proofs, switch-claim hardening, audit truncate guard ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([492f8df](https://github.com/hrishikeshdkakkad/fluidbox/commit/492f8df64a7618902b338a2cc72cd63732e69b46))
* **db:** final-review minors — projections, user_status symmetry, bootstrap/migrate test gaps ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([bcef985](https://github.com/hrishikeshdkakkad/fluidbox/commit/bcef9850ef634f744dbe76879ddf41a2342301e0))
* **db:** RLS review wave — role posture validation, enumerated grants, audit tenant floor ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([d0f1d82](https://github.com/hrishikeshdkakkad/fluidbox/commit/d0f1d8215474f577fb18077571c025bf48bef108))
* **db:** scope the sweeper tests to their own session ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([2166726](https://github.com/hrishikeshdkakkad/fluidbox/commit/21667265dcd5d6d2c714fb9c9e7c0b773b55146f))
* **db:** switch-claim takes the config lock first; jwks cache active-only ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([bb52347](https://github.com/hrishikeshdkakkad/fluidbox/commit/bb52347eb07c18861531595091818b5bc66d5820))
* **db:** the 0013 conversion is a GLOBAL scan — confine the tests to one tenant ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([7c58065](https://github.com/hrishikeshdkakkad/fluidbox/commit/7c58065097a2abcccd4d5989b519e82a3a89b079))
* **demo:** fail when the run fails; agree with the server on the docker daemon ([5f7b114](https://github.com/hrishikeshdkakkad/fluidbox/commit/5f7b114f4fe977090c59d7ff7ea93d44670bb781))
* **demo:** prove the daemon can read the checkout before running ([4f8e82b](https://github.com/hrishikeshdkakkad/fluidbox/commit/4f8e82b7695292182c69f510a146f02f2bc0eadd))
* **demo:** the from-source first run was broken; add static self-checks ([fbee879](https://github.com/hrishikeshdkakkad/fluidbox/commit/fbee87950be91290cb16673f9712825912ad572a))
* **e2e,core:** three SCRIPT defects behind the first hardening run ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([c098c3b](https://github.com/hrishikeshdkakkad/fluidbox/commit/c098c3b02b2753c17d6a1153a7ea20b3ccf5e69b))
* **e2e,ledger:** codex phase green (16/16) — summarize() lists edit paths; replay assertion counts ([a526108](https://github.com/hrishikeshdkakkad/fluidbox/commit/a526108e77a938731fe104ff78dfa16885a9fb92))
* **e2e:** deflake trigger rotation race; align github phase with [#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33) identities ([a6cb913](https://github.com/hrishikeshdkakkad/fluidbox/commit/a6cb913014f4f5a53cbd55ec7402a73bbdcc8909))
* **e2e:** make no-live mode zero-spend and deterministic (closes the CI flake class) ([#23](https://github.com/hrishikeshdkakkad/fluidbox/issues/23)) ([52d8f57](https://github.com/hrishikeshdkakkad/fluidbox/commit/52d8f57ba76c28d024eb40b0d0b1c0aff68eb739))
* **e2e:** strip stray ellipsis byte that broke e2e.sh preflight under set -u ([1f3f8ed](https://github.com/hrishikeshdkakkad/fluidbox/commit/1f3f8ed7452cc94dbaabd95651e1c66119e64988))
* **e2e:** suite fixes surfaced by the full local run (611/0 across the five phase suites) ([da80c76](https://github.com/hrishikeshdkakkad/fluidbox/commit/da80c76e75ade79df15abefbeef79fbf4b89006f))
* **e2e:** WRONG ASSERTION — (i.4) demanded 'cancelling' its own fixture cannot produce ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([a58b126](https://github.com/hrishikeshdkakkad/fluidbox/commit/a58b1269a746c75a6af112968f2229a89cc90021))
* **eval:** quote the required-token message, and make the guard parse the file ([8f33f0d](https://github.com/hrishikeshdkakkad/fluidbox/commit/8f33f0d16b42adc42c42e9d35b93931a794c4a06))
* **eval:** require an admin token; loopback the dashboard; guard both in CI ([922bcef](https://github.com/hrishikeshdkakkad/fluidbox/commit/922bcef09d881577a53593db07c7ec05f61cdf1f))
* **facade,e2e,web:** post-ship Phase 6 correctness review ([9bc05b7](https://github.com/hrishikeshdkakkad/fluidbox/commit/9bc05b7d1b69ddc43c51c121aee3b727896637dd))
* **facade+gate:** incorporate Step 4 review — dup-key differential, verdict CAS, NULL-digest fail-closed, dialect errors, SSE cap ([2142a56](https://github.com/hrishikeshdkakkad/fluidbox/commit/2142a567e7445646476facd22c843ad880b5ecf7))
* final-review follow-ups — preserve next_fire_at on cadence-neutral PATCH, no-op {} schedule, clearer errors/hints ([d9fd226](https://github.com/hrishikeshdkakkad/fluidbox/commit/d9fd226b72e2b72f954e13f236d0b5f4a39c004c))
* **gate:** CAS-first on the budget + approval-timeout paths (Step 4 re-review) ([a8064fa](https://github.com/hrishikeshdkakkad/fluidbox/commit/a8064fadc315680813e4cc22dfd90e580dab96f2))
* **gate:** server-side /result idempotency across revoke + /permission terminal check (Step 5 re-review) ([56fb21a](https://github.com/hrishikeshdkakkad/fluidbox/commit/56fb21a837a1c0b2be82ba7a78ed2f9e862311c5))
* **github:** drop default_events with the webhook on non-public deployments ([b17a8cf](https://github.com/hrishikeshdkakkad/fluidbox/commit/b17a8cfe05634a7b2595e8b6ddac8dab64c7eed3))
* **github:** omit the webhook from manifests on non-public FLUIDBOX_PUBLIC_URL ([bb9b0d9](https://github.com/hrishikeshdkakkad/fluidbox/commit/bb9b0d9f199dfbd19d56f9341f0940f310deee6c))
* **k8s:** archive streaming — pack to disk with a size cap, stream the GET, reclaim leaks (M4, L3) ([5d3acd5](https://github.com/hrishikeshdkakkad/fluidbox/commit/5d3acd52061348e003392673041e6238d916a4e2))
* **k8s:** batch-5 review round 2 — toleration fidelity, render-time validation, release binding tightened ([72b364f](https://github.com/hrishikeshdkakkad/fluidbox/commit/72b364f9c61906ffeaa2e99b695cc67ebf8d442d))
* **k8s:** batch-5 review round 3 — strict toleration fields, semver tag guard, doc truth ([3fc7c0e](https://github.com/hrishikeshdkakkad/fluidbox/commit/3fc7c0e3c21c5f8205dcfb4157b1a93598b5fecc))
* **k8s:** batch-6 review round 2 — pod-side streaming, atomic pack, fail-closed caps, safer archive lifecycle ([ec53557](https://github.com/hrishikeshdkakkad/fluidbox/commit/ec53557ac81a6f8f1cae47a36012c30fec28e595))
* **k8s:** batch-6 review round 3 — symlink-entry ceiling, session-state-aware TTL sweep, quieter-never-silent failures ([a034f61](https://github.com/hrishikeshdkakkad/fluidbox/commit/a034f61b7f81a6c751f51157d780fc25227d4b73))
* **k8s:** batch-7 review round 2 — rolling-deploy-safe reconcile, guarded adoption, honest no-handle collection ([277fb5b](https://github.com/hrishikeshdkakkad/fluidbox/commit/277fb5bdd28c1c5c1331b6340f89e096be61fe8b))
* **k8s:** batch-7 review round 3 — boot-sweep parse parity, honest label mismatch, launch-mins floor ([f26c3c4](https://github.com/hrishikeshdkakkad/fluidbox/commit/f26c3c44b5c1d6089efcbff141bd62d2dac8758b))
* **k8s:** buffer the archive file reader in workspaced init ([d098012](https://github.com/hrishikeshdkakkad/fluidbox/commit/d098012fed4a7026ae452d41307cb7d21f3ba0db))
* **k8s:** cleanups — fail-closed gate resolution, UID-guarded deletes and collection, quiesce replay (L2, L10, L11) ([a9695db](https://github.com/hrishikeshdkakkad/fluidbox/commit/a9695db42d79b6e64f67cd2a97a6dbf1b854d9bb))
* **k8s:** cleanups — fail-closed gate resolution, UID-guarded deletes, quiesce replay (L2, L10, L11) ([b6cb104](https://github.com/hrishikeshdkakkad/fluidbox/commit/b6cb1040d4369c2b785618a30f47fef443454abf))
* **k8s:** close the review round-2 findings on the finalizer (M1 pre-handle window + 8 defects) ([ad321f3](https://github.com/hrishikeshdkakkad/fluidbox/commit/ad321f3187a5389f97b16c4702a1c97ac1ccb3eb))
* **k8s:** close the netpol admission race with a bounded observation protocol ([8882fc1](https://github.com/hrishikeshdkakkad/fluidbox/commit/8882fc1485a3b9a9fa6fb6701ce8682c86fa67ea))
* **k8s:** enforce a fresh destination before extract/copy (Codex batch-3v3) ([1055827](https://github.com/hrishikeshdkakkad/fluidbox/commit/1055827dc60fee888fe48326bb7a62891803a829))
* **k8s:** extract in-tree symlinks in the workspace archive (H4, L4-pack) ([f77219f](https://github.com/hrishikeshdkakkad/fluidbox/commit/f77219f7c911484d45c62fd41444ec81674526a5))
* **k8s:** extract in-tree symlinks in the workspace archive (H4, L4-pack) ([4c51d51](https://github.com/hrishikeshdkakkad/fluidbox/commit/4c51d51ccdfbdf1a90350177502c75425ecf951f))
* **k8s:** finalizer durability — winning intent is the single source of truth (H2,H3,H5,M1,L6,L7) ([3f88b34](https://github.com/hrishikeshdkakkad/fluidbox/commit/3f88b34ffdedb8f2343d7dbbbce3dee0a11f3c85))
* **k8s:** harden symlink extraction + preserve links in copy_tree (review of [#61](https://github.com/hrishikeshdkakkad/fluidbox/issues/61)) ([c7d237a](https://github.com/hrishikeshdkakkad/fluidbox/commit/c7d237aaa25adc651350bd8889e9c03acfa77240))
* **k8s:** helm↔provider wiring — sandbox values reach the provider, digests render, probe gate parity (M3, M9, M10, L12) ([4804a03](https://github.com/hrishikeshdkakkad/fluidbox/commit/4804a03cc759ca3a560ca76ddf6cec8d0144bfd9))
* **k8s:** helm↔provider wiring — sandbox values reach the provider, digests render, the boot probe gains gate parity (M3, M9, M10, L12) ([a40af6d](https://github.com/hrishikeshdkakkad/fluidbox/commit/a40af6d0bb5f6f485e4d6ff0e1fa32a38b3b8d09))
* **k8s:** install ring CryptoProvider so the Kubernetes provider boots ([41c851f](https://github.com/hrishikeshdkakkad/fluidbox/commit/41c851f1ebedc9481adc95a8425df320ae4a55fa))
* **k8s:** install ring CryptoProvider so the Kubernetes provider boots ([290d2f6](https://github.com/hrishikeshdkakkad/fluidbox/commit/290d2f6cc3416673eb4058666e1c75c3b034e45e))
* **k8s:** integrity-check exec-collected diffs, resume dropped streams (M2, L4-exec) ([24e0299](https://github.com/hrishikeshdkakkad/fluidbox/commit/24e02998a9d02e4e824b4b5745ce6b4e0ffe8d8f))
* **k8s:** listener hardening — no /internal on the public plane under K8s (M8, L1, L5, L8) ([d2b1e3e](https://github.com/hrishikeshdkakkad/fluidbox/commit/d2b1e3eeb52bec7e311db07a2cdc1bf28b3a1913))
* **k8s:** make canonicalize the sole symlink-containment authority (Codex re-review) ([37912b6](https://github.com/hrishikeshdkakkad/fluidbox/commit/37912b6ac1d1af85087b93919f5f66c277ee6970))
* **k8s:** make the kind-calico CI tier a real check (H1) ([#60](https://github.com/hrishikeshdkakkad/fluidbox/issues/60)) ([e40d81b](https://github.com/hrishikeshdkakkad/fluidbox/commit/e40d81b97b744ed27db32cec9e14ba3eb5136383))
* **k8s:** numeric runAsUser for bundled LiteLLM ([03bf7cb](https://github.com/hrishikeshdkakkad/fluidbox/commit/03bf7cb60a9b3305213109a71e527baff74afbbe))
* **k8s:** numeric runAsUser for bundled LiteLLM (root image + runAsNonRoot) ([368936b](https://github.com/hrishikeshdkakkad/fluidbox/commit/368936b20945ac75f5a83b0792843bc6805e9397))
* **k8s:** reconcile — periodic adopt-or-terminate sweep, graded config errors, node-loss visibility, Docker-parity pre-launch diffs (M5, M6, M7, L9) ([cce008c](https://github.com/hrishikeshdkakkad/fluidbox/commit/cce008ce69aac74dde836b515e827fec8affcc9e))
* **k8s:** reconcile — periodic adopt-or-terminate sweep, graded config errors, node-loss visibility, Docker-parity pre-launch diffs (M5, M6, M7, L9) ([95fab79](https://github.com/hrishikeshdkakkad/fluidbox/commit/95fab79809d144745be63db3d71e409d315e36c2))
* **k8s:** refuse a symlinked destination in clear_dir_contents (Codex batch-3v4) ([d3a1756](https://github.com/hrishikeshdkakkad/fluidbox/commit/d3a1756c4196ed10c7042b61de4d2369e5c10d53))
* **k8s:** remove a duplicated match line that broke the build (batch-3 docs commit) ([a4aa6cf](https://github.com/hrishikeshdkakkad/fluidbox/commit/a4aa6cfca756ea7479e9d7901024989055a686f5))
* **k8s:** round-3 finalizer hardening — durable budget sweep, settle-window, verified RunResult ([dcfa7b5](https://github.com/hrishikeshdkakkad/fluidbox/commit/dcfa7b545e07cfe96a04458573037a9c894cfd43))
* **k8s:** round-6 — transactional attach fence, evidence-preserving abandon ([b53d0d6](https://github.com/hrishikeshdkakkad/fluidbox/commit/b53d0d67438776c29439bb93562fbd7d79a28a56))
* **k8s:** rounds 4-5 finalizer convergence — intent-aware launch ownership, gated collection, self-cleaning losers ([e3c1542](https://github.com/hrishikeshdkakkad/fluidbox/commit/e3c154234f26618bc47f97c7dca8261be2923628))
* make an audience mismatch fail loudly; tighten audience disclosures ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([3166f26](https://github.com/hrishikeshdkakkad/fluidbox/commit/3166f2677af59d17074bf6c7639b09d97312ff81))
* **oauth:** gate CIMD on a fetchable public URL; re-resolve stale client identities ([60ee57b](https://github.com/hrishikeshdkakkad/fluidbox/commit/60ee57b9179aee90b1e2f5b07e11086a24fea1a3))
* **policies:** codex confirmation nits — fail-closed seeds, direct RLS probe, sharper e2e pins ([ccb8bce](https://github.com/hrishikeshdkakkad/fluidbox/commit/ccb8bce1b8dcfbdfae003b31bf4cfa8d87fb9c84))
* **policies:** codex final-review fixes — divergent YAML, preview staleness, strict imports ([1438a1d](https://github.com/hrishikeshdkakkad/fluidbox/commit/1438a1d9eed786e7b1389a105b4b4c6379b17b2c))
* **policies:** review-response hardening — proportional seed refusal, policy delete, precise wildcard fold ([a388488](https://github.com/hrishikeshdkakkad/fluidbox/commit/a3884882f941e0fedd4fa9eb718da28e47b92931))
* **release:** close the three RC verification blockers ([0a5338f](https://github.com/hrishikeshdkakkad/fluidbox/commit/0a5338f6f7065bf856100fa6e3c50e9bf56764fb))
* **release:** don't let the Cargo.lock step mask the real release-please error ([#110](https://github.com/hrishikeshdkakkad/fluidbox/issues/110)) ([9860976](https://github.com/hrishikeshdkakkad/fluidbox/commit/9860976c454b6a909d875b00ba7531d930e2a29c))
* **release:** drop README.md from release-please extra-files ([0865d2e](https://github.com/hrishikeshdkakkad/fluidbox/commit/0865d2e42bd81ee49f75c9621be36122fa81a752))
* **release:** let the version guard express a prerelease ([22d8a2f](https://github.com/hrishikeshdkakkad/fluidbox/commit/22d8a2fb4638d5b6d67f697312c4d502c5fe0550))
* **release:** make release-please work with a virtual cargo workspace ([#109](https://github.com/hrishikeshdkakkad/fluidbox/issues/109)) ([f192dbd](https://github.com/hrishikeshdkakkad/fluidbox/commit/f192dbdb89bbd2725966df753796895eef79d0a7))
* **review:** address PR [#27](https://github.com/hrishikeshdkakkad/fluidbox/issues/27) whole-branch external review — 4 P1s, 3 P2s, 3 minors ([f05dc67](https://github.com/hrishikeshdkakkad/fluidbox/commit/f05dc67edb9c86013b5a5b7b1ee12ab1bff7e792))
* **runner-test:** an unopened fd is a platform assumption, not a fact ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([5d69db6](https://github.com/hrishikeshdkakkad/fluidbox/commit/5d69db6a93070cc5df807fde9e026a99513b6cbc))
* **runner+e2e:** Step 5 review — e2e build context, self-rescheduling renew, /result ack-on-revoke ([2898502](https://github.com/hrishikeshdkakkad/fluidbox/commit/2898502256a5f5a4a2fd3fcf951027ecf79ae106))
* **runner:** gate EVERY Claude tool call via a PreToolUse hook ([ef5ba1d](https://github.com/hrishikeshdkakkad/fluidbox/commit/ef5ba1de5b821b942bcac7713f87aec9500a2c96))
* **scale-e2e:** bound each concurrent gate request ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([8893c7b](https://github.com/hrishikeshdkakkad/fluidbox/commit/8893c7bda8e2acc2b3c9d44460fb51950696f323))
* **scale-e2e:** wait on the burst PIDs, not the whole job set ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([4c3db26](https://github.com/hrishikeshdkakkad/fluidbox/commit/4c3db26b76ea1a27fbb0010f6f90e6e209e06a0f))
* **scripts:** governance e2e runs from any cwd; .env.example uses reachable bind ([9458534](https://github.com/hrishikeshdkakkad/fluidbox/commit/945853497f98be59b78724ca97b29a7fe710ce5d))
* **seed:** bootstrap policies insert-if-absent so UI edits survive reboot ([b82f307](https://github.com/hrishikeshdkakkad/fluidbox/commit/b82f307e2135712c2587ffd38b3a65bc8e7d2a82))
* **seed:** source the curated agent's harness id + defaults through the registry (steps 1-3 review) ([d9c06dc](https://github.com/hrishikeshdkakkad/fluidbox/commit/d9c06dc66d0e2af1945aa8c71a9750e2de05f4c6))
* **server,ci,docs:** refresh-singleflight bug, restore-drill fixture, global-row RLS asserts, runbook truth ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([f6adb66](https://github.com/hrishikeshdkakkad/fluidbox/commit/f6adb66564e206d2e1d70457e9a720735ffc4b61))
* **server,ci:** audited JSON rejections; SSE exit-code assertion; comment accuracy ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([2994955](https://github.com/hrishikeshdkakkad/fluidbox/commit/2994955f3afe2ac9e62155347ffbbfd8e739b54b))
* **server,ci:** oauth critical section on one pooled connection; AS error log sanitization; per-bearer init assertion after refresh ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([9b47ff1](https://github.com/hrishikeshdkakkad/fluidbox/commit/9b47ff12b0f262f032646feb3f5ca6c6e97b2b49))
* **server,ci:** socket-peer client IP unless trusted proxy; e2e readiness path ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([c854032](https://github.com/hrishikeshdkakkad/fluidbox/commit/c854032eef7a9d4845f125c95c10a8b03b35b46e))
* **server,core:** bound schema validation cost; close ambient-proxy, git-env and OAuth redirect holes ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([af504b7](https://github.com/hrishikeshdkakkad/fluidbox/commit/af504b7865924c7e8cd8c00d1c6e82f6f31d39df))
* **server,core:** linear SSE parsing, capped server-request replies, bounded OAuth reads ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([be1bc64](https://github.com/hrishikeshdkakkad/fluidbox/commit/be1bc64c6311acec9193e3199ce7a572cd9b96f0))
* **server,db,ci:** connector_oauth_flows verifier joins the sealed-family lockstep ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([3bd156d](https://github.com/hrishikeshdkakkad/fluidbox/commit/3bd156d7ed6d71b7c677508fe6c3a43235c304e5))
* **server,db,runner:** adopt durable outcomes on lost CAS; tenant-partition the governor; stable shim idempotency ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([ef8ccb8](https://github.com/hrishikeshdkakkad/fluidbox/commit/ef8ccb88561679d4dfcedb9e7952c07a7cf6c84b))
* **server,db:** bound claim churn, unify the terminal refusal, gate the legacy path ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([34cb3cc](https://github.com/hrishikeshdkakkad/fluidbox/commit/34cb3ccfc751a4a40db80297dade26e78d836125))
* **server,db:** charge only on a durable usage write; repair two false-green guards ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([024b5b9](https://github.com/hrishikeshdkakkad/fluidbox/commit/024b5b9ee394bebe2b8ae237729ff5b5a0ddbb8f))
* **server,db:** review round findings — recheck seam, oauth atomicity, snapshot guards, xss ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([60d29f7](https://github.com/hrishikeshdkakkad/fluidbox/commit/60d29f747d3259ef63a0c401afee54338c61685b))
* **server,db:** land the OAuth custody bag inside the start's lock-holding txn ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([b991546](https://github.com/hrishikeshdkakkad/fluidbox/commit/b991546b5d852e0fe9bc0f2199849339b80bba6e))
* **server,db:** oauth bump-in-update + post-lock generation gate; sanitized upstream errors; capped discovery reads; trigger-token principal ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([84ad666](https://github.com/hrishikeshdkakkad/fluidbox/commit/84ad666e295ddac7b7a1cff7642bc0d19286603f))
* **server,db:** OAuth review wave — activation CAS, bounded key recovery, mint cleanup ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([b6ee2ed](https://github.com/hrishikeshdkakkad/fluidbox/commit/b6ee2edc472a0cf98478972390237a1f8df2627f))
* **server,web,ci:** review round-1c — arming locks, strict PATCH, proxy strictness, acceptance tightening ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([4052079](https://github.com/hrishikeshdkakkad/fluidbox/commit/4052079e2672b4a59025329b52fa4427dd115097))
* **server,web,ci:** Codex verify 1c — lock-coherent PATCH/deactivation, audited refusals, interleaving tests ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([17619f4](https://github.com/hrishikeshdkakkad/fluidbox/commit/17619f45b72f52ba41b49b08d49b56d167011cb6))
* **server,web:** tenant-scoped GitHub App flows; Phase C UI cutover fixes ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([cb17c69](https://github.com/hrishikeshdkakkad/fluidbox/commit/cb17c693f17d7c5b42b9bf67290048db8bc4b72f))
* **server:** approval decide_own excludes brokered calls; strict Decision body ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([cea8cd7](https://github.com/hrishikeshdkakkad/fluidbox/commit/cea8cd7bf202747e39751157caa0a1376b973b22))
* **server:** authorize the terminal MCP session DELETE ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([8c3ad84](https://github.com/hrishikeshdkakkad/fluidbox/commit/8c3ad84b02c01af8ade6e43b38696baf7fc9dee5))
* **server:** bind the CAS to the real start epoch; tighten key-rejection classification ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([cb55637](https://github.com/hrishikeshdkakkad/fluidbox/commit/cb556379ae1a68b00c55136cc5cfa284060562c6))
* **server:** bindings — reject unknown explicit slots, github_app publish assert, authority-branch tests ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([032d146](https://github.com/hrishikeshdkakkad/fluidbox/commit/032d146a2e38de1a2fb60f130641c71240882298))
* **server:** CIMD arm adopts existing registration identity ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([3d05c76](https://github.com/hrishikeshdkakkad/fluidbox/commit/3d05c7609872c7708e6eb716c8eaf856a3e3810c))
* **server:** claim a deployment KEK identity before serving; sweep expired DEKs ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([689f03d](https://github.com/hrishikeshdkakkad/fluidbox/commit/689f03dd555f27552d8f7705faaa48609d45c88b))
* **server:** close the connector-OAuth SSRF pre-flight gap; admission layer + hardening asserts ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([4ae8b10](https://github.com/hrishikeshdkakkad/fluidbox/commit/4ae8b10ad72f45006505e9f60c1ccd720e65d3c8))
* **server:** review round-1b — artifact scoping, JWKS/claims hardening, redirect canonicalization, SSE bound ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([dc1f20c](https://github.com/hrishikeshdkakkad/fluidbox/commit/dc1f20c1ac685b7503d83d332c34904634ad0ba2))
* **server:** Codex verify 1b — JWKS pairing/persistence, null claims, alg canonicality, SSE bound ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([7e2a2df](https://github.com/hrishikeshdkakkad/fluidbox/commit/7e2a2dfd7f5d604c9324292d8559df60bf17dbca))
* **server:** conservative reservation bound; no duplicate GitHub effects; fence the launch writes ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([1054375](https://github.com/hrishikeshdkakkad/fluidbox/commit/1054375316c5cb4e34fdf1b0fdb1db56de62c8d9))
* **server:** final-review wave — retirement gate quadrant, registration FK + heal semantics, transit AAD purpose, tenant-key 401 recovery ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([717b07a](https://github.com/hrishikeshdkakkad/fluidbox/commit/717b07a378cf5472cfd6d7765200585d5f73f17f))
* **server:** KMS review wave — KEK compatibility gate, DEK singleflight, bounded cache, audit fidelity ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([cd34b88](https://github.com/hrishikeshdkakkad/fluidbox/commit/cd34b8870f00bef5da4bae4a56545839e7f6a52b))
* **server:** oauth custody commits are checked — fail closed, never cache on ambiguity ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([99f0be3](https://github.com/hrishikeshdkakkad/fluidbox/commit/99f0be3573cdafcebb520a61183b3b6ba2abeac0))
* **server:** oauth refresh — commit check dominates both result branches ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([1e980fb](https://github.com/hrishikeshdkakkad/fluidbox/commit/1e980fb91c1205fec2d52d6472cfa662f5296d87))
* **server:** owner-role grants take the config lock; audit label + doc nits ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([cfe8ae2](https://github.com/hrishikeshdkakkad/fluidbox/commit/cfe8ae240ab1eb42a0248b7aeb2df6716fed3362))
* **server:** per-hop SSRF client for identity fetches; JWKS negative-cache scoping ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([0ebb108](https://github.com/hrishikeshdkakkad/fluidbox/commit/0ebb1086ffb1912c1147ec22d6600cf81d6db660))
* **server:** re-stamp delivery claims per attempt; tighten Task 6 disclosures ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([2382d11](https://github.com/hrishikeshdkakkad/fluidbox/commit/2382d11ab058f2ee575539d0c5ccbaa939040277))
* **server:** release the finalization claim when the driver lacks the lease ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([4181862](https://github.com/hrishikeshdkakkad/fluidbox/commit/41818624e3bc3e184984d22870dcb835694f31b8))
* **server:** route global registration writes through the audited bypass ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([4253ac5](https://github.com/hrishikeshdkakkad/fluidbox/commit/4253ac533c093213b50184b83a5aa7ae597c4d81))
* **server:** SSE re-auth bound holds across query awaits and backoff ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([edb11b3](https://github.com/hrishikeshdkakkad/fluidbox/commit/edb11b308dcf1c86f9362c4fa4b953b575a56a1f))
* **web,ci:** add-server wizard shapes; bindings-e2e coverage — ambiguity, publish binding, exact negotiation ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([b313bd9](https://github.com/hrishikeshdkakkad/fluidbox/commit/b313bd96f4f75d8bf4b83031ce44560644731b83))
* **web,ci:** requirement owner-aware binding mode; wizard snapshot settling; e2e — signature verification, workspace consumer proof, per-photograph negotiation ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([b759330](https://github.com/hrishikeshdkakkad/fluidbox/commit/b75933082ab332c0b400f2030265ab4e7fd852b2))
* **web:** extract + test proxy security helpers; bare login route; apiPatch ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([324c1be](https://github.com/hrishikeshdkakkad/fluidbox/commit/324c1be057cc35361abb3cbf27c1e21b404fa25f))
* **web:** hide revoked registrations/connections; e2e leaves no live fixtures ([7d181d1](https://github.com/hrishikeshdkakkad/fluidbox/commit/7d181d1483a6840611525c74807feb42931ac81c))
* **web:** label credentialless connections "no auth", not "api key" ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([7c49dd3](https://github.com/hrishikeshdkakkad/fluidbox/commit/7c49dd31194576d4ee76ab21b0d3331f18db1c84))
* **workers:** sweep sessions stalled before launch; allow Created→Failed ([280920e](https://github.com/hrishikeshdkakkad/fluidbox/commit/280920efddac080ecf350ed9bd6efff4ee9ccb9a))
* **workspace,scale-e2e:** two stale comments the whole-branch review caught ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([9c7786e](https://github.com/hrishikeshdkakkad/fluidbox/commit/9c7786e6cdd95eae81753223edc78523af9a18d2))


### Changed

* **db,server:** TenantScope wave A — sessions, events, approvals, workers ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([3b005f7](https://github.com/hrishikeshdkakkad/fluidbox/commit/3b005f707034ad1c74628a85a902c97101c86ea1))
* **db,server:** TenantScope wave B — agents, connections, triggers, create_run ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([1aad1a3](https://github.com/hrishikeshdkakkad/fluidbox/commit/1aad1a361d053f26510bcba78e214b59aedd5a86))


### Documentation

* $17 [#1](https://github.com/hrishikeshdkakkad/fluidbox/issues/1)-[#3](https://github.com/hrishikeshdkakkad/fluidbox/issues/3) recorded settled; event-spine invariant + env seams in DEVELOPING.md/.env.example ([fd3c5a5](https://github.com/hrishikeshdkakkad/fluidbox/commit/fd3c5a578a68e25152ac09c7f96640ce8ada4db2))
* add a full Kubernetes deployment guide ([1e981ec](https://github.com/hrishikeshdkakkad/fluidbox/commit/1e981ec2af7968349431e33127ddce870201552b))
* add root DEVELOPING.md ([0cad5ce](https://github.com/hrishikeshdkakkad/fluidbox/commit/0cad5ce674dc56c6055721a0fd75ad89063b2572))
* CHANGELOG 0.2.0 section + EKS-acceptance handover ([05fe6fe](https://github.com/hrishikeshdkakkad/fluidbox/commit/05fe6fe7b813307b437e38c5bccc72936bb8a115))
* CHANGELOG 0.2.0 section + EKS-acceptance handover ([c2287b3](https://github.com/hrishikeshdkakkad/fluidbox/commit/c2287b3bfc7912fbb66e8d6321958748cc667e07))
* **claude:** harness registry + canonical-tool-vocabulary invariant + two-image note (Phase 6) ([a86fd07](https://github.com/hrishikeshdkakkad/fluidbox/commit/a86fd07dc2328806d84a0b238b52c9741764a72c))
* connector-catalog & OAuth-custody slice — research findings + dense brief (owner-selected next, ahead of Phase 6) ([5e1ba6c](https://github.com/hrishikeshdkakkad/fluidbox/commit/5e1ba6c23ac6b9d02e207715e2253549cf2bdd5e))
* correct Phase D truth-pass overstatements ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([4e25d51](https://github.com/hrishikeshdkakkad/fluidbox/commit/4e25d519c5195df884898c267ebad37eb3f95e4b))
* correct the gate, egress and acceptance claims to what is actually proven ([91c114e](https://github.com/hrishikeshdkakkad/fluidbox/commit/91c114e41e13261a0d460dc250e7eba00243d386))
* **db:** add insert_audit_standalone to the bypass inventory ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([2b5bada](https://github.com/hrishikeshdkakkad/fluidbox/commit/2b5bada75b95d58734b97f5e6a27c3114d4f0eb7))
* **db:** the migrate! reminder was stale for four migrations ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([2434eb2](https://github.com/hrishikeshdkakkad/fluidbox/commit/2434eb23a243da32270c97a00644d0e2b22aa489))
* design agent workspaces and trigger integrations ([cb915fa](https://github.com/hrishikeshdkakkad/fluidbox/commit/cb915fae62fc03593f5c1a378cc80acbcd72a2cd))
* design for the five-minute first-run demo + launch media ([7d80912](https://github.com/hrishikeshdkakkad/fluidbox/commit/7d80912edb9c738c57c2f7fa03346bd0a6d314bf))
* document the outbound rate-limit and circuit-breaker knobs ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([bea019c](https://github.com/hrishikeshdkakkad/fluidbox/commit/bea019cb41163d77b85f6c092cdb60a1898f147e))
* drop references to the removed source-spec file ([32fd709](https://github.com/hrishikeshdkakkad/fluidbox/commit/32fd7092fe60c14ff503d0ead0546281ad0bf7ee))
* **eks:** Phase-F live EKS acceptance — PASS, zero-orphan audited ([c482a99](https://github.com/hrishikeshdkakkad/fluidbox/commit/c482a99717700fd6cf458c67f0497911d588ee96))
* full Kubernetes deployment guide ([5d9f290](https://github.com/hrishikeshdkakkad/fluidbox/commit/5d9f29032ab29de306fac5206eed564dba6d8faa))
* handover rev 4 — design-doc Phase 2 (API triggers + signed callbacks) shipped ([0bea63d](https://github.com/hrishikeshdkakkad/fluidbox/commit/0bea63da84fc2b40056ea7a389012e6c2f78ff57))
* handover rev 5 — design-doc Phase 3 (scheduled borrowing) shipped; §17 [#5](https://github.com/hrishikeshdkakkad/fluidbox/issues/5) settled defaults recorded ([ff53620](https://github.com/hrishikeshdkakkad/fluidbox/commit/ff53620f5c37c791758e3b937dfcda4f3b2f629b))
* handover rev 6 — design-doc Phase 4 shipped (github pr-review fan-out on the connector seam) ([14b9d0f](https://github.com/hrishikeshdkakkad/fluidbox/commit/14b9d0f5f6e33c199aacbd1c60eab3d47a6b4e78))
* **hosted:** incorporate adversarial review round 1 (11 findings) ([4e7f977](https://github.com/hrishikeshdkakkad/fluidbox/commit/4e7f97725e3756640770e9c00142b40d14c8a3b4))
* **hosted:** incorporate adversarial review round 2 (5 findings) ([3faf64f](https://github.com/hrishikeshdkakkad/fluidbox/commit/3faf64f8c6dbc2b68976e69bc4106e17d1215206))
* **hosted:** incorporate adversarial review round 3 (2 findings) ([e388e36](https://github.com/hrishikeshdkakkad/fluidbox/commit/e388e36935b18fa856a9d963c86636b3ab9ae59a))
* **hosted:** incorporate independent fidelity review (3 findings) ([f819c88](https://github.com/hrishikeshdkakkad/fluidbox/commit/f819c886cb58c6c3d3541370a10aca8ffd9420c8))
* **hosted:** Phase A draft — hosted product boundary (matrix, admission policy, network, threat model) ([dbdef99](https://github.com/hrishikeshdkakkad/fluidbox/commit/dbdef990061c1da8d3423828e0898d7c5622e01c))
* **hosted:** rollout gates with checkable exit criteria ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([272780d](https://github.com/hrishikeshdkakkad/fluidbox/commit/272780da6d8231912525213b4352ba4f3d307ac3))
* implementation plan for automation API contract + template clarity ([743915a](https://github.com/hrishikeshdkakkad/fluidbox/commit/743915ab3705f658d2a7eb34b9152d0282039954))
* implementation plan for the five-minute demo + launch clips ([1d4eceb](https://github.com/hrishikeshdkakkad/fluidbox/commit/1d4eceb8872bcdd545aeb0e1521c64e27ef05010))
* independent prime-time red-team assessment (reports only) ([350d5bc](https://github.com/hrishikeshdkakkad/fluidbox/commit/350d5bc7102e2e1fc2772463628773dd733d049a))
* **k8s:** document the residual symlinked-dest hardening as a follow-up (L15) ([5bf8616](https://github.com/hrishikeshdkakkad/fluidbox/commit/5bf861655c6272d9ede0f5827939a65f6e71b78a))
* live EKS acceptance for the Kubernetes-native provider (closes [#48](https://github.com/hrishikeshdkakkad/fluidbox/issues/48)) ([0b111f5](https://github.com/hrishikeshdkakkad/fluidbox/commit/0b111f5746b8a428c04d3e48679ee105150caacc))
* mark the red-team findings superseded by this integration ([acf138a](https://github.com/hrishikeshdkakkad/fluidbox/commit/acf138a86c0b524e44dd14c891f84949c0c72298))
* minimal hatchet-style README — link out, don't inline ([42fcd79](https://github.com/hrishikeshdkakkad/fluidbox/commit/42fcd790b99c99d38aa3f6e067393eedc4cb54b4))
* overnight integration review — four branches, independently verified ([a599d9f](https://github.com/hrishikeshdkakkad/fluidbox/commit/a599d9f8397e8d166e8616a8ce5f177c39b39517))
* Phase 6 codex-harness design (approved) + brief; phase 4 review record ([8b4ba8b](https://github.com/hrishikeshdkakkad/fluidbox/commit/8b4ba8bed6a58bc8750be81dc5c39445b7953193))
* Phase 6 live bring-up + post-ship review round (HANDOVER rev 11) ([3d62e30](https://github.com/hrishikeshdkakkad/fluidbox/commit/3d62e30b373701f7a8a69fe64fdc5e23d050e591))
* Phase B shipped-surface truth pass ([#30](https://github.com/hrishikeshdkakkad/fluidbox/issues/30)) ([4f5b3f1](https://github.com/hrishikeshdkakkad/fluidbox/commit/4f5b3f17549bb913dde857e2e347b6234d9874c3))
* Phase C shipped-surface truth pass ([#31](https://github.com/hrishikeshdkakkad/fluidbox/issues/31)) ([fce603b](https://github.com/hrishikeshdkakkad/fluidbox/commit/fce603b4ba6405595e6a5d21adb534b5bf492c3d))
* Phase D truth pass ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([a1f9451](https://github.com/hrishikeshdkakkad/fluidbox/commit/a1f9451dd732d75eb944e2deb1d3f29bb71e6241))
* Phase E truth pass + handover ([#33](https://github.com/hrishikeshdkakkad/fluidbox/issues/33)) ([0389682](https://github.com/hrishikeshdkakkad/fluidbox/commit/03896827a455370d5022e09d88af4e7ed07bcb64))
* **plans:** identity design v2 — incorporate adversarial round 1 ([90159aa](https://github.com/hrishikeshdkakkad/fluidbox/commit/90159aa515fd7bf7c66283eb668de82ca745ba81))
* **plans:** identity design v3 — incorporate adversarial round 2 ([f9c5a3c](https://github.com/hrishikeshdkakkad/fluidbox/commit/f9c5a3c22f513d51b083d1249b43d6882837473d))
* **plans:** identity design v4 — incorporate adversarial round 3 ([cac79a3](https://github.com/hrishikeshdkakkad/fluidbox/commit/cac79a39b1f9aa976345fb4fe3d16368f1dc5731))
* **plans:** identity design v5 — fix the bootstrap RETURNING defect (review round 4) ([2f3e96a](https://github.com/hrishikeshdkakkad/fluidbox/commit/2f3e96a5512ebfadccf3e58b7748337f5324680d))
* **plans:** k8s design v1.1 — dual-provider permanence (settled Q17) ([a1e170c](https://github.com/hrishikeshdkakkad/fluidbox/commit/a1e170c183fee68f2d2c01ce01e4a1fdc8544d44))
* **plans:** k8s design v1.2 — operator journeys + per-cloud presets incl. DOKS ([173442a](https://github.com/hrishikeshdkakkad/fluidbox/commit/173442a3ba91c1a9b5e8ac6a6fe3ba5be1d8f15d))
* **plans:** kubernetes-native execution provider + Helm deployability design ([cc00f74](https://github.com/hrishikeshdkakkad/fluidbox/commit/cc00f74275a4198942723baac00574994a1f45b7))
* **plans:** multi-user MCP control plane design — FINALIZED v2 ([af07df1](https://github.com/hrishikeshdkakkad/fluidbox/commit/af07df1a87a2feff8794604508355ba86ba322e1))
* **plans:** multi-user MCP v3 — browser-bound OAuth callbacks, 4-state execution claims, missing migrations ([1442ac7](https://github.com/hrishikeshdkakkad/fluidbox/commit/1442ac7c47a84c96758a12ef9e4e21d6e4d73e69))
* **plans:** multi-user v4 re-baseline + IdP-agnostic identity companion design ([9a4803c](https://github.com/hrishikeshdkakkad/fluidbox/commit/9a4803c07732de309cf99c9df08c7089ebeb6fe7))
* **plans:** public site + docs platform + WorkOS /app boundary design ([69c24e4](https://github.com/hrishikeshdkakkad/fluidbox/commit/69c24e4b1ebaf2115e9ac6d5028754ea593740ec))
* **policies:** close the live-agent gap — real run proves the governance loop ([034d950](https://github.com/hrishikeshdkakkad/fluidbox/commit/034d9507ced64c912b0f90aed8c62b0eee7350fc))
* **policies:** correct two errors in my own validation output ([734a069](https://github.com/hrishikeshdkakkad/fluidbox/commit/734a069ac0c9e9479ac8242bf8d13d635b112ee4))
* **policies:** design DB-native policies — versioned storage + structured authoring ([d1587d4](https://github.com/hrishikeshdkakkad/fluidbox/commit/d1587d49aa4b318d0558c0a1c39c7e1324d6b3e5))
* **policies:** prove the governance loop on Kubernetes too, and explain the EKS 503 ([d59eed0](https://github.com/hrishikeshdkakkad/fluidbox/commit/d59eed05fe76ba5fc516308aa6b351cf42a3dc99))
* **policies:** route every unfixed finding to a tracking item ([1289de0](https://github.com/hrishikeshdkakkad/fluidbox/commit/1289de0889da652166a16bda5944e716858ab0b9))
* **policies:** run the loop on REAL EKS; correct my own EKS 503 explanation ([ad4b46c](https://github.com/hrishikeshdkakkad/fluidbox/commit/ad4b46c65da6dadb4b2257992848daeeb1cd6175))
* **policies:** two-environment validation report + correct the upgrade guidance ([57d9e56](https://github.com/hrishikeshdkakkad/fluidbox/commit/57d9e566205eddbaa531c3b4711260f1ae7df7d1))
* professional open-source pass — community health files, templates, metadata ([8911ce7](https://github.com/hrishikeshdkakkad/fluidbox/commit/8911ce7d2ad05d2686700e02e51458375d71adfe))
* **readme:** lead with the product film instead of a still ([1e685f0](https://github.com/hrishikeshdkakkad/fluidbox/commit/1e685f0a7f5d5368db9acf1599ed363e0c37347f))
* **readme:** lead with the product film instead of a still ([7b265e1](https://github.com/hrishikeshdkakkad/fluidbox/commit/7b265e10c289dd124fc158ef9ec43afaeb626ae3))
* **readme:** raise the product film above the fold ([cdd451e](https://github.com/hrishikeshdkakkad/fluidbox/commit/cdd451e0057a787375cd52f8f2d93ff09039ec7e))
* **readme:** raise the product film above the fold ([a6db726](https://github.com/hrishikeshdkakkad/fluidbox/commit/a6db72695d9fdab2e67cadabfcc3c2e67f32dcec))
* record Step 5 review resolution (ACCEPT after 3 passes) ([6098100](https://github.com/hrishikeshdkakkad/fluidbox/commit/60981006ba9fa29d257696452a89be1341965ebd))
* reframe README around the agent control plane ([#70](https://github.com/hrishikeshdkakkad/fluidbox/issues/70)) ([8a08932](https://github.com/hrishikeshdkakkad/fluidbox/commit/8a08932f7ee34019d25f88e3fba0df9760e48e34))
* **release:** claims matrix, compatibility matrix, upgrade guide, beta package ([a5c45ab](https://github.com/hrishikeshdkakkad/fluidbox/commit/a5c45ab02960ab70d342f1387052a7df0705ea4f))
* **release:** correct the commit inventory in the readiness report ([6dada56](https://github.com/hrishikeshdkakkad/fluidbox/commit/6dada56e30ecac45eee87c8315ce0a44d01050c1))
* **release:** Linux/amd64 is validated for CI-executed paths ([4c9c0aa](https://github.com/hrishikeshdkakkad/fluidbox/commit/4c9c0aa144d9797fd3bb0a9696d9bed814acf436))
* **release:** pin the next release to 0.4.0 and explain why ([#116](https://github.com/hrishikeshdkakkad/fluidbox/issues/116)) ([f9a7e51](https://github.com/hrishikeshdkakkad/fluidbox/commit/f9a7e514ece913f5274c92ff5b7337d0f1ca13b8))
* **release:** v0.1.0 changelog + dashboard screenshot in the README ([d28e99d](https://github.com/hrishikeshdkakkad/fluidbox/commit/d28e99d396e612b3898e4eae70c56d016aa1e0b1))
* **review:** adversarial verification of the RC readiness report ([34c4edb](https://github.com/hrishikeshdkakkad/fluidbox/commit/34c4edbe8d80206bcfc29889c5e16723790f002f))
* revise automation-contract plan per external review (rev 2) ([3f97d6e](https://github.com/hrishikeshdkakkad/fluidbox/commit/3f97d6e0c48f7ef362456f2ba1157a2a25a153a1))
* **rls:** document the runtime-role posture gates, bypass opt-out, and audit tenant floor ([#32](https://github.com/hrishikeshdkakkad/fluidbox/issues/32)) ([adb2baf](https://github.com/hrishikeshdkakkad/fluidbox/commit/adb2baf1b20d812031fa8481d80bc1e243cc7888))
* spec for durable automation API contract + template clarity ([e57558a](https://github.com/hrishikeshdkakkad/fluidbox/commit/e57558ad933c9aa498efd633ed43ff6d448d4211))
* surface just demo as the no-key first-run path ([c632b25](https://github.com/hrishikeshdkakkad/fluidbox/commit/c632b250b0824ef42b117c8d145b5c80134b9aee))
* **threat-model:** two Phase F residuals narrowed, honestly ([#34](https://github.com/hrishikeshdkakkad/fluidbox/issues/34)) ([94731b5](https://github.com/hrishikeshdkakkad/fluidbox/commit/94731b51351a421b44b6d02049f823d6e4510825))
* update multi-user release README ([c222a8f](https://github.com/hrishikeshdkakkad/fluidbox/commit/c222a8f309d15fd7f8d8b5fe4a902d29bd4e1984))
* **web:** run-composer pickers — unleak connections, one card vocabulary, working + new ([#42](https://github.com/hrishikeshdkakkad/fluidbox/issues/42)) ([fbace15](https://github.com/hrishikeshdkakkad/fluidbox/commit/fbace15dbe22af6aa9ab058a4f55afc4abc90d23))

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
- **Hardening series** — all 30 findings (5 High / 10 Medium / 15 Low) from a three-round joint review of the epic fixed or explicitly dispositioned (`docs/reviews/2026-07-16-pr47-k8s-review-findings.md`): symlink-safe extraction with `canonicalize` as the sole containment authority, integrity-checked exec collection with resume, dual-listener isolation (no `/internal` on the public plane under K8s), UID-guarded deletes, quiesce replay, and more.
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
