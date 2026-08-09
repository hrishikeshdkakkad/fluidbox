import type { Metadata } from "next";
import { PageEcho } from "../components/PageEcho";
import Link from "next/link";

const REPO = "https://github.com/hrishikeshdkakkad/fluidbox";

export const metadata: Metadata = {
  title: "Pricing",
  description:
    "fluidbox is MIT-licensed and free to self-host — every capability, no held-back core. A hosted offering is in early access; there is no price list to show you yet, and we won't invent one.",
  alternates: { canonical: "/pricing" },
};

export default function PricingPage() {
  return (
    <div className="st">
      <section className="site-container site-section tight">
      <PageEcho en="pricing" es="precios" jp="価格" sc="价格" />
      <h1 className="site-h2" style={{ maxWidth: 700 }}>
        The control plane is free. Someone operating it for you is what will
        cost money.
      </h1>
      <p className="site-lead">
        No invented tiers, no &quot;contact sales&quot; theater. Two honest
        options today:
      </p>

      <div className="pricing">
        <div className="price-card">
          <div className="price-name">Open source</div>
          <div className="price-amount">$0 · MIT license</div>
          <p className="price-desc">
            The whole product, self-hosted on your infrastructure. Not a
            community edition — there is no other edition.
          </p>
          <ul className="price-list">
            <li>Every capability: gate, approvals, budgets, ledger, triggers, both harnesses</li>
            <li>Docker eval stack and the production Helm chart</li>
            <li>Multi-user posture (SSO, tenancy, KMS sealing) behind explicit flags</li>
            <li>Security fixes on latest main; public roadmap and design doc</li>
          </ul>
          <div className="hero-ctas">
            <Link className="btn primary" href="/docs/getting-started">
              Get started
            </Link>
            <a className="btn ghost" href={REPO} target="_blank" rel="noreferrer">
              GitHub ↗
            </a>
          </div>
        </div>

        <div className="price-card">
          <div className="price-name">Hosted</div>
          <div className="price-amount">early access · no price list yet</div>
          <p className="price-desc">
            The same open control plane, operated for you. In development — the
            hosted posture ships in the repository behind documented rollout
            gates, and it isn&apos;t for sale until those gates pass.
          </p>
          <ul className="price-list">
            <li>Same code you can read today — no proprietary fork</li>
            <li>Per-organization SSO, tenant isolation, key custody operated for you</li>
            <li>Honest status: capacity and residual-risk sign-off are published gates, not promises</li>
          </ul>
          <div className="hero-ctas">
            <a
              className="btn"
              href={`${REPO}/issues`}
              target="_blank"
              rel="noreferrer"
            >
              Register interest on GitHub ↗
            </a>
          </div>
        </div>
      </div>

      <p className="try-note" style={{ marginTop: 28 }}>
        What &quot;hosted-ready&quot; means, precisely:{" "}
        <a href={`${REPO}/blob/main/docs/hosted/rollout-gates.md`} target="_blank" rel="noreferrer">
          the rollout gates ↗
        </a>
        .
      </p>
      </section>
    </div>
  );
}
