import type { Metadata } from "next";
import { RELEASES } from "../docs/generated/changelog";
import { MarkdownView } from "../docs/MarkdownView";

export const metadata: Metadata = {
  title: "Changelog",
  description:
    "Every notable, user-visible fluidbox change — generated from the repository's CHANGELOG.md, releases and unreleased work alike.",
  alternates: { canonical: "/changelog" },
};

// Rendered from CHANGELOG.md via the docs sync (just docs-sync) — one source
// of truth, same as the docs. Author there, never here.
export default function ChangelogPage() {
  return (
    <div className="st">
      <section className="site-container site-section tight">
      <div className="site-kicker">changelog</div>
      <h1 className="site-h2">What shipped, when, and why.</h1>
      <p className="site-lead">
        Generated from the repository&apos;s{" "}
        <a
          href="https://github.com/hrishikeshdkakkad/fluidbox/blob/main/CHANGELOG.md"
          target="_blank"
          rel="noreferrer"
        >
          CHANGELOG.md
        </a>
        . Versions follow SemVer; entries follow Keep a Changelog.
      </p>

      <div style={{ marginTop: 24 }}>
        {RELEASES.map((release) => (
          <article className="cl-entry" key={release.version}>
            <div className="cl-rail">
              <div className="cl-version">
                {release.version === "Unreleased" ? "Unreleased" : `v${release.version}`}
              </div>
              {release.date && <div className="cl-date">{release.date}</div>}
            </div>
            <div className="cl-body">
              <MarkdownView md={release.md} />
            </div>
          </article>
        ))}
      </div>
      </section>
    </div>
  );
}
