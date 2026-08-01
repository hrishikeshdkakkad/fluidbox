"use client";

// Recipes — the enterprise catalog (design
// docs/plans/2026-07-31-enterprise-recipes-design.md §8). Two tabs:
//   Catalog      curated + custom templates, grouped by category, searchable,
//                with an honest per-card manifest (agents, triggers, cost
//                ceiling) and a "ready" signal from the tenant's connections.
//   Deployments  the tenant's instances with status + update-available.
// Presentation-only: every fact on a card is server-derived (facets), and the
// ready signal only shapes emphasis — the deploy wizard revalidates on the
// server either way.

import { Suspense, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Search } from "lucide-react";
import { apiGet, apiGetCached, Connection } from "../../lib/api";
import { LoadingRows, PageHead, Pill, timeAgo } from "../../components/bits";
import {
  cardMatches,
  groupByCategory,
  recipeReady,
  triggerLabel,
  type RecipeCard,
  type RecipeInstanceListEntry,
} from "../../lib/recipes";
import { useSmartPolling } from "../../lib/useSmartPolling";

type Tab = "catalog" | "deployments";

export default function RecipesPage() {
  return (
    <Suspense fallback={null}>
      <Recipes />
    </Suspense>
  );
}

function Recipes() {
  const router = useRouter();
  const search = useSearchParams();
  const tab: Tab = search.get("tab") === "deployments" ? "deployments" : "catalog";

  const [cards, setCards] = useState<RecipeCard[] | null>(null);
  const [instances, setInstances] = useState<RecipeInstanceListEntry[] | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loadErr, setLoadErr] = useState("");
  const [query, setQuery] = useState("");

  const load = useCallback(async () => {
    const [recipes, insts, conns] = await Promise.allSettled([
      apiGet<{ recipes: RecipeCard[] }>("/recipes"),
      apiGet<{ instances: RecipeInstanceListEntry[] }>("/recipes/instances"),
      apiGetCached<{ connections: Connection[] }>("/connections", { maxAgeMs: 15000 }),
    ]);
    if (recipes.status === "fulfilled") {
      setCards(recipes.value.recipes);
      setLoadErr("");
    } else if (cards === null) {
      setLoadErr(String(recipes.reason?.message ?? recipes.reason));
    }
    if (insts.status === "fulfilled") setInstances(insts.value.instances);
    if (conns.status === "fulfilled") setConnections(conns.value.connections ?? []);
    // Keep the last good snapshot on partial failure — the app-wide pattern.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useSmartPolling(load, 8000);
  useEffect(() => {
    void load();
  }, [load]);

  const setTab = (t: Tab) =>
    router.replace(t === "catalog" ? "/app/recipes" : "/app/recipes?tab=deployments");

  const deployedCount = instances?.length ?? 0;

  return (
    <>
      <PageHead
        title="Recipes"
        sub="Opinionated, versioned templates that deploy governed agent workloads in a few clicks."
      />
      <div className="tabs" role="tablist">
        <button
          role="tab"
          aria-selected={tab === "catalog"}
          className={`tab ${tab === "catalog" ? "active" : ""}`}
          onClick={() => setTab("catalog")}
        >
          Catalog {cards ? <span className="n">{cards.length}</span> : null}
        </button>
        <button
          role="tab"
          aria-selected={tab === "deployments"}
          className={`tab ${tab === "deployments" ? "active" : ""}`}
          onClick={() => setTab("deployments")}
        >
          Deployments {instances ? <span className="n">{deployedCount}</span> : null}
        </button>
      </div>

      {loadErr && cards === null ? (
        <div className="launch-empty">
          <p>Could not load the recipe catalog.</p>
          <p className="err">{loadErr}</p>
          <button className="btn" onClick={() => void load()}>
            Retry
          </button>
        </div>
      ) : tab === "catalog" ? (
        <Catalog
          cards={cards}
          connections={connections}
          query={query}
          setQuery={setQuery}
        />
      ) : (
        <Deployments entries={instances} />
      )}
    </>
  );
}

function Catalog({
  cards,
  connections,
  query,
  setQuery,
}: {
  cards: RecipeCard[] | null;
  connections: Connection[];
  query: string;
  setQuery: (q: string) => void;
}) {
  if (cards === null) return <LoadingRows rows={3} />;
  const visible = cards.filter((c) => cardMatches(c, query));
  const groups = groupByCategory(visible);
  return (
    <>
      <div className="search recipe-search">
        <Search size={14} aria-hidden />
        <input
          className="inp"
          placeholder="Search recipes — try “review”, “compliance”, or an integration"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search recipes"
        />
      </div>
      {visible.length === 0 ? (
        <div className="empty">No recipes match “{query}”.</div>
      ) : (
        groups.map(([category, list]) => (
          <section key={category} className="recipe-section">
            <h2 className="sectitle">{categoryLabel(category)}</h2>
            <div className="recipe-grid">
              {list.map((card) => (
                <RecipeCardView
                  key={card.slug}
                  card={card}
                  ready={recipeReady(card.facets, connections)}
                />
              ))}
            </div>
          </section>
        ))
      )}
    </>
  );
}

function categoryLabel(c: string): string {
  const known: Record<string, string> = {
    "code-review": "Code review",
    "ci-cd": "CI / CD",
    compliance: "Compliance",
    support: "Support",
    onboarding: "Onboarding & docs",
    general: "General",
  };
  return known[c] ?? c;
}

function RecipeCardView({ card, ready }: { card: RecipeCard; ready: boolean }) {
  const f = card.facets;
  return (
    <Link href={`/app/recipes/${card.slug}`} className="recipe-card" prefetch={false}>
      <div className="recipe-card-head">
        <span className={`recipe-mark recipe-mark-${card.icon}`} aria-hidden>
          {card.name.slice(0, 1)}
        </span>
        <div className="recipe-card-title">
          <h3>{card.name}</h3>
          <p>{card.tagline}</p>
        </div>
        {card.tier === "official" ? (
          <span className="badge brand">Official</span>
        ) : (
          <span className="badge">Custom</span>
        )}
      </div>
      <div className="chips recipe-card-chips">
        {f.trigger_kinds.map((k) => (
          <span key={k} className="chip">
            {triggerLabel(k)}
          </span>
        ))}
        {f.multi_agent && <span className="chip">{f.agent_count} agents</span>}
      </div>
      <div className="recipe-card-foot">
        <span className="helper">
          ≤ ${f.cost_ceiling_usd.toFixed(2)} per run{f.multi_agent ? " (all agents)" : ""}
        </span>
        {ready ? (
          <span className="badge ok">Ready to deploy</span>
        ) : f.connectors.some((c) => c.required) ? (
          <span className="badge warn">Needs a connection</span>
        ) : null}
      </div>
    </Link>
  );
}

function Deployments({ entries }: { entries: RecipeInstanceListEntry[] | null }) {
  if (entries === null) return <LoadingRows rows={3} />;
  if (entries.length === 0) {
    return (
      <div className="launch-empty">
        <p>Nothing deployed yet.</p>
        <p className="helper">
          Pick a recipe from the catalog — a deploy stamps the agents, policy, and
          triggers for you.
        </p>
        <Link className="btn primary" href="/app/recipes">
          Browse the catalog
        </Link>
      </div>
    );
  }
  return (
    <div className="rows">
      <div className="row thead recipe-row">
        <span>Deployment</span>
        <span>Recipe</span>
        <span>Status</span>
        <span>Version</span>
        <span>Created</span>
      </div>
      {entries.map(({ instance, update_available, latest_version }) => (
        <Link
          key={instance.id}
          href={`/app/recipes/instances/${instance.id}`}
          className="row recipe-row"
          prefetch={false}
        >
          <span className="t">{instance.name}</span>
          <span className="helper">{instance.recipe_slug}</span>
          <span>
            <Pill status={instance.status} />
          </span>
          <span className="helper">
            v{instance.recipe_version}
            {update_available && (
              <span className="badge warn" style={{ marginLeft: 8 }}>
                v{latest_version} available
              </span>
            )}
          </span>
          <span className="helper">{timeAgo(instance.created_at)}</span>
        </Link>
      ))}
    </div>
  );
}
