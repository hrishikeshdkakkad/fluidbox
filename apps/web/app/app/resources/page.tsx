"use client";

import { useState } from "react";
import { ResourceOverview } from "../../components/ResourceOverview";
import { RunComposer } from "../../components/RunComposer";
import { PageHead } from "../../components/bits";
import { AddServerWizard } from "../capabilities/AddServerWizard";

// The resources workbench (2026-08-14 navigation-boundary design): the index
// of agents, MCP servers, and integrations as a real place — what the
// masthead's `resources` points at and what agents/capabilities/integrations
// breadcrumb back to. ResourceOverview is the same component Overview embeds,
// so the two surfaces cannot drift; Overview stays the summary.
export default function ResourcesPage() {
  const [agentComposer, setAgentComposer] = useState(false);
  const [showCapabilityWizard, setShowCapabilityWizard] = useState(false);
  const [resourceRefresh, setResourceRefresh] = useState(0);

  return (
    <>
      <PageHead
        title="Resources"
        sub="The agents, MCP servers, and integrations every run draws from."
      />
      {/* Standalone framing: the page header above already says "resources",
          so the shared section's own h2/p are hidden here (globals.css
          .resources-standalone) and only the readiness chip survives. */}
      <div className="resources-standalone">
        <ResourceOverview
          refreshKey={resourceRefresh}
          onCreateAgent={() => setAgentComposer(true)}
          onAddCapability={() => setShowCapabilityWizard(true)}
        />
      </div>
      {agentComposer && (
        <RunComposer
          agentOnly
          onClose={() => setAgentComposer(false)}
          onRunCreated={() => {}}
          onAutomationCreated={() => {}}
          onAgentCreated={() => {
            setAgentComposer(false);
            setResourceRefresh((current) => current + 1);
          }}
        />
      )}
      {showCapabilityWizard && (
        <AddServerWizard
          onClose={() => {
            setShowCapabilityWizard(false);
            setResourceRefresh((current) => current + 1);
          }}
        />
      )}
    </>
  );
}
