import { Component, useEffect, useMemo, useState, type ReactNode } from "react";

import { listEngagements } from "./lib/api";
import type { Engagement } from "./lib/api";
import { EngagementPage } from "./routes/EngagementPage";
import { EngagementsPage } from "./routes/EngagementsPage";
import { RemediationPage } from "./routes/RemediationPage";
import { parseRunAuditQuery } from "./lib/runAudit";
import { engagementHref, parseWorkspaceRoute, positiveRouteId, remediationHref, writeWorkspaceHash } from "./lib/workspaceRoutes";

function currentRoute(): string {
  const hashRoute = window.location.hash.replace(/^#/, "");
  return hashRoute || "/engagements";
}

type EngagementRoute = {
  engagementKey: string;
  initialTab?: string;
  initialFindingSlug?: string;
  initialDrawerTab?: string;
  initialIntelType?: string;
  initialIntelId?: number;
  initialRequestVariantId?: number;
  initialRunId?: number;
  initialRunSection?: string;
  initialRunObject?: string;
};

// Hash scheme: #/engagements/{key}?tab={tabKey}&finding={slug}&dtab={drawerTab},
// #/engagements/{key}?tab=intel&intel_type={type}&intel_id={id},
// or #/engagements/{key}?tab=runs&run={id}&section={childKind}&object={id}.
// Explicit selections push canonical history; hashchange and popstate restore
// the same record and section when the operator returns.
function parseEngagementRoute(route: string): EngagementRoute | null {
  const parsed = parseWorkspaceRoute(route);
  if (parsed.kind !== "engagement") return null;
  const engagementKey = parsed.key;
  const params = parsed.params;
  const initialTab = params.get("tab") ?? undefined;
  const initialFindingSlug = params.get("finding") ?? undefined;
  const initialDrawerTab = params.get("dtab") ?? undefined;
  const initialIntelType = params.get("intel_type") ?? undefined;
  const initialIntelId = positiveRouteId(params, "intel_id");
  const initialRequestVariantId = positiveRouteId(params, "request");
  const runAudit = parseRunAuditQuery(params);
  return {
    engagementKey,
    initialTab,
    initialFindingSlug,
    initialDrawerTab,
    initialIntelType,
    initialIntelId,
    initialRequestVariantId,
    initialRunId: runAudit.runId,
    initialRunSection: runAudit.section,
    initialRunObject: runAudit.object,
  };
}

function navigate(route: string) {
  writeWorkspaceHash(route.startsWith("#") ? route : `#${route}`);
}

export default function App() {
  return <InterfaceBoundary><AppContent /></InterfaceBoundary>;
}

class InterfaceBoundary extends Component<{ children: ReactNode }, { error: string | null }> {
  state = { error: null as string | null };

  static getDerivedStateFromError(error: unknown): { error: string } {
    return { error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) };
  }

  render() {
    if (this.state.error !== null) {
      return (
        <main className="shell">
          <section className="panel empty-state" role="alert">
            <h1>Interface could not load</h1>
            <p>Reload to load the current interface. If the error continues, retain the technical message below for diagnosis.</p>
            <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{this.state.error}</pre>
            <button type="button" className="ghost-button" onClick={() => window.location.reload()}>Reload interface</button>
          </section>
        </main>
      );
    }
    return this.props.children;
  }
}

function AppContent() {
  const [route, setRoute] = useState(currentRoute());
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [engagementsError, setEngagementsError] = useState<string | null>(null);
  // True until the first listing resolves, so cold load shows a skeleton
  // instead of the "no engagements" empty state.
  const [engagementsLoading, setEngagementsLoading] = useState(true);
  const engagementRoute = useMemo(() => parseEngagementRoute(route), [route]);
  const parsedRoute = useMemo(() => parseWorkspaceRoute(route), [route]);
  const remediationKey = parsedRoute.kind === "remediation" ? parsedRoute.key : null;
  const requestedCaseId = parsedRoute.kind === "remediation" ? positiveRouteId(parsedRoute.params, "case") : undefined;

  useEffect(() => {
    const handler = () => setRoute(currentRoute());
    window.addEventListener("hashchange", handler);
    window.addEventListener("popstate", handler);
    return () => { window.removeEventListener("hashchange", handler); window.removeEventListener("popstate", handler); };
  }, []);

  useEffect(() => {
    if (parsedRoute.kind !== "index") {
      return;
    }

    let cancelled = false;
    let refreshing = false;

    async function refreshEngagements() {
      if (refreshing) {
        return;
      }
      refreshing = true;
      try {
        const nextEngagements = await listEngagements();
        if (!cancelled) {
          setEngagements(nextEngagements);
          setEngagementsError(null);
        }
      } catch (error) {
        if (!cancelled) {
          setEngagementsError(
            error instanceof Error ? error.message : "Failed to load engagements",
          );
        }
      } finally {
        refreshing = false;
        if (!cancelled) {
          setEngagementsLoading(false);
        }
      }
    }

    void refreshEngagements();
    const interval = window.setInterval(() => {
      if (document.hidden) {
        return;
      }
      void refreshEngagements();
    }, 5000);

    const handleVisibilityChange = () => {
      if (!document.hidden) {
        void refreshEngagements();
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [parsedRoute.kind]);

  if (parsedRoute.kind === "invalid") {
    return <main className="shell"><section className="panel empty-state" role="alert"><h1>Workspace not found</h1><p>The address does not identify a Vigil workspace.</p><a href="#/engagements">Open engagements</a></section></main>;
  }

  if (remediationKey) {
    return <RemediationPage engagementKey={remediationKey} initialCaseId={requestedCaseId} onBack={() => navigate("/engagements")} />;
  }

  if (engagementRoute) {
    return (
      <EngagementPage
        key={engagementRoute.engagementKey}
        engagementKey={engagementRoute.engagementKey}
        initialTab={engagementRoute.initialTab}
        initialFindingSlug={engagementRoute.initialFindingSlug}
        initialDrawerTab={engagementRoute.initialDrawerTab}
        initialIntelType={engagementRoute.initialIntelType}
        initialIntelId={engagementRoute.initialIntelId}
        initialRequestVariantId={engagementRoute.initialRequestVariantId}
        initialRunId={engagementRoute.initialRunId}
        initialRunSection={engagementRoute.initialRunSection}
        initialRunObject={engagementRoute.initialRunObject}
        onBack={() => navigate("/engagements")}
      />
    );
  }

  return (
    <EngagementsPage
      engagements={engagements}
      loading={engagementsLoading}
      loadError={engagementsError}
      onOpenEngagement={(engagementKey) => {
        const engagement = engagements.find((item) => item.key === engagementKey);
        navigate(engagement?.engagement_type === "remediation" ? remediationHref(engagementKey) : engagementHref(engagementKey));
      }}
      onEngagementDeleted={(engagementKey) => {
        setEngagements((current) => current.filter((engagement) => engagement.key !== engagementKey));
      }}
    />
  );
}
