import { useEffect, useMemo, useState } from "react";

import { listEngagements } from "./lib/api";
import type { Engagement } from "./lib/api";
import { EngagementPage } from "./routes/EngagementPage";
import { EngagementsPage } from "./routes/EngagementsPage";
import { parseRunAuditQuery } from "./lib/runAudit";

function currentRoute(): string {
  const hashRoute = window.location.hash.replace(/^#/, "");
  return hashRoute || "/engagements";
}

type EngagementRoute = {
  engagementKey: string;
  initialTab?: string;
  initialFindingSlug?: string;
  initialDrawerTab?: string;
  initialRunId?: number;
  initialRunSection?: string;
  initialRunObject?: string;
};

// Hash scheme: #/engagements/{key}?tab={tabKey}&finding={slug}&dtab={drawerTab}
// or #/engagements/{key}?tab=runs&run={id}&section={childKind}&object={id}.
// The `?query` tail, when present, is split off before decoding the key so
// deep-link params don't get folded into it. FindingsTab rewrites these via
// history.replaceState as the drawer opens/closes; replaceState doesn't emit
// `hashchange`, so the listener below never re-routes on a self-write.
function parseEngagementRoute(route: string): EngagementRoute | null {
  const match = route.match(/^\/engagements\/([^?]+)(?:\?(.*))?$/);
  if (!match) {
    return null;
  }
  const engagementKey = decodeURIComponent(match[1]);
  const params = new URLSearchParams(match[2] ?? "");
  const initialTab = params.get("tab") ?? undefined;
  const initialFindingSlug = params.get("finding") ?? undefined;
  const initialDrawerTab = params.get("dtab") ?? undefined;
  const runAudit = parseRunAuditQuery(params);
  return {
    engagementKey,
    initialTab,
    initialFindingSlug,
    initialDrawerTab,
    initialRunId: runAudit.runId,
    initialRunSection: runAudit.section,
    initialRunObject: runAudit.object,
  };
}

function navigate(route: string) {
  window.location.hash = route;
}

export default function App() {
  const [route, setRoute] = useState(currentRoute());
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [engagementsError, setEngagementsError] = useState<string | null>(null);
  // True until the first listing resolves, so cold load shows a skeleton
  // instead of the "no engagements" empty state.
  const [engagementsLoading, setEngagementsLoading] = useState(true);
  const engagementRoute = useMemo(() => parseEngagementRoute(route), [route]);
  const engagementKey = engagementRoute?.engagementKey ?? null;

  useEffect(() => {
    const handler = () => setRoute(currentRoute());
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);

  useEffect(() => {
    if (engagementKey) {
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
  }, [engagementKey]);

  if (engagementRoute) {
    return (
      <EngagementPage
        engagementKey={engagementRoute.engagementKey}
        initialTab={engagementRoute.initialTab}
        initialFindingSlug={engagementRoute.initialFindingSlug}
        initialDrawerTab={engagementRoute.initialDrawerTab}
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
      onOpenEngagement={(engagementKey) => navigate(`/engagements/${encodeURIComponent(engagementKey)}`)}
      onEngagementDeleted={(engagementKey) => {
        setEngagements((current) => current.filter((engagement) => engagement.key !== engagementKey));
      }}
    />
  );
}
