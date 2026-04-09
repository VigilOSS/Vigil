import { useEffect, useMemo, useState } from "react";

import { listEngagements } from "./lib/api";
import type { Engagement } from "./lib/api";
import { EngagementPage } from "./routes/EngagementPage";
import { EngagementsPage } from "./routes/EngagementsPage";

function currentRoute(): string {
  const hashRoute = window.location.hash.replace(/^#/, "");
  return hashRoute || "/engagements";
}

function parseEngagementRoute(route: string): string | null {
  const match = route.match(/^\/engagements\/(.+)$/);
  if (!match) {
    return null;
  }
  return decodeURIComponent(match[1]);
}

function navigate(route: string) {
  window.location.hash = route;
}

export default function App() {
  const [route, setRoute] = useState(currentRoute());
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const engagementRoute = useMemo(() => parseEngagementRoute(route), [route]);

  useEffect(() => {
    const handler = () => setRoute(currentRoute());
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);

  useEffect(() => {
    if (engagementRoute) {
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
        }
      } finally {
        refreshing = false;
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
  }, [engagementRoute]);

  if (engagementRoute) {
    return <EngagementPage engagementKey={engagementRoute} onBack={() => navigate("/engagements")} />;
  }

  return <EngagementsPage engagements={engagements} onOpenEngagement={(engagementKey) => navigate(`/engagements/${encodeURIComponent(engagementKey)}`)} />;
}
