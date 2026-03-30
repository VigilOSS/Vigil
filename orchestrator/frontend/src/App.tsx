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

  useEffect(() => {
    const handler = () => setRoute(currentRoute());
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function refreshEngagements() {
      const nextEngagements = await listEngagements();
      if (cancelled) return;
      setEngagements(nextEngagements);
    }

    void refreshEngagements();
    const interval = window.setInterval(() => {
      void refreshEngagements();
    }, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const engagementRoute = useMemo(() => parseEngagementRoute(route), [route]);

  if (engagementRoute) {
    return <EngagementPage engagementKey={engagementRoute} onBack={() => navigate("/engagements")} />;
  }

  return <EngagementsPage engagements={engagements} onOpenEngagement={(engagementKey) => navigate(`/engagements/${encodeURIComponent(engagementKey)}`)} />;
}
