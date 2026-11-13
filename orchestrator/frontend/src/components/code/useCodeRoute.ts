// The Code view's state lives in the URL (`?tab=code&view=…`), so a section,
// a focused repository (`repo`) or table (`focus`), the review queue's lead
// list (`leads`, `kind`), the file list's filters (`risk`, `tags`), the
// results' scope and filters, and an open result (`result`, `dtab`) can be
// deep-linked, and Back/Forward restore them. `q` and `page` belong to the
// list of the section shown: the file list on Files, the leads on Review
// queue, the results on Results.

import { useCallback, useEffect, useMemo, useState } from "react";

import { engagementHref, parseWorkspaceRoute, positiveRouteId, writeWorkspaceHash } from "../../lib/workspaceRoutes";
import type { CodeView } from "./codeLabels";

export const CODE_VIEWS: CodeView[] = ["overview", "repositories", "queue", "files", "results", "quality", "modules"];

/** Results scope: every current result, or only those that need a verdict ("Needs attention"). */
export type CodeResultsScope = "all" | "attention";

/** A table on the Files view to scroll to and mark: the risk table or the direct-read list. */
export type CodeFilesFocus = "risk" | "direct";

/**
 * The file list narrowed by what the classification recorded for context
 * tags: none at all, or the `client-bundle` tag (the files whose server-only
 * families are optional).
 */
export type CodeFileTags = "unrecorded" | "client-bundle";
const CODE_FILE_TAGS: readonly CodeFileTags[] = ["unrecorded", "client-bundle"];

/** Why a review left a lead: data flowing into another file, or a family closed below its depth floor. */
export type CodeLeadKind = "cross_file" | "depth_floor";
export const CODE_LEAD_KINDS: readonly CodeLeadKind[] = ["cross_file", "depth_floor"];

export type CodeRouteTarget = {
  view: CodeView;
  repo?: number;
  focus?: CodeFilesFocus;
  /** The review queue's lead list: the lead status shown (`pending` is the default and omitted). */
  leads?: string;
  /** The review queue's lead list narrowed to one kind. */
  kind?: CodeLeadKind;
  /** The file list narrowed to one risk tier. */
  risk?: string;
  /** The file list narrowed by recorded context tags. */
  tags?: CodeFileTags;
  scope?: CodeResultsScope;
  disposition?: string[];
  confidence?: string[];
  workflow?: string[];
  /** The shown list's search: results search, or the file list's path filter. */
  q?: string;
  /** 1-based page of the shown list (results, files or leads); 1 is omitted from the URL. */
  page?: number;
  /** Open analysis result. */
  result?: number;
  /** Open result's section. */
  dtab?: string;
};

function routeParams(engagementKey: string): URLSearchParams {
  const route = parseWorkspaceRoute(window.location.hash);
  return route.kind === "engagement" && route.key === engagementKey ? route.params : new URLSearchParams();
}

const list = (values: string[] | undefined) => (values && values.length > 0 ? values.join(",") : undefined);

export function codeViewHref(engagementKey: string, target: CodeRouteTarget): string {
  return engagementHref(engagementKey, {
    tab: "code",
    view: target.view === "overview" ? undefined : target.view,
    repo: target.repo,
    focus: target.focus,
    leads: target.leads && target.leads !== "pending" ? target.leads : undefined,
    kind: target.kind,
    risk: target.risk,
    tags: target.tags,
    scope: target.scope === "attention" ? "attention" : undefined,
    disposition: list(target.disposition),
    confidence: list(target.confidence),
    workflow: list(target.workflow),
    q: target.q?.trim() || undefined,
    page: target.page && target.page > 1 ? target.page : undefined,
    result: target.result,
    dtab: target.result != null ? target.dtab : undefined,
  });
}

function splitList(value: string | null): string[] {
  return (value ?? "").split(",").map((entry) => entry.trim()).filter(Boolean);
}

export type CodeRoute = ReturnType<typeof useCodeRoute>;

export function useCodeRoute(engagementKey: string) {
  const [params, setParams] = useState(() => routeParams(engagementKey));

  useEffect(() => {
    const sync = () => setParams(routeParams(engagementKey));
    sync();
    window.addEventListener("hashchange", sync);
    window.addEventListener("popstate", sync);
    return () => {
      window.removeEventListener("hashchange", sync);
      window.removeEventListener("popstate", sync);
    };
  }, [engagementKey]);

  const navigate = useCallback(
    (target: CodeRouteTarget, mode: "push" | "replace" = "push") =>
      writeWorkspaceHash(codeViewHref(engagementKey, target), mode),
    [engagementKey],
  );
  // Parsed once per URL change, so list values keep their identity between renders.
  const parsed = useMemo(() => {
    const requested = params.get("view");
    const focus = params.get("focus");
    const kind = params.get("kind");
    return {
      view: (CODE_VIEWS.includes(requested as CodeView) ? requested : "overview") as CodeView,
      repo: positiveRouteId(params, "repo"),
      // A `repo` value that is not a repository number names no repository;
      // the views that read `repo` report it instead of quietly dropping it.
      repoUnreadable: positiveRouteId(params, "repo") === undefined ? params.get("repo") || null : null,
      focus: focus === "risk" || focus === "direct" ? (focus as CodeFilesFocus) : undefined,
      // An empty value names no status; the list shows its default one.
      leads: params.get("leads")?.trim() || undefined,
      kind: CODE_LEAD_KINDS.includes(kind as CodeLeadKind) ? (kind as CodeLeadKind) : undefined,
      risk: params.get("risk")?.trim().toLowerCase() || undefined,
      tags: CODE_FILE_TAGS.find((value) => value === params.get("tags")),
      scope: (params.get("scope") === "attention" ? "attention" : "all") as CodeResultsScope,
      disposition: splitList(params.get("disposition")),
      confidence: splitList(params.get("confidence")),
      workflow: splitList(params.get("workflow")),
      q: params.get("q") ?? "",
      page: positiveRouteId(params, "page") ?? 1,
      result: positiveRouteId(params, "result"),
      dtab: params.get("dtab") ?? undefined,
    };
  }, [params]);
  return useMemo(() => ({ ...parsed, navigate }), [parsed, navigate]);
}
