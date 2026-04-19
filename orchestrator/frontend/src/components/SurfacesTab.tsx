import { useEffect, useMemo, useState } from "react";
import type { AssessmentFindingLink, AssessmentSurface } from "../lib/api";
import { listAssessmentFindingLinks } from "../lib/api";

type SurfacesTabProps = {
  engagementKey: string;
  surfaces: AssessmentSurface[];
};

type GroupedSurfaces = {
  type: string;
  items: AssessmentSurface[];
};

function groupSurfaces(surfaces: AssessmentSurface[]): GroupedSurfaces[] {
  const buckets = new Map<string, AssessmentSurface[]>();
  for (const surface of surfaces) {
    const key = surface.surface_type || "unknown";
    const list = buckets.get(key) ?? [];
    list.push(surface);
    buckets.set(key, list);
  }
  return Array.from(buckets.entries())
    .map(([type, items]) => ({ type, items }))
    .sort((a, b) => b.items.length - a.items.length || a.type.localeCompare(b.type));
}

export function SurfacesTab({ engagementKey, surfaces }: SurfacesTabProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [findingLinks, setFindingLinks] = useState<AssessmentFindingLink[]>([]);
  const [linksError, setLinksError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AssessmentSurface | null>(null);

  useEffect(() => {
    let cancelled = false;
    listAssessmentFindingLinks(engagementKey)
      .then((rows) => {
        if (cancelled) return;
        setFindingLinks(rows);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setFindingLinks([]);
        setLinksError(err instanceof Error ? err.message : "Failed to load finding links");
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey]);

  const groups = useMemo(() => groupSurfaces(surfaces), [surfaces]);

  // Build a surface_id -> linked findings map.
  const linksBySurfaceId = useMemo(() => {
    const map = new Map<number, AssessmentFindingLink[]>();
    for (const link of findingLinks) {
      if (link.target_kind !== "surface") continue;
      const id = Number.parseInt(link.target_ref, 10);
      if (!Number.isFinite(id)) continue;
      const list = map.get(id) ?? [];
      list.push(link);
      map.set(id, list);
    }
    return map;
  }, [findingLinks]);

  function toggle(type: string) {
    setExpanded((current) => ({ ...current, [type]: !current[type] }));
  }

  const selectedLinks = selected ? linksBySurfaceId.get(selected.id) ?? [] : [];

  useEffect(() => {
    if (!selected) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [selected]);

  return (
    <>
      <section className="panel">
        <div className="panel-header">
          <h2>Attack surfaces</h2>
          <p className="meta-text">
            {surfaces.length} surface{surfaces.length === 1 ? "" : "s"}
            {linksError ? " · links unavailable" : ""}
          </p>
        </div>

        {groups.length === 0 ? (
          <p className="empty-state" style={{ padding: "20px" }}>No surfaces discovered yet.</p>
        ) : (
          <div className="coverage-tree" style={{ marginTop: "14px" }}>
            {groups.map(({ type, items }) => {
              const isOpen = expanded[type] ?? true;
              return (
                <div key={type} className="coverage-tree-node">
                  <button
                    type="button"
                    className="coverage-tree-header"
                    onClick={() => toggle(type)}
                  >
                    <span>{isOpen ? "▾" : "▸"}</span>
                    <strong>{type}</strong>
                    <span className="meta-text">{items.length} surface{items.length === 1 ? "" : "s"}</span>
                  </button>
                  {isOpen && (
                    <div style={{ padding: "0 14px 14px" }}>
                      <div className="coverage-items-grid">
                        <div
                          className="coverage-items-header"
                          style={{ gridTemplateColumns: "1fr 120px 140px 2fr 80px" }}
                        >
                          <span>Target</span>
                          <span>Status</span>
                          <span>Source</span>
                          <span>Rationale</span>
                          <span>Findings</span>
                        </div>
                        {items.map((surface) => {
                          const links = linksBySurfaceId.get(surface.id) ?? [];
                          return (
                            <button
                              key={surface.id}
                              type="button"
                              className="finding-row"
                              onClick={() => setSelected(surface)}
                              style={{ display: "grid", gridTemplateColumns: "1fr 120px 140px 2fr 80px", gap: "8px", textAlign: "left" }}
                            >
                              <span className="mono-text" title={surface.target_descriptor}>{surface.target_descriptor}</span>
                              <span><span className={`badge status-${surface.status}`}>{surface.status}</span></span>
                              <span className="meta-text">{surface.source_name || "—"}</span>
                              <span className="meta-text">{surface.rationale || "—"}</span>
                              <span>{links.length > 0 ? <span className="badge">{links.length}</span> : <span className="meta-text">—</span>}</span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {selected && (
        <div className="finding-overlay" role="presentation" onClick={() => setSelected(null)}>
          <article className="finding-modal panel" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <div className="finding-modal-header">
              <div className="finding-modal-heading">
                <h2>{selected.target_descriptor}</h2>
                <p className="meta-text">{selected.surface_type}</p>
              </div>
              <div className="finding-modal-actions">
                <span className={`badge status-${selected.status}`}>{selected.status}</span>
                <button type="button" className="ghost-button" onClick={() => setSelected(null)}>Close</button>
              </div>
            </div>
            <div className="finding-modal-content">
              <div className="finding-meta-grid">
                <div>
                  <p className="eyebrow">Source</p>
                  <p>{selected.source_name || "—"}</p>
                </div>
                <div>
                  <p className="eyebrow">Updated</p>
                  <p className="meta-text">{selected.updated_at}</p>
                </div>
                {selected.evidence_ref && (
                  <div>
                    <p className="eyebrow">Evidence</p>
                    <p className="meta-text finding-mono">{selected.evidence_ref}</p>
                  </div>
                )}
              </div>

              {selected.rationale && (
                <div>
                  <p className="eyebrow">Rationale</p>
                  <p>{selected.rationale}</p>
                </div>
              )}

              <div>
                <p className="eyebrow">Linked findings</p>
                {selectedLinks.length === 0 ? (
                  <p className="meta-text">No findings linked to this surface yet.</p>
                ) : (
                  <div style={{ display: "grid", gap: "6px" }}>
                    {selectedLinks.map((link) => (
                      <div key={link.id} className="finding-row" style={{ textAlign: "left" }}>
                        <div className="finding-row-main">
                          <strong className="finding-row-title">{link.finding_slug}</strong>
                          <p className="meta-text">{link.link_kind}{link.notes ? ` · ${link.notes}` : ""}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </article>
        </div>
      )}
    </>
  );
}
