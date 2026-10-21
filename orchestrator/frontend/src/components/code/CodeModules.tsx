import { useState } from "react";

import type { CodeModule } from "../../lib/api";
import { CardSkeleton } from "../Skeletons";
import { EmptyState, statusLabel } from "../ui";

type Props = { modules: CodeModule[] | null; loading: boolean };

export function CodeModules({ modules, loading }: Props) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  if (modules === null) {
    return (
      <section className="panel cv-section">
        {loading ? <CardSkeleton lines={4} /> : <p className="meta-text">Modules are unavailable.</p>}
      </section>
    );
  }
  return (
    <section className="panel cv-section" aria-labelledby="cv-modules-title">
      <header className="cv-section-head">
        <h3 id="cv-modules-title">Modules</h3>
        <p className="meta-text">
          How the code was grouped while mapping it, with each module's trust boundary. {modules.length} modules.
        </p>
      </header>
      {modules.length === 0 ? (
        <EmptyState variant="empty" compact title="No modules have been mapped yet.">
          Modules appear once the code is classified and mapped.
        </EmptyState>
      ) : (
        <ul className="cv-module-list">
          {modules.map((module) => {
            const open = expanded.has(module.id);
            const detail = Boolean(module.trust_boundary || module.description);
            return (
              <li key={module.id} className="cv-module">
                <button
                  type="button"
                  className="cv-module-head"
                  aria-expanded={detail ? open : undefined}
                  disabled={!detail}
                  onClick={() =>
                    setExpanded((current) => {
                      const next = new Set(current);
                      if (next.has(module.id)) next.delete(module.id);
                      else next.add(module.id);
                      return next;
                    })
                  }
                >
                  <span className="cv-chevron" aria-hidden="true">{detail ? (open ? "▾" : "▸") : "·"}</span>
                  <strong>{module.name}</strong>
                  <span className="meta-text">{module.file_count.toLocaleString()} files</span>
                  {module.critical_file_count > 0 && (
                    <span className="cv-risk cv-risk-critical">{module.critical_file_count} critical</span>
                  )}
                  <span className="cv-chip">{statusLabel("code-repo", module.analysis_status)}</span>
                </button>
                {open && (
                  <dl className="cv-facts cv-module-body">
                    {module.trust_boundary && <div><dt>Trust boundary</dt><dd>{module.trust_boundary}</dd></div>}
                    {module.description && <div><dt>Description</dt><dd>{module.description}</dd></div>}
                  </dl>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
