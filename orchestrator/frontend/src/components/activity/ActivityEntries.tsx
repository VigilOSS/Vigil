// Row, dispatch card, and burst renderers for the Activity view. Every entry
// is one line until opened; the stored fields stay one disclosure away.

import type { ReactNode } from "react";

import type { ActivityEntity, ActivityItem } from "../../lib/activityApi";
import { formatAbsoluteTime, formatRelativeTime, parseServerTime } from "../../lib/serverTime";
import { engagementHref } from "../../lib/workspaceRoutes";
import { KV, KVTime } from "../drawer/DrawerKit";
import { CopyInline } from "../formatting";
import { JsonView } from "../JsonView";
import { StatusPill } from "../ui";
import {
  dispatchSpanText,
  dispatchStatusEntry,
  entityHref,
  entityUnlinkedReason,
  type BurstEntry,
  type DispatchEntry,
  type FeedEntry,
  type RowEntry,
} from "./activityModel";

export type EntryUi = {
  engagementKey: string;
  categoryLabels: Map<string, string>;
  expanded: ReadonlySet<string>;
  /** Opens `id`, or closes it and every alias (a burst's member keys). */
  toggle: (id: string, aliases?: readonly string[]) => void;
  fresh: ReadonlySet<string>;
};

const ACTOR_KIND_LABEL = { operator: "Operator", agent: "Agent", system: "System" } as const;
const ENTITY_CHIP_LIMIT = 4;

/** Clock time inside a day group; the full UTC instant and age are on hover and in the label. */
export function ClockTime({ value, className = "" }: { value: string; className?: string }) {
  const parsed = parseServerTime(value);
  if (!parsed) return <span className={`activity-time ${className}`.trim()}>{value || "—"}</span>;
  const absolute = formatAbsoluteTime(value, "second");
  const label = `${absolute} (${formatRelativeTime(value)})`;
  return (
    <time className={`activity-time timestamp ${className}`.trim()} dateTime={parsed.toISOString()} title={label} aria-label={label}>
      {absolute.slice(11, 19)}
    </time>
  );
}

/** "14:06:00–14:09:00", oldest to newest, on one line; the full instants are on hover. */
function ClockRange({ newest, oldest }: { newest: string; oldest: string }) {
  const from = formatAbsoluteTime(oldest, "second");
  const to = formatAbsoluteTime(newest, "second");
  if (!parseServerTime(newest) || !parseServerTime(oldest) || from === to) return null;
  return (
    <span className="activity-burst-range" title={`${from} to ${to}`}>
      {from.slice(11, 19)}–{to.slice(11, 19)}
    </span>
  );
}

function ActorTag({ name, kind }: { name: string; kind: keyof typeof ACTOR_KIND_LABEL }) {
  return (
    <span className={`activity-actor actor-${kind}`} title={`${ACTOR_KIND_LABEL[kind]}: ${name || "unnamed"}`}>
      <span className="activity-actor-kind">{ACTOR_KIND_LABEL[kind]}</span>
      <span className="activity-actor-name">{name || "unnamed"}</span>
    </span>
  );
}

const ENTITY_NOUNS: Record<string, string> = {
  finding: "finding",
  run: "run",
  http_variant: "HTTP request",
  surface: "surface",
  intel: "intel record",
  chain: "attack chain's first finding",
  code_file: "code review results for",
  file: "file",
  oob_probe: "the record for",
};

export function EntityChips({ engagementKey, entities, limit = ENTITY_CHIP_LIMIT }: { engagementKey: string; entities: ActivityEntity[]; limit?: number }) {
  if (!entities.length) return null;
  const shown = entities.slice(0, limit);
  return (
    <span className="activity-entities">
      {shown.map((entity) => {
        const href = entityHref(engagementKey, entity);
        const key = `${entity.type}:${entity.key}`;
        if (href) {
          return (
            <a key={key} className={`activity-entity entity-${entity.type}`} href={href} title={`Open ${ENTITY_NOUNS[entity.type] ?? entity.type} ${entity.label}`}>
              {entity.label}
            </a>
          );
        }
        const reason = entityUnlinkedReason(entity);
        return (
          <span key={key} className={`activity-entity entity-${entity.type} is-unlinked`} title={`${entity.label} — ${reason}`}>
            {entity.label}
            <span className="sr-only"> (not linkable: {reason})</span>
          </span>
        );
      })}
      {entities.length > shown.length && <span className="activity-entity-more">+{entities.length - shown.length}</span>}
    </span>
  );
}

/** Entities no view opens, each with the reason, so the detail says why instead of only a hover. */
function UnlinkedEntities({ engagementKey, entities }: { engagementKey: string; entities: ActivityEntity[] }) {
  const unlinked = entities.filter((entity) => entityHref(engagementKey, entity) === null);
  if (!unlinked.length) return null;
  return (
    <ul className="activity-unlinked" aria-label="Linked records that cannot be opened">
      {unlinked.map((entity) => (
        <li key={`${entity.type}:${entity.key}`}>
          <span className="mono">{entity.label}</span>
          {" — "}
          <span className="activity-unlinked-reason">{entityUnlinkedReason(entity)}</span>
        </li>
      ))}
    </ul>
  );
}

function Verbatim({ label, value, entryId }: { label: string; value: unknown; entryId: string }) {
  const text = typeof value === "string" ? value : "";
  if (!text) return null;
  return (
    <div className="activity-verbatim">
      <div className="activity-verbatim-head">
        <span className="k">{label}</span>
        <CopyInline text={text} ariaLabel={`Copy ${label.toLowerCase()} for ${entryId}`}>copy</CopyInline>
      </div>
      <pre>{text}</pre>
    </div>
  );
}

function RowDetail({ item, ui, id }: { item: ActivityItem; ui: EntryUi; id: string }) {
  const detail = item.detail;
  const metadata = detail.metadata;
  const hasMetadata = Boolean(metadata && typeof metadata === "object" && Object.keys(metadata).length);
  const dispatch = item.dispatch;
  return (
    <div className="activity-detail" id={id}>
      <p className="activity-detail-summary">{item.summary}</p>
      <div className="activity-kv-grid">
        <KVTime k="Occurred" v={item.occurred_at} precision="millisecond" />
        <KVTime k="Recorded" v={typeof detail.recorded_at === "string" ? detail.recorded_at : null} />
        <KV k="Actor" v={`${item.actor.name || "unnamed"} · ${ACTOR_KIND_LABEL[item.actor.kind].toLowerCase()}${typeof detail.actor_kind === "string" && detail.actor_kind && detail.actor_kind !== item.actor.kind ? ` (stored as ${detail.actor_kind})` : ""}`} />
        <KV k="Category" v={ui.categoryLabels.get(item.category) ?? item.category} />
        <KV k={item.source === "audit" ? "Audit title" : "Event type"} v={item.kind} mono />
        <KV k="Source" v={item.source === "audit" ? `Audit log entry #${item.source_id}` : `Structured event #${item.source_id}`} />
        {item.source === "event" && <KV k="Phase" v={detail.phase} />}
        {item.source === "event" && <KV k="Task" v={detail.task_name} mono />}
        {dispatch && (
          <div className="kv">
            <p className="k">Dispatch</p>
            <p className="v">
              <span className="mono">{dispatch.agent_id}</span>{dispatch.role ? ` · ${dispatch.role}` : ""}
              {dispatch.run_id ? <> · <a href={engagementHref(ui.engagementKey, { tab: "runs", run: dispatch.run_id })}>Run #{dispatch.run_id}</a></> : null}
            </p>
          </div>
        )}
      </div>
      {item.entities.length > 0 && (
        <div className="activity-detail-entities">
          <span className="k">Linked</span>
          <EntityChips engagementKey={ui.engagementKey} entities={item.entities} limit={item.entities.length} />
          <UnlinkedEntities engagementKey={ui.engagementKey} entities={item.entities} />
        </div>
      )}
      <Verbatim label="Action" value={detail.action} entryId={item.id} />
      <Verbatim label="Result" value={detail.result} entryId={item.id} />
      <Verbatim label="Artifact reference" value={detail.artifact_ref} entryId={item.id} />
      <Verbatim label="Body" value={detail.body_markdown} entryId={item.id} />
      {item.source === "event" && <Verbatim label="Stored summary" value={detail.summary} entryId={item.id} />}
      {hasMetadata && (
        <details className="activity-metadata">
          <summary>Metadata</summary>
          <JsonView value={metadata} label="Stored metadata" />
        </details>
      )}
    </div>
  );
}

function RowView({ entry, ui, compact = false }: { entry: RowEntry; ui: EntryUi; compact?: boolean }) {
  const { item } = entry;
  const open = ui.expanded.has(entry.id);
  const detailId = `activity-detail-${entry.id.replace(/[^A-Za-z0-9_-]/g, "-")}`;
  return (
    <li className={`activity-entry activity-row cat-${item.category}${ui.fresh.has(item.id) ? " is-new" : ""}${open ? " is-open" : ""}`}>
      <div className="activity-line">
        <ClockTime value={item.occurred_at} />
        {!compact && <ActorTag name={item.actor.name} kind={item.actor.kind} />}
        <button
          type="button"
          className="activity-summary"
          aria-expanded={open}
          aria-controls={detailId}
          onClick={() => ui.toggle(entry.id)}
          title={item.summary}
        >
          <span className="activity-caret" aria-hidden="true" />
          <span className="activity-summary-text">{item.summary}</span>
        </button>
        <EntityChips engagementKey={ui.engagementKey} entities={item.entities} />
      </div>
      {open && <RowDetail item={item} ui={ui} id={detailId} />}
    </li>
  );
}

function DispatchView({ entry, ui }: { entry: DispatchEntry; ui: EntryUi }) {
  const open = ui.expanded.has(entry.id);
  const membersId = `activity-members-${entry.id.replace(/[^A-Za-z0-9_-]/g, "-")}`;
  const handoff = typeof entry.handoff?.detail.result === "string" ? entry.handoff.detail.result : "";
  const isNew = entry.items.some((item) => ui.fresh.has(item.id));
  const status = dispatchStatusEntry(entry.status);
  return (
    <li className={`activity-entry activity-card activity-dispatch${isNew ? " is-new" : ""}${open ? " is-open" : ""}`}>
      <div className="activity-line">
        <ClockTime value={entry.at} />
        <ActorTag name={entry.role || "agent"} kind="agent" />
        <button type="button" className="activity-summary" aria-expanded={open} aria-controls={membersId} onClick={() => ui.toggle(entry.id)}>
          <span className="activity-caret" aria-hidden="true" />
          <span className="activity-summary-text">
            <span className="mono">{entry.agentId}</span>
            <span className="activity-sep" aria-hidden="true"> · </span>
            <span className="activity-span">{dispatchSpanText(entry)}</span>
            <span className="activity-sep" aria-hidden="true"> · </span>
            <span>{entry.items.length} entries</span>
          </span>
        </button>
        <StatusPill
          className="activity-status"
          size="sm"
          value={entry.status}
          label={status.label}
          tone={status.tone}
          title={status.meaning}
        />
        {entry.runId ? <a className="activity-entity entity-run" href={engagementHref(ui.engagementKey, { tab: "runs", run: entry.runId })}>Run #{entry.runId}</a> : null}
        <EntityChips engagementKey={ui.engagementKey} entities={entry.findings} />
      </div>
      {handoff && <p className="activity-card-note"><span className="k">Handoff</span> {handoff}</p>}
      {open && (
        <ul className="activity-members" id={membersId} aria-label={`${entry.agentId} entries`}>
          {entry.items.map((item) => <RowView key={item.id} entry={{ type: "row", id: item.id, at: item.occurred_at, item }} ui={ui} compact />)}
        </ul>
      )}
    </li>
  );
}

function BurstView({ entry, ui }: { entry: BurstEntry; ui: EntryUi }) {
  const open = entry.memberKeys.some((key) => ui.expanded.has(key));
  const membersId = `activity-members-${entry.id.replace(/[^A-Za-z0-9_-]/g, "-")}`;
  const isNew = entry.entries.some((member) => (member.type === "row" ? [member.item] : member.items).some((item) => ui.fresh.has(item.id)));
  const first = entry.entries[0];
  const kind = first.type === "row" ? first.item.actor.kind : "agent";
  // A burst of dispatch cards shares one role; show it where the actor goes.
  const role = first.type === "dispatch" ? first.role : "";
  return (
    <li className={`activity-entry activity-card activity-burst${isNew ? " is-new" : ""}${open ? " is-open" : ""}`}>
      <div className="activity-line">
        <ClockTime value={entry.at} />
        {entry.actorName || role
          ? <ActorTag name={entry.actorName ?? role} kind={kind} />
          : <span className="activity-actor" aria-hidden="true" />}
        <button type="button" className="activity-summary" aria-expanded={open} aria-controls={membersId} onClick={() => ui.toggle(entry.id, entry.memberKeys)}>
          <span className="activity-caret" aria-hidden="true" />
          <span className="activity-summary-text">
            {entry.label}
            <ClockRange newest={entry.at} oldest={entry.oldestAt} />
          </span>
        </button>
        <EntityChips engagementKey={ui.engagementKey} entities={entry.entities} />
      </div>
      {open && (
        <ul className="activity-members" id={membersId} aria-label={entry.label}>
          {entry.entries.map((member) => <EntryView key={member.id} entry={member} ui={ui} />)}
        </ul>
      )}
    </li>
  );
}

export function EntryView({ entry, ui }: { entry: FeedEntry; ui: EntryUi }): ReactNode {
  if (entry.type === "dispatch") return <DispatchView entry={entry} ui={ui} />;
  if (entry.type === "burst") return <BurstView entry={entry} ui={ui} />;
  return <RowView entry={entry} ui={ui} />;
}
