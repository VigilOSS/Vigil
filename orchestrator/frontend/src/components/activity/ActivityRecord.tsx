// One activity entry inside the shared RecordView (ActivityTab owns the view,
// the list order and the address). The header names the entry; Details holds
// its fields, every linked record and the stored text blocks verbatim (ADR
// 0019); Metadata holds the stored metadata object.

import type { ActivityEntity, ActivityItem } from "../../lib/activityApi";
import { engagementHref } from "../../lib/workspaceRoutes";
import { KV, KVTime } from "../drawer/DrawerKit";
import { CopyInline } from "../formatting";
import { JsonView } from "../JsonView";
import { RecordBody, RecordCopyLinkButton, RecordHeader, RecordTabs, type RecordDate, type RecordTab } from "../record/RecordView";
import { Skeleton, SlowLoadHint } from "../Skeletons";
import { ACTOR_KIND_LABEL, ActorTag, EntityChips } from "./ActivityEntries";
import { entityHref, entityUnlinkedReason } from "./activityModel";

export type EntrySection = "details" | "metadata";

export function isEntrySection(value: string | undefined): value is EntrySection {
  return value === "details" || value === "metadata";
}

/** How an entry is cited: its source and that source's row number. */
function entryReference(item: Pick<ActivityItem, "source" | "source_id">): string {
  return item.source === "audit" ? `Audit log entry #${item.source_id}` : `Structured event #${item.source_id}`;
}

/** Entities no view opens, each with the reason, so the record says why instead of only a hover. */
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
    <section className="section activity-verbatim">
      <h3 className="section-title">
        {label}
        <CopyInline text={text} ariaLabel={`Copy ${label.toLowerCase()} for ${entryId}`}>copy</CopyInline>
      </h3>
      <pre>{text}</pre>
    </section>
  );
}

function EntryDetails({ item, engagementKey }: { item: ActivityItem; engagementKey: string }) {
  const detail = item.detail;
  const dispatch = item.dispatch;
  const storedKind = typeof detail.actor_kind === "string" && detail.actor_kind && detail.actor_kind !== item.actor.kind ? ` (stored as ${detail.actor_kind})` : "";
  return (
    <>
      <section className="section">
        <h3 className="section-title">Fields</h3>
        <div className="kv-grid">
          <KVTime k="Occurred" v={item.occurred_at} precision="millisecond" />
          <KV k="Actor" v={`${item.actor.name || "unnamed"} · ${ACTOR_KIND_LABEL[item.actor.kind].toLowerCase()}${storedKind}`} />
          <KV k={item.source === "audit" ? "Audit title" : "Event type"} v={item.kind} mono />
          {item.source === "event" && <KV k="Phase" v={detail.phase} />}
          {item.source === "event" && <KV k="Task" v={detail.task_name} mono />}
          {dispatch && (
            <div className="kv">
              <p className="k">Dispatch</p>
              <p className="v">
                <span className="mono">{dispatch.agent_id}</span>{dispatch.role ? ` · ${dispatch.role}` : ""}
                {dispatch.run_id ? <> · <a href={engagementHref(engagementKey, { tab: "runs", run: dispatch.run_id })}>Run #{dispatch.run_id}</a></> : null}
              </p>
            </div>
          )}
        </div>
      </section>
      {item.entities.length > 0 && (
        <section className="section activity-record-linked">
          <h3 className="section-title">Linked records <span className="count">{item.entities.length.toLocaleString()}</span></h3>
          <EntityChips engagementKey={engagementKey} entities={item.entities} limit={item.entities.length} />
          <UnlinkedEntities engagementKey={engagementKey} entities={item.entities} />
        </section>
      )}
      <Verbatim label="Action" value={detail.action} entryId={item.id} />
      <Verbatim label="Result" value={detail.result} entryId={item.id} />
      <Verbatim label="Artifact reference" value={detail.artifact_ref} entryId={item.id} />
      <Verbatim label="Body" value={detail.body_markdown} entryId={item.id} />
      {item.source === "event" && <Verbatim label="Stored summary" value={detail.summary} entryId={item.id} />}
    </>
  );
}

type EntryRecordProps = {
  /** The open entry's id; the record shows its loading shape until `item` is known. */
  entryId: string;
  /** The entry, from the loaded rows or read by id; null while that read runs or after it failed. */
  item: ActivityItem | null;
  /** Failure reading an entry the list does not hold. */
  loadError?: string | null;
  /** Reads the entry again after a failure. */
  onRetry?: () => void;
  /** Loaded rows the list holds when this entry is not among them; null when it is. */
  outsideLoaded: number | null;
  engagementKey: string;
  categoryLabels: Map<string, string>;
  section: EntrySection;
  onSectionChange: (next: EntrySection) => void;
  /** Id for the record heading (RecordView focuses it on open). */
  titleId: string;
};

export function EntryRecord({
  entryId,
  item,
  loadError,
  onRetry,
  outsideLoaded,
  engagementKey,
  categoryLabels,
  section,
  onSectionChange,
  titleId,
}: EntryRecordProps) {
  if (!item) {
    return (
      <>
        <RecordHeader
          id="Activity entry"
          title={<span className="mono">{entryId}</span>}
          titleId={titleId}
          actions={<RecordCopyLinkButton noun="entry" />}
        />
        <RecordBody busy={!loadError}>
          {loadError ? (
            <div className="activity-record-error">
              <p className="error-text" role="alert">Entry {entryId} unavailable: {loadError}</p>
              {onRetry && <button type="button" className="ui-button" onClick={onRetry}>Try again</button>}
            </div>
          ) : (
            <>
              <div className="activity-record-skeleton" role="status" aria-label={`Loading entry ${entryId}`}>
                <Skeleton height={12} width="45%" />
                <Skeleton height={12} />
                <Skeleton height={12} width="80%" />
              </div>
              <SlowLoadHint active what="this entry" />
            </>
          )}
        </RecordBody>
      </>
    );
  }

  const metadata = item.detail.metadata;
  const metadataFields = metadata && typeof metadata === "object" ? Object.keys(metadata).length : 0;
  const shown: EntrySection = metadataFields ? section : "details";
  const reference = entryReference(item);
  const recorded = typeof item.detail.recorded_at === "string" ? item.detail.recorded_at : "";
  const dates: RecordDate[] = [{ label: "Occurred", value: item.occurred_at }];
  if (recorded) dates.push({ label: "Recorded", value: recorded });
  const tabs: RecordTab<EntrySection>[] = [
    { id: "details", label: "Details" },
    { id: "metadata", label: "Metadata", count: metadataFields, hidden: !metadataFields },
  ];
  return (
    <>
      <RecordHeader
        id={reference}
        copyId={reference}
        copyIdLabel="Copy entry reference"
        title={item.summary}
        titleId={titleId}
        actions={<RecordCopyLinkButton noun="entry" />}
        pills={
          <>
            <span className="tag" title="Category">{categoryLabels.get(item.category) ?? item.category}</span>
            <ActorTag name={item.actor.name} kind={item.actor.kind} />
          </>
        }
        dates={dates}
        datesLabel="Entry dates"
      >
        {outsideLoaded !== null && (
          <p className="activity-record-notice" role="note">
            <strong>Not among the loaded results.</strong>{" "}
            The list holds {outsideLoaded.toLocaleString()} {outsideLoaded === 1 ? "entry" : "entries"} for its current filters and this is not one of them,
            so Previous and Next are unavailable. Back to results shows the list, where older entries can be loaded and the filters changed.
          </p>
        )}
      </RecordHeader>
      <RecordTabs tabs={tabs} active={shown} onChange={onSectionChange} label="Entry sections" />
      <RecordBody>
        {shown === "details"
          ? <EntryDetails item={item} engagementKey={engagementKey} />
          : <JsonView value={metadata} label="Stored metadata" />}
      </RecordBody>
    </>
  );
}
