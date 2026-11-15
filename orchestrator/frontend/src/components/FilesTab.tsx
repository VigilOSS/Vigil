// ── FilesTab ──────────────────────────────────────────────────────────
// The engagement's root documents (brief, handoff, memory, issues log,
// snapshots). The tab shows the file list, the brief first; opening a file
// replaces the list with the shared record view, and Back, Escape and browser
// Back return to the list. Owns its reads: the file list and the open file's
// content, both re-read on every parent refresh bump. Reloads coalesce — one
// request in flight per source, re-run once afterwards if another bump
// arrived — and previous data stays on screen while they run. The open file
// and its section live in the URL (`file=`, `dtab=raw`), so they survive
// reload and Back.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import {
  listEngagementFiles,
  readEngagementFile,
  type EngagementFile,
  type EngagementFileContent,
} from "../lib/filesApi";
import { useCoalescedRunner } from "../lib/useCoalescedRequest";
import { FileList, FileRecord, isFileSection, shownFileOrder, type FileSection } from "./ArtifactViewer";
import { RecordView, useResultsScrollMemory, type RecordNavigation } from "./record/RecordView";
import { listNavigation } from "./record/recordNavigation";
import { PageHeader } from "./ui";

type FilesTabProps = {
  engagementKey: string;
  // Bumped by EngagementPage after every refresh pass; a change re-reads the
  // list and the open file in the background.
  refreshVersion?: number;
  /** `file=` in the URL: the engagement file whose record is open. */
  initialFileName?: string;
  /** `dtab=` in the URL: the open file's section (`raw`; Rendered is the default). */
  initialDrawerTab?: string;
};

const RECORD_TITLE_ID = "file-record-title";

function errorText(error: unknown, fallback: string) {
  return error instanceof Error && error.message ? error.message : fallback;
}

/** A read that brought back the text and metadata already held. */
function sameContent(held: EngagementFileContent | null, read: EngagementFileContent): boolean {
  if (!held) return false;
  const keys = new Set([...Object.keys(held), ...Object.keys(read)]) as Set<keyof EngagementFileContent>;
  for (const key of keys) if (held[key] !== read[key]) return false;
  return true;
}

/** A file the address named, or that was open, which the engagement does not have (or has not created yet). */
type RouteMiss = { name: string; listed: boolean };

export function FilesTab({ engagementKey, refreshVersion, initialFileName, initialDrawerTab }: FilesTabProps) {
  const [files, setFiles] = useState<EngagementFile[]>([]);
  const [listLoaded, setListLoaded] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [listLoading, setListLoading] = useState(false);
  // The file whose record is open; null while the list shows.
  const [openName, setOpenName] = useState<string | null>(initialFileName ?? null);
  const [section, setSection] = useState<FileSection>(isFileSection(initialDrawerTab) ? initialDrawerTab : "rendered");
  const [routeMiss, setRouteMiss] = useState<RouteMiss | null>(null);
  const [content, setContent] = useState<EngagementFileContent | null>(null);
  const [contentLoading, setContentLoading] = useState(false);
  const [contentError, setContentError] = useState<{ name: string; message: string } | null>(null);

  const keyRef = useRef(engagementKey);
  keyRef.current = engagementKey;
  const openRef = useRef<string | null>(openName);
  openRef.current = openName;
  const filesRef = useRef<EngagementFile[] | null>(null);
  // The `file=` and `dtab=` values the open record last followed (or wrote).
  const appliedRoute = useRef({ file: initialFileName, section: initialDrawerTab });
  // The row a record was opened from: focus returns there when it closes.
  const invokerRef = useRef<HTMLElement | null>(null);

  const writeHash = useCallback((name: string | null, shown: FileSection = "rendered", mode: "push" | "replace" = "push") => {
    appliedRoute.current = { file: name ?? undefined, section: name && shown === "raw" ? "raw" : undefined };
    writeWorkspaceHash(
      engagementHref(keyRef.current, { tab: "artifacts", file: name ?? undefined, dtab: appliedRoute.current.section }),
      mode,
    );
  }, []);

  // Settle the open record against a known file list: a file the engagement
  // does not hold cannot stay open, so the list shows and says why.
  const settleOpen = useCallback((list: EngagementFile[]) => {
    const wanted = openRef.current;
    if (!wanted || list.some((file) => file.name === wanted && file.exists)) return;
    setRouteMiss({ name: wanted, listed: list.some((file) => file.name === wanted) });
    setOpenName(null);
    invokerRef.current = null;
    writeHash(null, "rendered", "replace");
  }, [writeHash]);

  // A different engagement starts from a clean slate.
  useEffect(() => {
    setFiles([]);
    filesRef.current = null;
    setListLoaded(false);
    setListError(null);
    setRouteMiss(null);
    setOpenName(appliedRoute.current.file ?? null);
    setContent(null);
    setContentLoading(false);
    setContentError(null);
  }, [engagementKey]);

  const loadList = useCoalescedRunner(async () => {
    const key = keyRef.current;
    setListLoading(true);
    try {
      const next = await listEngagementFiles(key);
      if (keyRef.current !== key) return;
      setFiles(next);
      filesRef.current = next;
      setListError(null);
      settleOpen(next);
    } catch (error) {
      if (keyRef.current === key) setListError(errorText(error, "Failed to load engagement files"));
    } finally {
      if (keyRef.current === key) {
        setListLoaded(true);
        setListLoading(false);
      }
    }
  });

  // Content reads coalesce per file: a refresh during an in-flight read of
  // the same file re-runs once afterwards, while opening another file
  // starts its read at once instead of queueing behind a slow one.
  const contentInFlightRef = useRef<string | null>(null);
  const contentQueuedRef = useRef(false);
  const loadContent = useCallback(async () => {
    const key = keyRef.current;
    const name = openRef.current;
    if (!name) return;
    const token = `${key}\n${name}`;
    if (contentInFlightRef.current === token) {
      contentQueuedRef.current = true;
      return;
    }
    contentInFlightRef.current = token;
    contentQueuedRef.current = false;
    const current = () => keyRef.current === key && openRef.current === name;
    setContentLoading(true);
    try {
      do {
        contentQueuedRef.current = false;
        try {
          const next = await readEngagementFile(key, name);
          if (!current()) return;
          // An unchanged file keeps the content object the record rendered,
          // so a refresh does not render the document again.
          setContent((held) => (sameContent(held, next) ? held : next));
          setContentError(null);
        } catch (error) {
          if (current()) setContentError({ name, message: errorText(error, "Failed to read file") });
        }
      } while (contentQueuedRef.current && contentInFlightRef.current === token);
    } finally {
      if (contentInFlightRef.current === token) {
        contentInFlightRef.current = null;
        setContentLoading(false);
      }
    }
  }, []);

  // StrictMode repeats the mount effect for the same key: join that load.
  // A different key must re-run after any in-flight load for the old one.
  const listKeyRef = useRef<string | null>(null);
  useEffect(() => {
    const mode = listKeyRef.current === engagementKey ? "join" : "refresh";
    listKeyRef.current = engagementKey;
    void loadList(mode);
  }, [engagementKey, loadList]);

  useEffect(() => {
    if (!openName) return;
    setContentError(null);
    void loadContent();
  }, [engagementKey, openName, loadContent]);

  // The URL changing under the tab (Back / Forward, a link) opens its file
  // and section; no `file=` shows the list.
  useEffect(() => {
    const applied = appliedRoute.current;
    if (applied.file === initialFileName && applied.section === initialDrawerTab) return;
    const stepping = openRef.current !== null && initialFileName !== undefined;
    appliedRoute.current = { file: initialFileName, section: initialDrawerTab };
    setRouteMiss(null);
    if (!stepping) invokerRef.current = null;
    openRef.current = initialFileName ?? null;
    setOpenName(initialFileName ?? null);
    setSection(isFileSection(initialDrawerTab) ? initialDrawerTab : "rendered");
    if (filesRef.current) settleOpen(filesRef.current);
  }, [initialFileName, initialDrawerTab, settleOpen]);

  // Opening from the list remembers the row; stepping from an open record
  // keeps the row the first one was opened from. Each file opens rendered.
  const openFile = useCallback((name: string, invoker?: HTMLElement | null) => {
    if (openRef.current === null) invokerRef.current = invoker ?? null;
    setRouteMiss(null);
    setOpenName(name);
    setSection("rendered");
    writeHash(name);
  }, [writeHash]);

  const closeFile = useCallback(() => {
    setOpenName(null);
    writeHash(null);
  }, [writeHash]);

  const chooseSection = useCallback((next: FileSection) => {
    setSection(next);
    if (openRef.current) writeHash(openRef.current, next);
  }, [writeHash]);

  // Background refresh on parent bumps; the first render is the mount load.
  const lastVersionRef = useRef(refreshVersion);
  useEffect(() => {
    if (lastVersionRef.current === refreshVersion) return;
    lastVersionRef.current = refreshVersion;
    void loadList();
    if (openRef.current) void loadContent();
  }, [refreshVersion, loadList, loadContent]);

  const investigating = openName !== null;
  const present = files.filter((file) => file.exists);
  const missing = files.length - present.length;
  // Previous / Next walk the list as shown. Until the list has loaded (or
  // when it could not be read), the open file's place in it is not known.
  const order = useMemo(() => shownFileOrder(files), [files]);
  const navigation: RecordNavigation = files.length === 0 && listError
    ? { index: undefined, total: undefined, error: listError }
    : listLoaded || files.length > 0
      ? listNavigation(order, openName, openFile)
      : { index: undefined, total: undefined };
  const resultsRef = useRef<HTMLDivElement | null>(null);
  useResultsScrollMemory(resultsRef, investigating, { recordKey: openName });

  return (
    <div className="files-page">
      <PageHeader
        title="Files"
        titleId="files-title"
        purpose="The engagement's working documents: the program brief, handoff notes, memory and snapshots. Start with the brief."
        stats={!listLoaded && files.length === 0 ? [] : [
          { value: present.length, label: present.length === 1 ? "document" : "documents" },
          { value: missing || null, label: "not created yet" },
        ]}
        status={listLoaded && listLoading ? "Updating…" : null}
        hidden={investigating}
      />
      {/* The list (an open record replaces it; it stays mounted behind) */}
      <div ref={resultsRef} className="files-results" hidden={investigating}>
        <FileList
          files={files}
          labelledBy="files-title"
          loading={!listLoaded}
          error={listError}
          refreshing={listLoading}
          notice={routeMiss
            ? routeMiss.listed
              ? <><strong>{routeMiss.name} has not been created yet.</strong> The file list is shown.</>
              : <><strong>{routeMiss.name} is not one of this engagement&apos;s files.</strong> The file list is shown.</>
            : null}
          onRetry={() => void loadList()}
          onOpen={openFile}
        />
      </div>
      {openName !== null && (
        <RecordView
          label="File"
          noun="file"
          navigation={navigation}
          onBack={closeFile}
          titleId={RECORD_TITLE_ID}
          returnFocusRef={invokerRef}
        >
          <FileRecord
            key={openName}
            name={openName}
            file={files.find((file) => file.name === openName) ?? null}
            content={content}
            loadError={contentError?.name === openName ? contentError.message : null}
            loading={contentLoading}
            section={section}
            onSectionChange={chooseSection}
            onRetry={() => void loadContent()}
            titleId={RECORD_TITLE_ID}
          />
        </RecordView>
      )}
    </div>
  );
}
