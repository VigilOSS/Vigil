// ── FilesTab ──────────────────────────────────────────────────────────
// The engagement's root documents (brief, handoff, memory, issues log,
// snapshots). Owns its reads: the file list and the selected file's content,
// both re-read on every parent refresh bump. Reloads coalesce — one request
// in flight per source, re-run once afterwards if another bump arrived — and
// previous data stays on screen while they run. The open file lives in the
// URL (`file=`), so it survives reload and Back. ArtifactViewer renders.

import { useCallback, useEffect, useRef, useState } from "react";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import {
  defaultEngagementFile,
  listEngagementFiles,
  readEngagementFile,
  type EngagementFile,
  type EngagementFileContent,
} from "../lib/filesApi";
import { useCoalescedRunner } from "../lib/useCoalescedRequest";
import { ArtifactViewer } from "./ArtifactViewer";

type FilesTabProps = {
  engagementKey: string;
  // Bumped by EngagementPage after every refresh pass; a change re-reads the
  // list and the open file in the background.
  refreshVersion?: number;
  /** `file=` in the URL: the engagement file open in the viewer. */
  initialFileName?: string;
};

function errorText(error: unknown, fallback: string) {
  return error instanceof Error && error.message ? error.message : fallback;
}

/** A file the URL named that the engagement does not have (or has not created yet). */
type RouteMiss = { name: string; listed: boolean };

export function FilesTab({ engagementKey, refreshVersion, initialFileName }: FilesTabProps) {
  const [files, setFiles] = useState<EngagementFile[]>([]);
  const [listLoaded, setListLoaded] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [listLoading, setListLoading] = useState(false);
  const [selectedName, setSelectedName] = useState<string | null>(initialFileName ?? null);
  const [routeMiss, setRouteMiss] = useState<RouteMiss | null>(null);
  const [content, setContent] = useState<EngagementFileContent | null>(null);
  const [contentLoading, setContentLoading] = useState(false);
  const [contentError, setContentError] = useState<{ name: string; message: string } | null>(null);

  const keyRef = useRef(engagementKey);
  keyRef.current = engagementKey;
  const selectedRef = useRef<string | null>(selectedName);
  selectedRef.current = selectedName;
  const filesRef = useRef<EngagementFile[] | null>(null);
  // The file the URL names; a missing one is reported, not silently swapped.
  const routeFileRef = useRef<string | undefined>(initialFileName);
  routeFileRef.current = initialFileName;
  // The `file=` value the selection last followed (or wrote).
  const appliedRouteFile = useRef(initialFileName);

  // Settle the selection against a known file list: keep a present file,
  // otherwise open the default, saying so when the URL named the missing one.
  const settleSelection = useCallback((wanted: string | null, list: EngagementFile[]) => {
    if (wanted && list.some((file) => file.name === wanted && file.exists)) {
      setSelectedName(wanted);
      return;
    }
    const fallback = defaultEngagementFile(list);
    setSelectedName(fallback);
    if (wanted && wanted === routeFileRef.current) {
      setRouteMiss({ name: wanted, listed: list.some((file) => file.name === wanted) });
      appliedRouteFile.current = undefined;
      writeWorkspaceHash(engagementHref(keyRef.current, { tab: "artifacts" }), "replace");
    }
  }, []);

  // A different engagement starts from a clean slate.
  useEffect(() => {
    setFiles([]);
    filesRef.current = null;
    setListLoaded(false);
    setListError(null);
    setRouteMiss(null);
    setSelectedName(routeFileRef.current ?? null);
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
      // Keep the open file while it still exists; otherwise open the default.
      settleSelection(selectedRef.current, next);
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
  // the same file re-runs once afterwards, while selecting another file
  // starts its read at once instead of queueing behind a slow one.
  const contentInFlightRef = useRef<string | null>(null);
  const contentQueuedRef = useRef(false);
  const loadContent = useCallback(async () => {
    const key = keyRef.current;
    const name = selectedRef.current;
    if (!name) return;
    const token = `${key}\n${name}`;
    if (contentInFlightRef.current === token) {
      contentQueuedRef.current = true;
      return;
    }
    contentInFlightRef.current = token;
    contentQueuedRef.current = false;
    const current = () => keyRef.current === key && selectedRef.current === name;
    setContentLoading(true);
    try {
      do {
        contentQueuedRef.current = false;
        try {
          const next = await readEngagementFile(key, name);
          if (!current()) return;
          setContent(next);
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
    if (!selectedName) return;
    setContentError(null);
    void loadContent();
  }, [engagementKey, selectedName, loadContent]);

  // The URL changing under the tab (Back / Forward, a link) opens its file;
  // no `file=` means the default document.
  useEffect(() => {
    if (appliedRouteFile.current === initialFileName) return;
    appliedRouteFile.current = initialFileName;
    setRouteMiss(null);
    const list = filesRef.current;
    if (list) settleSelection(initialFileName ?? defaultEngagementFile(list), list);
    else setSelectedName(initialFileName ?? null);
  }, [initialFileName, settleSelection]);

  const selectFile = useCallback((name: string) => {
    setRouteMiss(null);
    setSelectedName(name);
    appliedRouteFile.current = name;
    writeWorkspaceHash(engagementHref(keyRef.current, { tab: "artifacts", file: name }));
  }, []);

  // Background refresh on parent bumps; the first render is the mount load.
  const lastVersionRef = useRef(refreshVersion);
  useEffect(() => {
    if (lastVersionRef.current === refreshVersion) return;
    lastVersionRef.current = refreshVersion;
    void loadList();
    if (selectedRef.current) void loadContent();
  }, [refreshVersion, loadList, loadContent]);

  return (
    <ArtifactViewer
      artifacts={files}
      selectedName={selectedName}
      selectedArtifact={content}
      loadError={contentError?.name === selectedName ? contentError.message : null}
      listLoading={!listLoaded}
      listError={listError}
      contentLoading={contentLoading}
      refreshing={listLoaded && (listLoading || (contentLoading && content?.name === selectedName))}
      routeNotice={routeMiss
        ? routeMiss.listed
          ? <><strong>{routeMiss.name} has not been created yet.</strong> Showing {selectedName ?? "the file list"} instead.</>
          : <><strong>{routeMiss.name} is not one of this engagement&apos;s files.</strong> Showing {selectedName ?? "the file list"} instead.</>
        : null}
      onRetry={() => {
        void loadList();
        if (selectedRef.current) void loadContent();
      }}
      onSelect={selectFile}
    />
  );
}
