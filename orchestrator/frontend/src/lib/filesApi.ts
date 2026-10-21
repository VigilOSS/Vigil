// Engagement root documents served by GET /engagements/{key}/artifacts
// (backend: services/artifacts.py owns the list, roles, and the view limit).
import { request } from "./api";

export type EngagementFileGroup = "working" | "snapshot";

export type EngagementFileMeta = {
  group: EngagementFileGroup;
  role: string;
  description: string;
  size_bytes: number | null;
  modified_at: string | null;
  // ENGAGEMENT.md still carries the generated STUB marker.
  is_stub: boolean;
  // Operator's no-separate-brief reason for a deliberately unfilled stub; "" otherwise.
  stub_waiver: string;
};

export type EngagementFile = EngagementFileMeta & {
  name: string;
  relative_path: string;
  media_type: string;
  exists: boolean;
};

export type EngagementFileContent = EngagementFile & {
  content: string;
  // The backend stops at its view limit; `returned_bytes` of `size_bytes` are in `content`.
  truncated: boolean;
  returned_bytes: number;
};

export function listEngagementFiles(engagementKey: string) {
  return request<EngagementFile[]>(`/engagements/${encodeURIComponent(engagementKey)}/artifacts`);
}

export function readEngagementFile(engagementKey: string, name: string) {
  return request<EngagementFileContent>(
    `/engagements/${encodeURIComponent(engagementKey)}/artifacts/${encodeURIComponent(name)}`,
  );
}

// The brief first; the legacy brief name, then scope, when it is absent.
const DEFAULT_FILE_ORDER = ["ENGAGEMENT.md", "RULES.md", "scope.json"];

export function defaultEngagementFile(files: Pick<EngagementFile, "name" | "exists">[]): string | null {
  const present = files.filter((file) => file.exists);
  for (const name of DEFAULT_FILE_ORDER) {
    if (present.some((file) => file.name === name)) return name;
  }
  return present[0]?.name ?? null;
}
