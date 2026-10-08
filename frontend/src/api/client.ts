import type { components } from "./schema";

export type Schemas = components["schemas"];
export type InvestigationSummary = Schemas["InvestigationSummary"];
export type InvestigationDetail = Schemas["InvestigationDetail"];
export type IncidentSummary = Schemas["IncidentSummary"];
export type IncidentDetail = Schemas["IncidentDetailOut"];
export type FindingOut = Schemas["FindingOut"];
export type EvidencePage = Schemas["EvidencePage"];
export type EvidenceOut = Schemas["EvidenceOut"];
export type AnomaliesOut = Schemas["AnomaliesOut"];
export type SliceOut = Schemas["SliceOut"];
export type NarrativeOut = Schemas["NarrativeOut"];
export type FeedbackLabel = Schemas["FeedbackIn"]["label"];

const BASE = "/api/v1";
const TOKEN_KEY = "tracewright.token";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function getToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setToken(token: string): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: the token simply is not remembered */
  }
}

function headers(extra?: HeadersInit): Headers {
  const h = new Headers(extra);
  const token = getToken();
  if (token) h.set("Authorization", `Bearer ${token}`);
  return h;
}

async function fail(response: Response): Promise<never> {
  let code = "ERROR";
  let message = `Request failed (${response.status}).`;
  try {
    const body = (await response.json()) as { error?: { code?: string; message?: string } };
    code = body.error?.code ?? code;
    message = body.error?.message ?? message;
  } catch {
    /* not JSON: keep the generic message */
  }
  throw new ApiError(response.status, code, message);
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(BASE + path, { ...init, headers: headers(init.headers) });
  if (!response.ok) return fail(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function post<T>(path: string, body?: unknown): Promise<T> {
  return api<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export async function uploadCapture(file: File): Promise<{ id: string; status: string }> {
  const form = new FormData();
  form.append("file", file, file.name);
  return api("/investigations", { method: "POST", body: form });
}

/** Fetch a file with the auth header and hand it to the browser as a download. */
export async function download(path: string, filename: string): Promise<void> {
  const response = await fetch(BASE + path, { headers: headers() });
  if (!response.ok) return fail(response);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export const queryKeys = {
  investigations: ["investigations"] as const,
  investigation: (id: string) => ["investigation", id] as const,
  incidents: (id: string) => ["incidents", id] as const,
  anomalies: (id: string) => ["anomalies", id] as const,
  incident: (id: number) => ["incident", id] as const,
  evidence: (id: number, finding?: number) => ["evidence", id, finding ?? "all"] as const,
  slice: (id: number) => ["slice", id] as const,
  narrative: (id: number) => ["narrative", id] as const,
};
