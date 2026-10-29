const API_BASE = process.env.NEXT_PUBLIC_API_URL?.replace(/\/+$/, '')
  || (process.env.NODE_ENV === 'development' ? 'http://localhost:8000' : '');

function apiEndpoint(path: string): string {
  if (!API_BASE) {
    throw new Error('Set NEXT_PUBLIC_API_URL to the deployed Sakshya API URL.');
  }
  return `${API_BASE}/api/v1${path}`;
}

export const ROLES = [
  { id: 'scrutiny_officer', actor: 'officer.demo', label: 'Scrutiny officer' },
  { id: 'specialist_reviewer', actor: 'reviewer.demo', label: 'Specialist reviewer' },
  { id: 'applicant', actor: 'applicant.demo', label: 'Applicant' },
  { id: 'rule_author', actor: 'author.demo', label: 'Rule author' },
  { id: 'regulatory_expert', actor: 'expert.demo', label: 'Regulatory expert' },
  { id: 'competent_authority', actor: 'authority.demo', label: 'Competent authority' },
  { id: 'administrator', actor: 'admin.demo', label: 'Administrator' },
] as const;

export type Session = { role: string; actor: string };
let session: Session = { role: 'scrutiny_officer', actor: 'officer.demo' };
export const setApiSession = (s: Session) => { session = s; };
export const getApiSession = () => session;

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}

const headers = (extra?: Record<string, string>) => ({ 'X-Role': session.role, 'X-Actor': session.actor, ...extra });

export async function api<T = any>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const { json, ...rest } = init;
  const res = await fetch(apiEndpoint(path), {
    ...rest,
    headers: headers(json !== undefined ? { 'Content-Type': 'application/json' } : undefined),
    body: json !== undefined ? JSON.stringify(json) : rest.body,
  });
  if (!res.ok) {
    let msg = res.statusText;
    try { const b = await res.json(); msg = typeof b.detail === 'string' ? b.detail : JSON.stringify(b.detail); } catch { /* ignore */ }
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<T>;
}

/** Fetch binary content with auth headers so access is attributed in the audit trail. */
export async function blobUrl(path: string): Promise<string> {
  const res = await fetch(apiEndpoint(path), { headers: headers() });
  if (!res.ok) throw new ApiError(res.status, 'could not load file');
  return URL.createObjectURL(await res.blob());
}

export async function upload(appId: string, file: File, replaces?: string) {
  const fd = new FormData();
  fd.append('file', file);
  if (replaces) fd.append('replaces', replaces);
  const res = await fetch(apiEndpoint(`/applications/${appId}/documents`), { method: 'POST', headers: headers(), body: fd });
  if (!res.ok) { const b = await res.json().catch(() => ({})); throw new ApiError(res.status, b.detail || 'upload failed'); }
  return res.json();
}
