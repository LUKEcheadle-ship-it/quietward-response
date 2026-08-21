const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8002";
const ANALYST_SESSION_KEY = "qwr.analyst.bearer";

function errorMessageFromPayload(payload: unknown): string | null {
  if (!payload || typeof payload !== "object") return null;
  const value = payload as Record<string, unknown>;
  const detail = value.detail;
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object") {
    const detailValue = detail as Record<string, unknown>;
    if (typeof detailValue.message === "string") return detailValue.message;
    if (typeof detailValue.code === "string") return detailValue.code.replaceAll("_", " ");
  }
  if (typeof value.message === "string") return value.message;
  return null;
}

export function analystTokenConfigured(): boolean {
  if (typeof window === "undefined") return false;
  return Boolean(window.sessionStorage.getItem(ANALYST_SESSION_KEY));
}

export function setAnalystToken(token: string): void {
  if (typeof window === "undefined") return;
  const value = token.trim();
  if (!value) throw new Error("Analyst token cannot be empty");
  if (value.length > 512) throw new Error("Analyst token is too long");
  window.sessionStorage.setItem(ANALYST_SESSION_KEY, value);
}

export function clearAnalystToken(): void {
  if (typeof window === "undefined") return;
  window.sessionStorage.removeItem(ANALYST_SESSION_KEY);
}

function analystAuthorizationHeader(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = window.sessionStorage.getItem(ANALYST_SESSION_KEY);
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    cache: "no-store",
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...analystAuthorizationHeader(),
      ...(init?.headers || {})
    }
  });
  if (!response.ok) {
    let detail: string | null = null;
    try {
      detail = errorMessageFromPayload(await response.clone().json());
    } catch {
      try {
        const text = (await response.text()).trim();
        detail = text || null;
      } catch {
        detail = null;
      }
    }
    throw new Error(detail ? `API request failed (${response.status}): ${detail}` : `API request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

export function formatRelative(value: string): string {
  const seconds = Math.round((new Date(value).getTime() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, "second");
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute");
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return formatter.format(hours, "hour");
  return formatter.format(Math.round(hours / 24), "day");
}
