// Minimal fetch wrapper: same-origin cookies, CSRF header on state-changing requests,
// and structured errors carrying the backend's `detail` payload.

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(status: number, detail: unknown) {
    super(ApiError.describe(status, detail));
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }

  static describe(status: number, detail: unknown): string {
    if (typeof detail === "string" && detail) return detail;
    if (detail && typeof detail === "object") {
      const d = detail as Record<string, unknown>;
      if (typeof d.message === "string") return d.message;
      if (typeof d.detail === "string") return d.detail;
    }
    return `Request failed (HTTP ${status})`;
  }
}

let csrfToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export function getCsrfToken() {
  return csrfToken;
}

export function onUnauthorized(handler: (() => void) | null) {
  unauthorizedHandler = handler;
}

const SAFE = new Set(["GET", "HEAD", "OPTIONS"]);

export interface RequestOptions {
  method?: string;
  body?: unknown;
  form?: FormData;
  signal?: AbortSignal;
  /** Do not trigger the global 401 handler (used by the session probe). */
  quiet401?: boolean;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = (opts.method ?? (opts.body !== undefined || opts.form ? "POST" : "GET")).toUpperCase();
  const headers: Record<string, string> = { Accept: "application/json" };
  let body: BodyInit | undefined;
  if (opts.form) {
    body = opts.form;
  } else if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  if (!SAFE.has(method) && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  const res = await fetch(path, { method, headers, body, credentials: "same-origin", signal: opts.signal });
  const type = res.headers.get("content-type") ?? "";
  const payload = type.includes("application/json") ? await res.json().catch(() => null) : await res.text().catch(() => "");
  if (!res.ok) {
    if (res.status === 401 && !opts.quiet401 && unauthorizedHandler) unauthorizedHandler();
    const detail = payload && typeof payload === "object" && "detail" in payload ? (payload as { detail: unknown }).detail : payload;
    throw new ApiError(res.status, detail);
  }
  return payload as T;
}

export const api = {
  get: <T,>(path: string, signal?: AbortSignal) => request<T>(path, { signal }),
  post: <T,>(path: string, body?: unknown) => request<T>(path, { method: "POST", body: body ?? {} }),
  put: <T,>(path: string, body: unknown) => request<T>(path, { method: "PUT", body }),
  patch: <T,>(path: string, body: unknown) => request<T>(path, { method: "PATCH", body }),
  upload: <T,>(path: string, form: FormData) => request<T>(path, { method: "POST", form }),
};

export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "" || v === false) continue;
    sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}
