import { describe, expect, it, vi } from "vitest";
import { api, ApiError, qs, request, setCsrfToken } from "../api/client";

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn(async (_url: string, _init?: RequestInit) =>
    new Response(typeof body === "string" ? body : JSON.stringify(body), {
      status,
      headers: { "content-type": typeof body === "string" ? "text/plain" : "application/json" },
    }),
  );
  vi.stubGlobal("fetch", fn);
  return fn;
}

function headersOf(fn: ReturnType<typeof vi.fn>, call = 0): Record<string, string> {
  return (fn.mock.calls[call][1] as RequestInit).headers as Record<string, string>;
}

describe("api client", () => {
  it("sends the CSRF token on state-changing requests only", async () => {
    setCsrfToken("tok-123");
    const fn = mockFetch(200, { ok: true });
    await api.get("/api/cases");
    await api.post("/api/cases/1/rebuild");
    await api.patch("/api/cases/1", { status: "closed" });
    expect(headersOf(fn, 0)["X-CSRF-Token"]).toBeUndefined();
    expect(headersOf(fn, 1)["X-CSRF-Token"]).toBe("tok-123");
    expect(headersOf(fn, 2)["X-CSRF-Token"]).toBe("tok-123");
    expect((fn.mock.calls[2][1] as RequestInit).method).toBe("PATCH");
    expect((fn.mock.calls[0][1] as RequestInit).credentials).toBe("same-origin");
  });

  it("does not set a JSON content-type for multipart uploads", async () => {
    setCsrfToken("t");
    const fn = mockFetch(201, { results: [] });
    const form = new FormData();
    form.append("files", new Blob(["x"]), "a.log");
    await api.upload("/api/cases/1/evidence", form);
    expect(headersOf(fn)["Content-Type"]).toBeUndefined();
    expect((fn.mock.calls[0][1] as RequestInit).body).toBe(form);
  });

  it("throws ApiError with string detail", async () => {
    mockFetch(415, { detail: "rejected: extension '.exe' does not match detected content 'Plain text'" });
    const err = (await request("/api/x").catch((e) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(415);
    expect(err.message).toMatch(/does not match detected content/);
  });

  it("throws ApiError with structured detail (duplicate evidence)", async () => {
    mockFetch(409, { detail: { message: "duplicate evidence", results: [{ existing_id: "EV-20261030-AAAAAAAA" }] } });
    const err = (await api.post("/api/cases/1/evidence").catch((e) => e)) as ApiError;
    expect(err.status).toBe(409);
    expect(err.message).toBe("duplicate evidence");
    expect((err.detail as { results: { existing_id: string }[] }).results[0].existing_id).toBe("EV-20261030-AAAAAAAA");
  });

  it("falls back to a generic message for non-JSON errors", async () => {
    mockFetch(502, "Bad gateway");
    const err = (await api.get("/api/x").catch((e) => e)) as ApiError;
    expect(err.message).toBe("Bad gateway");
  });

  it("builds query strings skipping empty values", () => {
    expect(qs({ a: 1, b: "", c: undefined, d: false, e: true, f: "x y" })).toBe("?a=1&e=true&f=x+y");
    expect(qs({})).toBe("");
  });
});
