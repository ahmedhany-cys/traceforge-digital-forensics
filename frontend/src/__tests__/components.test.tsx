import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth/AuthContext";
import { FindingList } from "../components/FindingList";
import { AssessmentBadge, ClassificationBadge, SeverityChip } from "../components/ui";
import LoginPage from "../pages/Login";
import type { Finding } from "../api/types";

describe("badges", () => {
  it("renders classification labels", () => {
    render(
      <div>
        <ClassificationBadge classification="confirmed_rule_match" />
        <ClassificationBadge classification="suspicious" />
        <ClassificationBadge classification="hypothesis" />
        <ClassificationBadge classification="inconclusive" />
      </div>,
    );
    expect(screen.getByText("Confirmed rule match")).toBeInTheDocument();
    expect(screen.getByText("Suspicious")).toBeInTheDocument();
    expect(screen.getByText("Hypothesis")).toBeInTheDocument();
    expect(screen.getByText("Inconclusive")).toBeInTheDocument();
  });

  it("renders severity chip text and IOC assessments", () => {
    render(
      <div>
        <SeverityChip severity="high" />
        <AssessmentBadge assessment="watchlist_match" />
        <AssessmentBadge assessment="benign_context" />
      </div>,
    );
    expect(screen.getByText("high")).toBeInTheDocument();
    expect(screen.getByText("Watchlist match")).toBeInTheDocument();
    expect(screen.getByText("Benign context")).toBeInTheDocument();
  });
});

describe("FindingList", () => {
  const finding: Finding = {
    id: 7, case_id: 1, evidence_id: "EV-20261030-AAAAAAAA", source: "evtx", rule_id: "WIN-PROC-002",
    title: "Executable with a document-style double extension was run", classification: "suspicious", severity: "high",
    confidence: "high", description: "<img src=x onerror=alert(1)> C:\\Users\\x\\a.pdf.exe", rationale: "Double extensions disguise executables.",
    event_time: "2026-10-14T13:43:10.482+00:00", source_ref: { record_number: 88418 },
  };

  it("expands to show rationale and renders evidence strings as text", async () => {
    render(<FindingList findings={[finding]} />);
    expect(screen.queryByText(/Double extensions disguise/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /double extension/i }));
    expect(screen.getByText(/Double extensions disguise/)).toBeInTheDocument();
    // markup in evidence-derived text must not become DOM elements
    expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it("shows an empty state", () => {
    render(<FindingList findings={[]} empty="Nothing here." />);
    expect(screen.getByText("Nothing here.")).toBeInTheDocument();
  });
});

describe("LoginPage", () => {
  it("submits credentials to the login endpoint and surfaces errors", async () => {
    const fetchMock = vi.fn(async (url: string, _init?: RequestInit) => {
      if (url === "/api/auth/me") return new Response(JSON.stringify({ detail: "authentication required" }), { status: 401, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify({ detail: "invalid username or password" }), { status: 401, headers: { "content-type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);
    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>,
    );
    await userEvent.type(screen.getByLabelText("Username"), "arivera");
    await userEvent.type(screen.getByLabelText("Password"), "wrong-password-123");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("invalid username or password"));
    const loginCall = fetchMock.mock.calls.find((c) => c[0] === "/api/auth/login")!;
    const init = loginCall[1] as unknown as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ username: "arivera", password: "wrong-password-123" });
    expect((screen.getByLabelText("Password") as HTMLInputElement).value).toBe("");
  });
});
