import { useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { useCase } from "../auth/CaseContext";
import { Icon } from "./Icon";
import { Badge, cx, selectCls } from "./ui";

const NAV: { to: string; label: string; icon: string; group: string }[] = [
  { to: "/", label: "Overview", icon: "overview", group: "Investigation" },
  { to: "/cases", label: "Investigations", icon: "cases", group: "Investigation" },
  { to: "/evidence", label: "Evidence Vault", icon: "vault", group: "Investigation" },
  { to: "/malware", label: "Malware Analysis", icon: "malware", group: "Analysis" },
  { to: "/events", label: "Windows Events", icon: "events", group: "Analysis" },
  { to: "/browser", label: "Browser Forensics", icon: "browser", group: "Analysis" },
  { to: "/timeline", label: "Timeline", icon: "timeline", group: "Analysis" },
  { to: "/iocs", label: "IOC Explorer", icon: "ioc", group: "Analysis" },
  { to: "/custody", label: "Chain of Custody", icon: "custody", group: "Integrity" },
  { to: "/reports", label: "Reports", icon: "reports", group: "Integrity" },
  { to: "/settings", label: "System Settings", icon: "settings", group: "System" },
];

function Brand() {
  return (
    <div className="flex items-center gap-2.5 px-4 py-4">
      <svg viewBox="0 0 32 32" className="h-8 w-8" aria-hidden="true">
        <rect width="32" height="32" rx="7" fill="#131b28" stroke="#263246" />
        <path d="M8 9h16M16 9v15" stroke="#3fd0c9" strokeWidth="3" strokeLinecap="round" />
        <circle cx="16" cy="24" r="2.6" fill="#f59e0b" />
      </svg>
      <div className="leading-tight">
        <div className="text-[15px] font-bold tracking-wide text-ink-100">TraceForge</div>
        <div className="text-[10.5px] uppercase tracking-[0.14em] text-ink-400">DFIR Platform</div>
      </div>
    </div>
  );
}

function Nav({ onNavigate }: { onNavigate?: () => void }) {
  const groups = Array.from(new Set(NAV.map((n) => n.group)));
  return (
    <nav className="flex-1 overflow-y-auto px-2 pb-4" aria-label="Main">
      {groups.map((g) => (
        <div key={g} className="mt-3">
          <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-ink-500">{g}</div>
          {NAV.filter((n) => n.group === g).map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === "/"}
              onClick={onNavigate}
              className={({ isActive }) =>
                cx(
                  "group flex items-center gap-2.5 rounded-md px-3 py-1.5 text-[13.5px] transition-colors",
                  isActive ? "bg-accent-500/10 text-accent-400 ring-1 ring-inset ring-accent-500/25" : "text-ink-300 hover:bg-ink-800 hover:text-ink-100",
                )
              }
            >
              <Icon name={n.icon} className="h-4 w-4 shrink-0" />
              {n.label}
            </NavLink>
          ))}
        </div>
      ))}
    </nav>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const { cases, caseId, select, current } = useCase();
  const [menuOpen, setMenuOpen] = useState(false);
  const loc = useLocation();
  const page = NAV.find((n) => (n.to === "/" ? loc.pathname === "/" : loc.pathname.startsWith(n.to)));

  return (
    <div className="flex h-screen overflow-hidden bg-ink-950 text-ink-100">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-ink-800 bg-ink-900/70 lg:flex">
        <Brand />
        <Nav />
        <div className="border-t border-ink-800 px-4 py-3 text-[11px] text-ink-500">Evidence is analysed read-only. Samples are never executed.</div>
      </aside>

      {menuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMenuOpen(false)} />
          <aside className="relative flex h-full w-64 flex-col border-r border-ink-800 bg-ink-900">
            <Brand />
            <Nav onNavigate={() => setMenuOpen(false)} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-ink-800 bg-ink-900/60 px-4 backdrop-blur">
          <button type="button" className="rounded p-1.5 text-ink-300 hover:bg-ink-800 lg:hidden" onClick={() => setMenuOpen(true)} aria-label="Open navigation">
            <Icon name="menu" className="h-5 w-5" />
          </button>
          <div className="hidden whitespace-nowrap text-sm text-ink-400 xl:block">{page?.label}</div>
          <div className="ml-auto flex min-w-0 items-center gap-2 md:ml-6">
            <label htmlFor="case-select" className="hidden text-[11px] uppercase tracking-wider text-ink-500 sm:block">
              Case
            </label>
            <select
              id="case-select"
              className={cx(selectCls, "w-[min(56vw,340px)] font-mono text-[12.5px]")}
              value={caseId ?? ""}
              onChange={(e) => select(Number(e.target.value))}
              disabled={!cases.length}
            >
              {!cases.length && <option value="">No cases</option>}
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.case_number} — {c.title}
                </option>
              ))}
            </select>
            {current?.is_synthetic && (
              <Badge tone="warn" className="hidden sm:inline-flex" title="This case uses simulated evidence">
                SIMULATED
              </Badge>
            )}
          </div>
          <div className="ml-auto flex items-center gap-3">
            <div className="hidden text-right leading-tight md:block">
              <div className="text-[13px] text-ink-100">{user?.display_name}</div>
              <div className="text-[11px] uppercase tracking-wider text-ink-400">{user?.role}</div>
            </div>
            <button type="button" onClick={() => void logout()} className="rounded-md border border-ink-700 p-1.5 text-ink-300 hover:bg-ink-800 hover:text-ink-100" title="Sign out" aria-label="Sign out">
              <Icon name="logout" className="h-4 w-4" />
            </button>
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1600px] px-4 py-5 md:px-6">{children}</div>
        </main>
      </div>
    </div>
  );
}
