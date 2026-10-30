import { useEffect, useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import { truncateMiddle, titleCase } from "../lib/format";
import { Icon } from "./Icon";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

// ------------------------------------------------------------------ layout

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-ink-100">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-ink-300">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className,
  bodyClass,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClass?: string;
}) {
  return (
    <section className={cx("rounded-lg border border-ink-700/80 bg-ink-900 shadow-panel", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-ink-700/70 px-4 py-2.5">
          <div className="min-w-0">
            {title && <h2 className="text-[13px] font-semibold uppercase tracking-wider text-ink-200">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-ink-400">{subtitle}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cx("p-4", bodyClass)}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, hint, tone = "default" }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "default" | "danger" | "warn" | "ok" | "accent" }) {
  const toneCls = {
    default: "text-ink-100",
    danger: "text-rose-300",
    warn: "text-amber-300",
    ok: "text-emerald-300",
    accent: "text-accent-400",
  }[tone];
  return (
    <div className="rounded-lg border border-ink-700/80 bg-ink-900 px-4 py-3 shadow-panel">
      <div className="text-[11px] font-medium uppercase tracking-wider text-ink-400">{label}</div>
      <div className={cx("mt-1 text-2xl font-semibold tabular-nums", toneCls)}>{value}</div>
      {hint && <div className="mt-0.5 truncate text-xs text-ink-400">{hint}</div>}
    </div>
  );
}

// ------------------------------------------------------------------ buttons & inputs

type Variant = "primary" | "secondary" | "ghost" | "danger";

export function Button({
  variant = "secondary",
  size = "md",
  busy,
  icon,
  children,
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: "sm" | "md"; busy?: boolean; icon?: string }) {
  const v = {
    primary: "bg-accent-500 text-ink-950 hover:bg-accent-400 border-accent-400/60 font-semibold",
    secondary: "bg-ink-800 text-ink-100 hover:bg-ink-700 border-ink-600",
    ghost: "bg-transparent text-ink-200 hover:bg-ink-800 border-transparent",
    danger: "bg-rose-600/90 text-white hover:bg-rose-500 border-rose-500/60",
  }[variant];
  const s = size === "sm" ? "h-7 px-2.5 text-xs" : "h-8 px-3 text-sm";
  return (
    <button
      type="button"
      {...rest}
      disabled={rest.disabled || busy}
      className={cx(
        "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md border transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-400/60 disabled:cursor-not-allowed disabled:opacity-50",
        v,
        s,
        className,
      )}
    >
      {busy ? <Spinner className="h-3.5 w-3.5" /> : icon ? <Icon name={icon} className="h-3.5 w-3.5" /> : null}
      {children}
    </button>
  );
}

export const inputCls =
  "h-8 w-full rounded-md border border-ink-600 bg-ink-850 px-2.5 text-sm text-ink-100 placeholder:text-ink-400 focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500/50 disabled:cursor-not-allowed disabled:opacity-60";
export const selectCls = inputCls + " pr-7";
export const textareaCls =
  "w-full rounded-md border border-ink-600 bg-ink-850 px-2.5 py-2 text-sm text-ink-100 placeholder:text-ink-400 focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500/50 disabled:cursor-not-allowed disabled:opacity-60";

export function Label({ children, htmlFor }: { children: ReactNode; htmlFor?: string }) {
  return (
    <label htmlFor={htmlFor} className="mb-1 block text-[11px] font-medium uppercase tracking-wider text-ink-400">
      {children}
    </label>
  );
}

export function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <div className="relative w-full sm:w-64">
      <Icon name="search" className="pointer-events-none absolute left-2.5 top-2 h-4 w-4 text-ink-400" />
      <input className={cx(inputCls, "pl-8")} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder ?? "Search…"} aria-label={placeholder ?? "Search"} />
    </div>
  );
}

// ------------------------------------------------------------------ badges

const SEV_STYLE: Record<string, string> = {
  critical: "bg-rose-600/25 text-rose-200 ring-rose-500/50",
  high: "bg-red-500/15 text-red-300 ring-red-500/40",
  medium: "bg-amber-500/15 text-amber-300 ring-amber-500/40",
  low: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
  info: "bg-ink-600/40 text-ink-200 ring-ink-500/60",
};

export const SEV_HEX: Record<string, string> = {
  critical: "#e11d48",
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#64748b",
};

export function SeverityChip({ severity, className }: { severity: string; className?: string }) {
  return (
    <span className={cx("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10.5px] font-bold uppercase tracking-wider ring-1 ring-inset", SEV_STYLE[severity] ?? SEV_STYLE.info, className)}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_HEX[severity] ?? SEV_HEX.info }} />
      {severity}
    </span>
  );
}

const CLASS_LABEL: Record<string, string> = {
  confirmed_rule_match: "Confirmed rule match",
  suspicious: "Suspicious",
  informational: "Informational",
  inconclusive: "Inconclusive",
  hypothesis: "Hypothesis",
};
const CLASS_STYLE: Record<string, string> = {
  confirmed_rule_match: "border-fuchsia-400/50 bg-fuchsia-500/10 text-fuchsia-200",
  suspicious: "border-amber-400/50 bg-amber-500/10 text-amber-200",
  informational: "border-ink-500 bg-ink-800 text-ink-200",
  inconclusive: "border-ink-400/60 border-dashed bg-transparent text-ink-300",
  hypothesis: "border-violet-400/50 border-dashed bg-violet-500/10 text-violet-200",
};

export function ClassificationBadge({ classification }: { classification: string }) {
  return (
    <span className={cx("inline-flex items-center whitespace-nowrap rounded border px-1.5 py-0.5 text-[11px] font-medium", CLASS_STYLE[classification] ?? CLASS_STYLE.informational)}>
      {CLASS_LABEL[classification] ?? titleCase(classification)}
    </span>
  );
}

type Tone = "neutral" | "ok" | "warn" | "danger" | "info" | "accent" | "violet";
const TONE: Record<Tone, string> = {
  neutral: "bg-ink-700/60 text-ink-200 ring-ink-500/60",
  ok: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40",
  warn: "bg-amber-500/15 text-amber-300 ring-amber-500/40",
  danger: "bg-rose-500/15 text-rose-300 ring-rose-500/40",
  info: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
  accent: "bg-accent-500/15 text-accent-400 ring-accent-500/40",
  violet: "bg-violet-500/15 text-violet-200 ring-violet-500/40",
};

export function Badge({ tone = "neutral", children, className, title }: { tone?: Tone; children: ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cx("inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", TONE[tone], className)}>
      {children}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, Tone> = {
    complete: "ok",
    verified: "ok",
    match: "ok",
    partial: "warn",
    running: "info",
    pending: "neutral",
    error: "danger",
    mismatch: "danger",
    missing: "danger",
    refused: "danger",
    skipped: "warn",
    timeout: "warn",
  };
  return <Badge tone={map[status] ?? "neutral"}>{titleCase(status)}</Badge>;
}

export function AssessmentBadge({ assessment }: { assessment: string }) {
  const map: Record<string, [Tone, string]> = {
    watchlist_match: ["danger", "Watchlist match"],
    suspicious: ["warn", "Suspicious"],
    observed: ["neutral", "Observed"],
    benign_context: ["ok", "Benign context"],
  };
  const [tone, label] = map[assessment] ?? ["neutral", titleCase(assessment)];
  return <Badge tone={tone}>{label}</Badge>;
}

export function ConfidenceTag({ value }: { value: string }) {
  const bars = value === "high" ? 3 : value === "medium" ? 2 : 1;
  return (
    <span className="inline-flex items-center gap-1 text-[11px] text-ink-300" title={`Confidence: ${value}`}>
      <span className="inline-flex items-end gap-[2px]">
        {[1, 2, 3].map((b) => (
          <span key={b} className={cx("w-[3px] rounded-sm", b <= bars ? "bg-accent-400" : "bg-ink-600")} style={{ height: 3 + b * 3 }} />
        ))}
      </span>
      {value}
    </span>
  );
}

// ------------------------------------------------------------------ data display

export function CopyButton({ value, label }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1200);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard?.writeText(value).then(() => setDone(true), () => undefined);
      }}
      className="inline-flex shrink-0 items-center rounded p-0.5 text-ink-400 hover:bg-ink-700 hover:text-ink-100"
      title={label ?? "Copy to clipboard"}
      aria-label={label ?? "Copy to clipboard"}
    >
      <Icon name={done ? "check" : "copy"} className="h-3.5 w-3.5" />
    </button>
  );
}

export function Hash({ value, keep = 10, full }: { value: string | null | undefined; keep?: number; full?: boolean }) {
  if (!value) return <span className="text-ink-400">–</span>;
  return (
    <span className="inline-flex max-w-full items-center gap-1">
      <span className={cx("font-mono text-[12px] text-ink-200", full ? "break-all" : "whitespace-nowrap")} title={value}>
        {full ? value : truncateMiddle(value, keep)}
      </span>
      <CopyButton value={value} />
    </span>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx("font-mono text-[12px] text-ink-200", className)}>{children}</span>;
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-1.5 text-sm">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-xs uppercase tracking-wider text-ink-400">{k}</dt>
          <dd className="min-w-0 break-words text-ink-100">{v ?? "–"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Spinner({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg className={cx("animate-spin text-current", className)} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 px-1 py-6 text-sm text-ink-300">
      <Spinner /> {label}
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: Error | null; onRetry?: () => void }) {
  if (!error) return null;
  return (
    <div className="flex items-start justify-between gap-3 rounded-md border border-rose-500/40 bg-rose-950/40 px-3 py-2 text-sm text-rose-200" role="alert">
      <span className="flex items-start gap-2">
        <Icon name="alert" className="mt-0.5 h-4 w-4 shrink-0" />
        {error.message}
      </span>
      {onRetry && (
        <Button size="sm" variant="ghost" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-md border border-dashed border-ink-600 px-4 py-8 text-center text-sm text-ink-400">{children}</div>;
}

export function Drawer({ open, onClose, title, children, width = "max-w-3xl" }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; width?: string }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className={cx("relative flex h-full w-full flex-col border-l border-ink-700 bg-ink-900 shadow-2xl", width)}>
        <div className="flex items-center justify-between gap-3 border-b border-ink-700 px-5 py-3">
          <div className="min-w-0 text-base font-semibold text-ink-100">{title}</div>
          <button type="button" onClick={onClose} className="rounded p-1 text-ink-300 hover:bg-ink-700 hover:text-ink-100" aria-label="Close">
            <Icon name="x" className="h-5 w-5" />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </div>
  );
}

// Shared table classes: dense, zebra-free with hover, sticky header.
export const tableCls = "w-full border-collapse text-left text-[13px]";
export const thCls = "sticky top-0 z-[1] whitespace-nowrap border-b border-ink-700 bg-ink-850 px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-ink-400";
export const tdCls = "border-b border-ink-800 px-3 py-2 align-top text-ink-200";
export const trCls = "hover:bg-ink-800/60";

export function TableWrap({ children, maxH }: { children: ReactNode; maxH?: string }) {
  return <div className={cx("overflow-auto rounded-md border border-ink-700/80", maxH)}>{children}</div>;
}

export function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md border border-ink-700 bg-ink-950 p-3 font-mono text-[11.5px] leading-relaxed text-ink-200">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: { id: T; label: ReactNode }[] }) {
  return (
    <div className="mb-4 flex gap-1 overflow-x-auto border-b border-ink-700" role="tablist">
      {items.map((it) => (
        <button
          key={it.id}
          type="button"
          role="tab"
          aria-selected={value === it.id}
          onClick={() => onChange(it.id)}
          className={cx(
            "-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm",
            value === it.id ? "border-accent-400 text-ink-100" : "border-transparent text-ink-400 hover:text-ink-200",
          )}
        >
          {it.label}
        </button>
      ))}
    </div>
  );
}
