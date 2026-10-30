import { useState } from "react";
import type { Finding } from "../api/types";
import { formatUtc } from "../lib/format";
import { ClassificationBadge, ConfidenceTag, cx, Empty, JsonBlock, Mono, SeverityChip } from "./ui";

/** Expandable list of findings with classification, severity, confidence and the rule's rationale. */
export function FindingList({ findings, empty = "No findings.", showEvidence = true }: { findings: Finding[]; empty?: string; showEvidence?: boolean }) {
  const [open, setOpen] = useState<number | null>(null);
  if (!findings.length) return <Empty>{empty}</Empty>;
  return (
    <ul className="divide-y divide-ink-800 rounded-md border border-ink-700/80">
      {findings.map((f) => {
        const isOpen = open === f.id;
        return (
          <li key={f.id} className={cx("px-3 py-2.5", isOpen && "bg-ink-850")}>
            <button type="button" className="flex w-full flex-wrap items-start gap-x-3 gap-y-1 text-left" onClick={() => setOpen(isOpen ? null : f.id)} aria-expanded={isOpen}>
              <SeverityChip severity={f.severity} className="mt-0.5" />
              <span className="min-w-0 flex-1">
                <span className="block text-[13.5px] font-medium text-ink-100 [overflow-wrap:anywhere]">{f.title}</span>
                <span className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-ink-400">
                  <Mono className="text-ink-300">{f.rule_id}</Mono>
                  <span>·</span>
                  <span>{f.source}</span>
                  {f.event_time && (
                    <>
                      <span>·</span>
                      <span className="font-mono">{formatUtc(f.event_time)} UTC</span>
                    </>
                  )}
                  {showEvidence && f.evidence_id && (
                    <>
                      <span>·</span>
                      <Mono className="text-ink-400">{f.evidence_id}</Mono>
                    </>
                  )}
                </span>
              </span>
              <span className="flex items-center gap-2">
                <ClassificationBadge classification={f.classification} />
                <ConfidenceTag value={f.confidence} />
              </span>
            </button>
            {isOpen && (
              <div className="mt-3 space-y-2 border-l-2 border-ink-600 pl-3 text-sm">
                <p className="whitespace-pre-wrap break-words text-ink-200">{f.description}</p>
                <div>
                  <div className="text-[11px] uppercase tracking-wider text-ink-400">Why this was flagged</div>
                  <p className="whitespace-pre-wrap text-ink-300">{f.rationale}</p>
                </div>
                {Object.keys(f.source_ref ?? {}).length > 0 && (
                  <div>
                    <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-400">Source reference</div>
                    <JsonBlock value={f.source_ref} />
                  </div>
                )}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
