import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { Case } from "../api/types";

const STORAGE_KEY = "traceforge.caseId";

interface CaseState {
  cases: Case[];
  current: Case | null;
  caseId: number | null;
  select: (id: number) => void;
  refresh: () => Promise<void>;
  loading: boolean;
  error: Error | null;
}

const CaseCtx = createContext<CaseState | null>(null);

function readStored(): number | null {
  try {
    const v = window.localStorage.getItem(STORAGE_KEY);
    return v ? Number(v) : null;
  } catch {
    return null;
  }
}

export function CaseProvider({ children }: { children: ReactNode }) {
  const [cases, setCases] = useState<Case[]>([]);
  const [caseId, setCaseId] = useState<number | null>(readStored());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const refresh = useCallback(async () => {
    try {
      const list = await api.get<Case[]>("/api/cases");
      setCases(list);
      setError(null);
      setCaseId((cur) => (cur && list.some((c) => c.id === cur) ? cur : list[0]?.id ?? null));
    } catch (e) {
      setError(e as Error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    try {
      if (caseId) window.localStorage.setItem(STORAGE_KEY, String(caseId));
    } catch {
      /* storage unavailable: selection simply isn't remembered */
    }
  }, [caseId]);

  const value = useMemo<CaseState>(
    () => ({
      cases,
      caseId,
      current: cases.find((c) => c.id === caseId) ?? null,
      select: setCaseId,
      refresh,
      loading,
      error,
    }),
    [cases, caseId, refresh, loading, error],
  );
  return <CaseCtx.Provider value={value}>{children}</CaseCtx.Provider>;
}

export function useCase(): CaseState {
  const ctx = useContext(CaseCtx);
  if (!ctx) throw new Error("useCase outside CaseProvider");
  return ctx;
}
