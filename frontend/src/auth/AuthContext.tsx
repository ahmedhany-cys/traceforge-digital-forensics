import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, onUnauthorized, request, setCsrfToken } from "../api/client";
import type { Role, User } from "../api/types";

interface AuthState {
  user: User | null;
  ready: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (role: Role) => boolean;
}

const RANK: Record<Role, number> = { viewer: 0, investigator: 1, admin: 2 };

const AuthCtx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    onUnauthorized(() => {
      setCsrfToken(null);
      setUser(null);
    });
    request<{ user: User; csrf_token: string }>("/api/auth/me", { quiet401: true })
      .then((r) => {
        setCsrfToken(r.csrf_token);
        setUser(r.user);
      })
      .catch(() => setUser(null))
      .finally(() => setReady(true));
    return () => onUnauthorized(null);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const r = await request<{ user: User; csrf_token: string }>("/api/auth/login", {
      method: "POST",
      body: { username, password },
      quiet401: true,
    });
    setCsrfToken(r.csrf_token);
    setUser(r.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post("/api/auth/logout");
    } finally {
      setCsrfToken(null);
      setUser(null);
    }
  }, []);

  const can = useCallback((role: Role) => !!user && RANK[user.role] >= RANK[role], [user]);

  return <AuthCtx.Provider value={{ user, ready, login, logout, can }}>{children}</AuthCtx.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}
