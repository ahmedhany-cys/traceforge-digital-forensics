import { useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import { Button, inputCls, Label } from "../components/ui";

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError((err as Error).message);
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-ink-950 bg-[radial-gradient(ellipse_at_top,rgba(31,181,174,0.10),transparent_60%)] px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-3">
          <svg viewBox="0 0 32 32" className="h-10 w-10" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="#131b28" stroke="#263246" />
            <path d="M8 9h16M16 9v15" stroke="#3fd0c9" strokeWidth="3" strokeLinecap="round" />
            <circle cx="16" cy="24" r="2.6" fill="#f59e0b" />
          </svg>
          <div>
            <div className="text-xl font-bold tracking-wide text-ink-100">TraceForge</div>
            <div className="text-xs uppercase tracking-[0.16em] text-ink-400">Digital Forensics &amp; Threat Investigation</div>
          </div>
        </div>
        <form onSubmit={submit} className="rounded-lg border border-ink-700 bg-ink-900 p-6 shadow-panel" aria-label="Sign in">
          <h1 className="mb-4 text-base font-semibold text-ink-100">Investigator sign-in</h1>
          <div className="mb-3">
            <Label htmlFor="username">Username</Label>
            <input id="username" className={inputCls} autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required maxLength={64} autoFocus />
          </div>
          <div className="mb-4">
            <Label htmlFor="password">Password</Label>
            <input id="password" type="password" className={inputCls} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required maxLength={256} />
          </div>
          {error && (
            <div className="mb-3 rounded-md border border-rose-500/40 bg-rose-950/40 px-3 py-2 text-sm text-rose-200" role="alert">
              {error}
            </div>
          )}
          <Button type="submit" variant="primary" className="w-full" busy={busy}>
            Sign in
          </Button>
          <p className="mt-4 text-xs leading-relaxed text-ink-400">
            Access is logged to the tamper-evident audit ledger. Repeated failures temporarily lock the account.
          </p>
        </form>
      </div>
    </div>
  );
}
