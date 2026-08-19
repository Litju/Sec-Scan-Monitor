"use client";

import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { createAuthClient, type VanillaBetterAuthClient } from "@neondatabase/auth";
import { getHostedAuthToken, resolveApiMode } from "@/lib/api/client";

type AuthClient = VanillaBetterAuthClient;

function authUrl(): string | undefined {
  const value = process.env.NEXT_PUBLIC_NEON_AUTH_URL?.trim();
  return value || undefined;
}

function AuthMessage({ children }: { children: ReactNode }) {
  return <main className="page-canvas"><section className="surface-panel panel-pad" aria-live="polite">{children}</section></main>;
}

function HostedAuthContent({ children }: { children: ReactNode }) {
  const [client] = useState<AuthClient | null>(() => {
    const url = authUrl();
    return url ? createAuthClient(url) as AuthClient : null;
  });
  const [session, setSession] = useState<unknown>(null);
  const [loading, setLoading] = useState(() => client !== null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let active = true;
    if (!client) {
      return () => { active = false; };
    }
    void client.getSession().then((result) => {
      if (active) setSession(result.data ?? null);
    }).catch(() => {
      if (active) setError("Hosted session could not be verified.");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [client]);

  async function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client) return;
    setSubmitting(true);
    setError("");
    try {
      const result = await client.signIn.email({ email, password });
      if (result.error) throw new Error(result.error.message || "Sign-in failed.");
      const current = await client.getSession();
      setSession(current.data ?? null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Sign-in failed.");
    } finally {
      setSubmitting(false);
    }
  }

  async function signOut() {
    if (!client) return;
    setError("");
    try {
      const token = await getHostedAuthToken();
      const revoke = await fetch("/api/secscan/auth/revoke", {
        method: "POST",
        headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
        cache: "no-store",
      });
      if (!revoke.ok) throw new Error("Hosted session could not be revoked.");
      await client.signOut();
      setSession(null);
    } catch {
      setError("Sign-out failed.");
    }
  }

  if (!client) return <AuthMessage><h1 className="panel-title">Hosted authentication is not configured</h1><p className="panel-description">No preview fallback is active. Configure the Neon Auth URL before using HOSTED_INTEGRATED mode.</p></AuthMessage>;
  if (loading) return <AuthMessage><p className="panel-description">Verifying hosted session…</p></AuthMessage>;
  if (!session) return <AuthMessage><p className="eyebrow">SecScanMonitor · hosted sign-in</p><h1 className="panel-title">Sign in</h1><p className="panel-description">Use the Neon Auth account provisioned for this staging tenant.</p><form onSubmit={signIn} className="stack"><label>Email<input required type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label><label>Password<input required type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>{error ? <p role="alert" className="status danger">{error}</p> : null}<button className="button primary" type="submit" disabled={submitting}>{submitting ? "Signing in…" : "Sign in"}</button></form></AuthMessage>;
  return <>
    <div className="auth-session-bar"><span className="small muted">Authenticated hosted session</span><button className="button" type="button" onClick={signOut}>Sign out</button></div>
    {error ? <p role="alert" className="status danger">{error}</p> : null}
    {children}
  </>;
}

export function HostedAuthBoundary({ children }: { children: ReactNode }) {
  let mode: string;
  try {
    mode = resolveApiMode();
  } catch {
    return <>{children}</>;
  }
  return mode === "HOSTED_INTEGRATED" ? <HostedAuthContent>{children}</HostedAuthContent> : <>{children}</>;
}
