"use client";

import { useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";

interface TenantAuth {
  slug: string;
  adminKey: string;
}

interface Props {
  onLogin: (auth: TenantAuth) => void;
}

export default function TenantSelector({ onLogin }: Props) {
  const [slug, setSlug] = useState("");
  const [adminKey, setAdminKey] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    // Verify credentials by fetching the tenant's license list
    try {
      const res = await fetch(`${API}/tenant/licenses`, {
        headers: {
          "X-Tenant-ID": slug,
          "X-Admin-Key": adminKey,
        },
      });
      if (res.status === 401) {
        setError("Invalid tenant ID or admin key.");
      } else if (res.status === 403) {
        setError("This tenant account is deactivated.");
      } else if (res.status === 404) {
        setError(`Tenant '${slug}' not found.`);
      } else if (!res.ok) {
        setError(`Server error: ${res.status}`);
      } else {
        onLogin({ slug, adminKey });
      }
    } catch {
      setError("Network error. Is the API running?");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 p-4">
      <div className="w-full max-w-sm bg-slate-900 rounded-2xl border border-slate-700 p-8 shadow-2xl">
        <h1 className="text-2xl font-bold text-white mb-2">Tenant Login</h1>
        <p className="text-slate-400 text-sm mb-6">
          Enter your organisation&apos;s slug and admin key to access your
          DRM dashboard.
        </p>

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-slate-300 text-sm mb-1">
              Organisation Slug
            </label>
            <input
              type="text"
              value={slug}
              onChange={(e) => setSlug(e.target.value.toLowerCase().trim())}
              placeholder="e.g. acme-corp"
              required
              className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-slate-300 text-sm mb-1">
              Admin Key
            </label>
            <input
              type="password"
              value={adminKey}
              onChange={(e) => setAdminKey(e.target.value)}
              placeholder="Your secret admin key"
              required
              className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {error && (
            <p className="text-red-400 text-sm bg-red-900/30 border border-red-800 rounded-lg px-3 py-2">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold rounded-lg py-2 transition-colors"
          >
            {loading ? "Verifying..." : "Login"}
          </button>
        </form>
      </div>
    </div>
  );
}
