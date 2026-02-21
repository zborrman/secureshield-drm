"use client";

import { useState, useEffect, useCallback } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";

interface Tenant {
  id: number;
  name: string;
  slug: string;
  plan: string;
  max_licenses: number;
  max_vault_mb: number;
  is_active: boolean;
  created_at: string;
}

interface Props {
  superAdminKey: string;
}

export default function SuperAdminDashboard({ superAdminKey }: Props) {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Create-tenant form state
  const [newName, setNewName] = useState("");
  const [newSlug, setNewSlug] = useState("");
  const [newKey, setNewKey] = useState("");
  const [newPlan, setNewPlan] = useState("starter");
  const [newMaxLic, setNewMaxLic] = useState(10);
  const [newMaxVault, setNewMaxVault] = useState(100);
  const [createMsg, setCreateMsg] = useState("");

  const headers = { "X-Super-Admin-Key": superAdminKey };

  const fetchTenants = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/superadmin/tenants`, { headers });
      if (!res.ok) throw new Error(await res.text());
      setTenants(await res.json());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [superAdminKey]);

  useEffect(() => {
    fetchTenants();
  }, [fetchTenants]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreateMsg("");
    const params = new URLSearchParams({
      name: newName,
      slug: newSlug,
      admin_key: newKey,
      plan: newPlan,
      max_licenses: String(newMaxLic),
      max_vault_mb: String(newMaxVault),
    });
    const res = await fetch(`${API}/superadmin/tenants?${params}`, {
      method: "POST",
      headers,
    });
    if (!res.ok) {
      setCreateMsg(`Error: ${(await res.json()).detail}`);
    } else {
      setCreateMsg("Tenant created.");
      setNewName(""); setNewSlug(""); setNewKey("");
      fetchTenants();
    }
  }

  async function toggleActive(slug: string, currentActive: boolean) {
    await fetch(
      `${API}/superadmin/tenants/${slug}?is_active=${!currentActive}`,
      { method: "PATCH", headers }
    );
    fetchTenants();
  }

  async function handleDelete(slug: string) {
    if (!confirm(`Delete tenant "${slug}"? This cannot be undone.`)) return;
    await fetch(`${API}/superadmin/tenants/${slug}`, { method: "DELETE", headers });
    fetchTenants();
  }

  return (
    <div className="space-y-8">
      <h2 className="text-2xl font-bold text-white">Super Admin — Tenant Management</h2>

      {/* Create tenant */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
        <h3 className="text-lg font-semibold text-slate-200 mb-4">Create New Tenant</h3>
        <form onSubmit={handleCreate} className="grid grid-cols-2 gap-4">
          <input
            value={newName} onChange={(e) => setNewName(e.target.value)}
            placeholder="Organisation name" required
            className="col-span-2 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-slate-400"
          />
          <input
            value={newSlug} onChange={(e) => setNewSlug(e.target.value.toLowerCase())}
            placeholder="slug (e.g. acme-corp)" required
            className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-slate-400"
          />
          <input
            type="password"
            value={newKey} onChange={(e) => setNewKey(e.target.value)}
            placeholder="Admin key (shown once)" required
            className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-slate-400"
          />
          <select
            value={newPlan} onChange={(e) => setNewPlan(e.target.value)}
            className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white"
          >
            <option value="starter">Starter</option>
            <option value="pro">Pro</option>
            <option value="enterprise">Enterprise</option>
          </select>
          <div className="flex gap-2">
            <input
              type="number" value={newMaxLic} min={1}
              onChange={(e) => setNewMaxLic(Number(e.target.value))}
              placeholder="Max licenses"
              className="w-1/2 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white"
            />
            <input
              type="number" value={newMaxVault} min={1}
              onChange={(e) => setNewMaxVault(Number(e.target.value))}
              placeholder="Max vault MB"
              className="w-1/2 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-white"
            />
          </div>
          <button
            type="submit"
            className="col-span-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg py-2 transition-colors"
          >
            Create Tenant
          </button>
          {createMsg && <p className="col-span-2 text-sm text-slate-300">{createMsg}</p>}
        </form>
      </div>

      {/* Tenant list */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
        <h3 className="text-lg font-semibold text-slate-200 mb-4">
          All Tenants ({tenants.length})
        </h3>
        {error && <p className="text-red-400 mb-4">{error}</p>}
        {loading ? (
          <p className="text-slate-400">Loading...</p>
        ) : tenants.length === 0 ? (
          <p className="text-slate-500 text-sm">No tenants yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead>
                <tr className="text-slate-400 border-b border-slate-700">
                  <th className="pb-2 pr-4">Name</th>
                  <th className="pb-2 pr-4">Slug</th>
                  <th className="pb-2 pr-4">Plan</th>
                  <th className="pb-2 pr-4">Max Lic.</th>
                  <th className="pb-2 pr-4">Vault MB</th>
                  <th className="pb-2 pr-4">Status</th>
                  <th className="pb-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {tenants.map((t) => (
                  <tr key={t.slug} className="border-b border-slate-700/50 text-slate-300">
                    <td className="py-2 pr-4 font-medium text-white">{t.name}</td>
                    <td className="py-2 pr-4 font-mono text-blue-400">{t.slug}</td>
                    <td className="py-2 pr-4 capitalize">{t.plan}</td>
                    <td className="py-2 pr-4">{t.max_licenses}</td>
                    <td className="py-2 pr-4">{t.max_vault_mb}</td>
                    <td className="py-2 pr-4">
                      <span
                        className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
                          t.is_active
                            ? "bg-green-900/50 text-green-400"
                            : "bg-red-900/50 text-red-400"
                        }`}
                      >
                        {t.is_active ? "Active" : "Deactivated"}
                      </span>
                    </td>
                    <td className="py-2 flex gap-2">
                      <button
                        onClick={() => toggleActive(t.slug, t.is_active)}
                        className="text-xs px-2 py-1 bg-slate-700 hover:bg-slate-600 rounded text-slate-300 transition-colors"
                      >
                        {t.is_active ? "Deactivate" : "Activate"}
                      </button>
                      <button
                        onClick={() => handleDelete(t.slug)}
                        className="text-xs px-2 py-1 bg-red-900/50 hover:bg-red-800/50 rounded text-red-400 transition-colors"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
