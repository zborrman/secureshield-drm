"use client";

import { useState } from "react";
import SuperAdminDashboard from "../../../components/SuperAdminDashboard";

export default function SuperAdminPage() {
  const [key, setKey] = useState("");
  const [input, setInput] = useState("");

  if (!key) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
        <div className="w-full max-w-sm bg-slate-900 rounded-2xl border border-slate-700 p-8 space-y-4 shadow-2xl">
          <h1 className="text-xl font-bold text-white">Super Admin Access</h1>
          <p className="text-slate-400 text-sm">
            Enter your super-admin key to manage all tenants.
          </p>
          <input
            type="password"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && setKey(input)}
            placeholder="X-Super-Admin-Key"
            className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500"
          />
          <button
            onClick={() => setKey(input)}
            className="w-full bg-purple-600 hover:bg-purple-500 text-white font-semibold rounded-lg py-2 transition-colors"
          >
            Authenticate
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 bg-slate-950 min-h-screen">
      <div className="flex justify-end mb-4">
        <button
          onClick={() => { setKey(""); setInput(""); }}
          className="text-xs text-red-500 hover:text-red-400 font-mono border border-red-900/40 px-3 py-1.5 rounded"
        >
          Logout
        </button>
      </div>
      <SuperAdminDashboard superAdminKey={key} />
    </div>
  );
}
