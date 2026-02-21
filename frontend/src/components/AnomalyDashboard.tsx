"use client";

import { useState, useEffect, useCallback } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";

// ── Types ──────────────────────────────────────────────────────────────────

interface AnomalyEvidence {
  [key: string]: unknown;
}

interface AnomalyFinding {
  anomaly_id: string;
  type: string;
  score: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  evidence: AnomalyEvidence;
  recommendation: string;
  detected_at: string;
  invoice_id: string | null;
  owner_id: string | null;
  ip_address?: string;
  license_id?: number;
}

interface AnomalySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface Props {
  adminKey: string;
  /** When set, uses tenant-scoped /tenant/anomalies endpoint */
  tenantSlug?: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-900/60 text-red-300 border-red-700",
  HIGH:     "bg-orange-900/60 text-orange-300 border-orange-700",
  MEDIUM:   "bg-yellow-900/60 text-yellow-300 border-yellow-700",
  LOW:      "bg-slate-700/60 text-slate-300 border-slate-600",
};

const SCORE_BAR_COLOR: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH:     "bg-orange-500",
  MEDIUM:   "bg-yellow-500",
  LOW:      "bg-slate-500",
};

const TYPE_LABELS: Record<string, string> = {
  ip_velocity:          "IP Velocity",
  session_flood:        "Session Flood",
  bot_pattern:          "Bot Pattern",
  brute_force_cluster:  "Brute-Force Cluster",
  credential_sharing:   "Credential Sharing",
  duration_anomaly:     "Duration Anomaly",
  multi_country:        "Multi-Country Access",
};

function formatEvidenceValue(value: unknown): string {
  if (Array.isArray(value)) return value.slice(0, 5).join(", ");
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

// ── Main Component ─────────────────────────────────────────────────────────

export default function AnomalyDashboard({ adminKey, tenantSlug }: Props) {
  const [findings, setFindings] = useState<AnomalyFinding[]>([]);
  const [summary, setSummary] = useState<AnomalySummary | null>(null);
  const [filter, setFilter] = useState<string>("ALL");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const endpoint = tenantSlug
    ? `${API}/tenant/anomalies?skip_geo=true`
    : `${API}/admin/anomalies?skip_geo=true`;

  const headers: Record<string, string> = tenantSlug
    ? { "X-Tenant-ID": tenantSlug, "X-Admin-Key": adminKey }
    : { "X-Admin-Key": adminKey };

  const fetchAnomalies = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await fetch(endpoint, { headers });
      if (!res.ok) {
        setError(`Failed to fetch anomalies: ${res.status}`);
        return;
      }
      const data = await res.json();
      setFindings(data.findings ?? []);
      setSummary(data.summary ?? null);
      setLastRefresh(new Date());
    } catch {
      setError("Network error fetching anomaly data.");
    } finally {
      setLoading(false);
    }
  }, [adminKey, tenantSlug]);

  useEffect(() => {
    if (adminKey) fetchAnomalies();
  }, [fetchAnomalies]);

  // Auto-refresh every 60 seconds
  useEffect(() => {
    if (!adminKey) return;
    const id = setInterval(fetchAnomalies, 60_000);
    return () => clearInterval(id);
  }, [fetchAnomalies]);

  const displayed =
    filter === "ALL"
      ? findings
      : findings.filter((f) => f.severity === filter);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span className="text-purple-400">AI</span> Anomaly Pattern Discovery
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            7-detector statistical engine · rolling 24h window · auto-refreshes every 60 s
          </p>
        </div>
        <button
          onClick={fetchAnomalies}
          disabled={loading}
          className="text-xs bg-slate-700 hover:bg-slate-600 disabled:opacity-50 px-3 py-1.5 rounded text-slate-300 transition-colors"
        >
          {loading ? "Scanning…" : "Refresh"}
        </button>
      </div>

      {error && (
        <p className="text-red-400 text-sm bg-red-900/30 border border-red-800 rounded-lg px-4 py-2">
          {error}
        </p>
      )}

      {/* Summary strip */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label: "Total", value: summary.total,    color: "text-white"         },
            { label: "Critical", value: summary.critical, color: "text-red-400"    },
            { label: "High",     value: summary.high,     color: "text-orange-400" },
            { label: "Medium",   value: summary.medium,   color: "text-yellow-400" },
            { label: "Low",      value: summary.low,      color: "text-slate-400"  },
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="bg-slate-800 rounded-xl border border-slate-700 p-4 text-center"
            >
              <div className={`text-3xl font-bold ${color}`}>{value}</div>
              <div className="text-xs text-slate-500 mt-1 uppercase tracking-wider">
                {label}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex gap-2 flex-wrap">
        {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
          <button
            key={sev}
            onClick={() => setFilter(sev)}
            className={`text-xs px-3 py-1.5 rounded-full font-semibold transition-colors border ${
              filter === sev
                ? sev === "ALL"
                  ? "bg-slate-600 border-slate-500 text-white"
                  : SEVERITY_STYLES[sev]
                : "bg-slate-800 border-slate-700 text-slate-400 hover:text-white"
            }`}
          >
            {sev}
            {sev !== "ALL" && summary && (
              <span className="ml-1.5 opacity-70">
                ({summary[sev.toLowerCase() as keyof AnomalySummary]})
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Findings list */}
      {displayed.length === 0 ? (
        <div className="text-center py-12 text-slate-500 text-sm bg-slate-800/30 rounded-xl border border-dashed border-slate-700">
          {loading
            ? "Scanning for anomalies…"
            : findings.length === 0
            ? "No anomalies detected — all patterns look healthy."
            : `No ${filter} findings.`}
        </div>
      ) : (
        <div className="space-y-4">
          {displayed.map((f) => (
            <div
              key={f.anomaly_id}
              className={`rounded-xl border p-5 space-y-3 ${SEVERITY_STYLES[f.severity]}`}
            >
              {/* Card header */}
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  <span
                    className={`text-xs font-bold px-2.5 py-1 rounded-full border ${SEVERITY_STYLES[f.severity]}`}
                  >
                    {f.severity}
                  </span>
                  <span className="font-semibold text-white">
                    {TYPE_LABELS[f.type] ?? f.type}
                  </span>
                  {f.invoice_id && (
                    <span className="font-mono text-xs text-blue-300 bg-blue-900/30 px-2 py-0.5 rounded">
                      {f.invoice_id}
                    </span>
                  )}
                  {f.ip_address && (
                    <span className="font-mono text-xs text-slate-300">
                      {f.ip_address}
                    </span>
                  )}
                </div>
                <div className="text-xs text-slate-400 font-mono whitespace-nowrap">
                  {new Date(f.detected_at).toLocaleString()}
                </div>
              </div>

              {/* Score bar */}
              <div className="flex items-center gap-3">
                <div className="text-xs text-slate-400 w-12 shrink-0">
                  Score
                </div>
                <div className="flex-1 h-2 bg-slate-900/60 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${SCORE_BAR_COLOR[f.severity]} transition-all`}
                    style={{ width: `${f.score}%` }}
                  />
                </div>
                <div className="text-xs font-mono text-slate-300 w-8 text-right">
                  {f.score}
                </div>
              </div>

              {/* Evidence table */}
              <div className="bg-slate-900/50 rounded-lg p-3 text-xs font-mono space-y-1">
                {Object.entries(f.evidence).map(([k, v]) => (
                  <div key={k} className="flex gap-3">
                    <span className="text-slate-500 shrink-0 w-40">{k}</span>
                    <span className="text-slate-200 break-all">
                      {formatEvidenceValue(v)}
                    </span>
                  </div>
                ))}
              </div>

              {/* Recommendation */}
              <div className="text-sm text-slate-300 leading-relaxed border-t border-white/10 pt-3">
                <span className="text-purple-400 font-semibold">Recommendation: </span>
                {f.recommendation}
              </div>
            </div>
          ))}
        </div>
      )}

      {lastRefresh && (
        <p className="text-xs text-slate-600 text-right">
          Last scan: {lastRefresh.toLocaleTimeString()}
        </p>
      )}
    </div>
  );
}
