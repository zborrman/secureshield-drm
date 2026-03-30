"use client";

import { useState, useEffect, useCallback } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";

// ── Types ──────────────────────────────────────────────────────────────────

interface AnomalyEvidence {
  [key: string]: unknown;
}

interface CouncilVerdict {
  final_severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  final_confidence: number;
  consensus_root_cause: string;
  priority_rank: number;
  immediate_actions: string[];
  council_summary: string;
  models_used: string[];
  chairman: string;
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
  council_verdict?: CouncilVerdict;
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

/** Returns true when the chairman model is a Nemotron NIM model. */
function isNemotronChairman(chairman?: string): boolean {
  return !!chairman && chairman.includes("nemotron");
}

// ── Nemotron Verdict Panel ─────────────────────────────────────────────────

function NemotronVerdictPanel({ verdict }: { verdict: CouncilVerdict }) {
  const nemotron = isNemotronChairman(verdict.chairman);
  return (
    <div className="mt-3 rounded-lg border border-green-700/50 bg-green-900/20 p-4 space-y-3">
      {/* Header */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs font-bold px-2 py-0.5 rounded bg-green-800/60 text-green-300 border border-green-700">
          {nemotron ? "NVIDIA Nemotron" : "AI Council"} Verdict
        </span>
        <span
          className={`text-xs font-bold px-2 py-0.5 rounded border ${SEVERITY_STYLES[verdict.final_severity]}`}
        >
          {verdict.final_severity}
        </span>
        <span className="text-xs text-slate-400">
          Confidence: <span className="text-green-300 font-mono">{verdict.final_confidence}%</span>
        </span>
        <span className="text-xs text-slate-400">
          Priority: <span className="text-green-300 font-mono">{verdict.priority_rank}/10</span>
        </span>
      </div>

      {/* Root cause */}
      <p className="text-sm text-slate-200 leading-relaxed">
        <span className="text-green-400 font-semibold">Root cause: </span>
        {verdict.consensus_root_cause}
      </p>

      {/* Summary */}
      <p className="text-xs text-slate-400 italic">{verdict.council_summary}</p>

      {/* Actions */}
      {verdict.immediate_actions.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-green-400 mb-1">Immediate actions:</p>
          <ul className="space-y-1">
            {verdict.immediate_actions.map((action, i) => (
              <li key={i} className="text-xs text-slate-300 flex gap-2">
                <span className="text-green-500 shrink-0">→</span>
                {action}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Model attribution */}
      <div className="pt-2 border-t border-green-900/50 flex flex-wrap gap-1 items-center">
        <span className="text-xs text-slate-600">Council:</span>
        {verdict.models_used.map((m) => (
          <span
            key={m}
            className="text-xs font-mono text-slate-500 bg-slate-800/60 px-1.5 py-0.5 rounded"
          >
            {m}
          </span>
        ))}
        {verdict.chairman && (
          <>
            <span className="text-xs text-slate-600 ml-1">Chair:</span>
            <span
              className={`text-xs font-mono px-1.5 py-0.5 rounded ${
                nemotron
                  ? "text-green-400 bg-green-900/40 border border-green-800"
                  : "text-slate-400 bg-slate-800/60"
              }`}
            >
              {verdict.chairman}
            </span>
          </>
        )}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────

export default function AnomalyDashboard({ adminKey, tenantSlug }: Props) {
  const [findings, setFindings] = useState<AnomalyFinding[]>([]);
  const [summary, setSummary] = useState<AnomalySummary | null>(null);
  const [filter, setFilter] = useState<string>("ALL");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [enriched, setEnriched] = useState(false);
  const [enrichedUnavailable, setEnrichedUnavailable] = useState(false);

  const baseEndpoint = tenantSlug
    ? `${API}/tenant/anomalies?skip_geo=true`
    : `${API}/admin/anomalies?skip_geo=true`;

  const enrichedEndpoint = `${API}/admin/anomalies/enriched?skip_geo=true&min_score=0&limit=10`;

  const headers: Record<string, string> = tenantSlug
    ? { "X-Tenant-ID": tenantSlug, "X-Admin-Key": adminKey }
    : { "X-Admin-Key": adminKey };

  const fetchAnomalies = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      // Enriched endpoint only available for admin (not tenant-scoped)
      const useEnriched = enriched && !tenantSlug;
      const endpoint = useEnriched ? enrichedEndpoint : baseEndpoint;

      const res = await fetch(endpoint, { headers });
      if (res.status === 503 && useEnriched) {
        setEnrichedUnavailable(true);
        setEnriched(false);
        return;
      }
      if (!res.ok) {
        setError(`Failed to fetch anomalies: ${res.status}`);
        return;
      }
      const data = await res.json();
      // enriched endpoint returns { enriched_findings, summary }
      setFindings(data.enriched_findings ?? data.findings ?? []);
      setSummary(data.summary ?? null);
      setLastRefresh(new Date());
    } catch {
      setError("Network error fetching anomaly data.");
    } finally {
      setLoading(false);
    }
  }, [adminKey, tenantSlug, enriched]);

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

  const hasNemotronFindings = findings.some((f) =>
    isNemotronChairman(f.council_verdict?.chairman)
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span className="text-purple-400">AI</span> Anomaly Pattern Discovery
            {hasNemotronFindings && (
              <span className="text-xs font-normal px-2 py-0.5 rounded bg-green-900/40 text-green-400 border border-green-700">
                Nemotron
              </span>
            )}
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            7-detector statistical engine · rolling 24h window · auto-refreshes every 60 s
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* Enriched toggle — only for admin, not tenant */}
          {!tenantSlug && (
            <button
              onClick={() => {
                setEnrichedUnavailable(false);
                setEnriched((v) => !v);
              }}
              title={
                enrichedUnavailable
                  ? "NVIDIA_API_KEY not configured on server"
                  : enriched
                  ? "Switch to statistical view"
                  : "Enable Nemotron AI enrichment"
              }
              className={`text-xs px-3 py-1.5 rounded border transition-colors ${
                enrichedUnavailable
                  ? "bg-slate-800 border-slate-700 text-slate-600 cursor-not-allowed"
                  : enriched
                  ? "bg-green-900/40 border-green-700 text-green-300 hover:bg-green-900/60"
                  : "bg-slate-700 border-slate-600 text-slate-300 hover:bg-slate-600"
              }`}
              disabled={enrichedUnavailable}
            >
              {enrichedUnavailable ? "Nemotron N/A" : enriched ? "Nemotron ON" : "Nemotron"}
            </button>
          )}
          <button
            onClick={fetchAnomalies}
            disabled={loading}
            className="text-xs bg-slate-700 hover:bg-slate-600 disabled:opacity-50 px-3 py-1.5 rounded text-slate-300 transition-colors"
          >
            {loading ? "Scanning…" : "Refresh"}
          </button>
        </div>
      </div>

      {enrichedUnavailable && (
        <p className="text-yellow-400 text-xs bg-yellow-900/20 border border-yellow-800 rounded-lg px-4 py-2">
          Nemotron enrichment requires <span className="font-mono">NVIDIA_API_KEY</span> on the server.
          Showing statistical findings instead.
        </p>
      )}

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
                  {f.council_verdict && isNemotronChairman(f.council_verdict.chairman) && (
                    <span className="text-xs px-1.5 py-0.5 rounded bg-green-900/40 text-green-400 border border-green-800">
                      Nemotron
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

              {/* Nemotron / council verdict */}
              {f.council_verdict && (
                <NemotronVerdictPanel verdict={f.council_verdict} />
              )}
            </div>
          ))}
        </div>
      )}

      {lastRefresh && (
        <p className="text-xs text-slate-600 text-right">
          Last scan: {lastRefresh.toLocaleTimeString()}
          {enriched && (
            <span className="ml-2 text-green-700">· Nemotron enriched</span>
          )}
        </p>
      )}
    </div>
  );
}
