'use client';

import { useState, useEffect, useCallback } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001';

interface Resolution {
    method: string;
    invoice_id: string;
    owner_id: string;
    fingerprint: string;
}

interface LicenseInfo {
    invoice_id: string;
    owner_id: string;
    is_paid: boolean;
    max_sessions: number;
    allowed_countries: string | null;
}

interface ViewingSession {
    session_id: number;
    content_id: string;
    start_time: string;
    last_heartbeat: string;
    duration_seconds: number;
    ip_address: string;
    device_info: string;
    is_bot_suspect: boolean;
}

interface AuditEntry {
    timestamp: string;
    ip_address: string;
    is_success: boolean;
    user_agent: string;
}

interface Summary {
    total_sessions: number;
    bot_suspected_sessions: number;
    unique_ips: string[];
    total_audit_events: number;
    failed_verifications: number;
    first_activity: string | null;
    last_activity: string | null;
}

interface LeakReport {
    report_id: string;
    generated_at: string;
    system: string;
    submitted_fingerprint: string;
    resolution: Resolution;
    license: LicenseInfo;
    viewing_sessions: ViewingSession[];
    audit_trail: AuditEntry[];
    summary: Summary;
    integrity_hash: string;
}

interface ReportSummary {
    report_id: string;
    generated_at: string;
    invoice_id: string;
    submitted_fingerprint: string;
}

const STAT = ({ label, value, color }: { label: string; value: string | number; color: string }) => (
    <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700 text-center">
        <p className={`text-lg font-bold font-mono ${color}`}>{value}</p>
        <p className="text-[10px] text-slate-500 mt-0.5">{label}</p>
    </div>
);

export default function LeakReporter({ adminKey }: { adminKey: string }) {
    const [mode, setMode] = useState<'invoice' | 'fingerprint'>('invoice');
    const [input, setInput] = useState('');
    const [report, setReport] = useState<LeakReport | null>(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [pastReports, setPastReports] = useState<ReportSummary[]>([]);

    const fetchPastReports = useCallback(async () => {
        const res = await fetch(`${API}/admin/proof-of-leak`, {
            headers: { 'X-Admin-Key': adminKey },
        });
        if (res.ok) setPastReports(await res.json());
    }, [adminKey]);

    useEffect(() => { fetchPastReports(); }, [fetchPastReports]);

    const generate = async () => {
        if (!input.trim()) return;
        setError('');
        setReport(null);
        setLoading(true);
        const param = mode === 'invoice'
            ? `invoice_id=${encodeURIComponent(input)}`
            : `fingerprint=${encodeURIComponent(input)}`;
        try {
            const res = await fetch(`${API}/admin/proof-of-leak?${param}`, {
                method: 'POST',
                headers: { 'X-Admin-Key': adminKey },
            });
            const data = await res.json();
            if (!res.ok) { setError(data.detail ?? 'Unknown error'); }
            else { setReport(data); fetchPastReports(); }
        } catch {
            setError('Network error — is the backend running?');
        } finally {
            setLoading(false);
        }
    };

    const loadReport = async (id: string) => {
        const res = await fetch(`${API}/admin/proof-of-leak/${id}`, {
            headers: { 'X-Admin-Key': adminKey },
        });
        if (res.ok) setReport(await res.json());
    };

    const downloadJSON = () => {
        if (!report) return;
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `leak-evidence-${report.report_id}.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div className="bg-slate-900 rounded-xl border border-orange-900/30 p-6 shadow-xl">
            {/* Header */}
            <h2 className="text-lg font-bold text-orange-400 mb-1 flex items-center gap-2">
                <span className="text-orange-500">&#x2696;</span> Proof of Leak
                <span className="text-[10px] font-normal text-slate-500 ml-1">Legal Evidence Generator</span>
            </h2>
            <p className="text-[11px] text-slate-500 mb-5">
                Submit the watermark fingerprint extracted from leaked content, or an invoice ID,
                to generate a tamper-evident legal evidence report.
            </p>

            {/* Mode toggle */}
            <div className="flex gap-2 mb-3">
                {(['invoice', 'fingerprint'] as const).map((m) => (
                    <button
                        key={m}
                        onClick={() => { setMode(m); setInput(''); }}
                        className={`px-3 py-1.5 rounded text-xs font-bold transition ${
                            mode === m
                                ? 'bg-orange-600 text-white'
                                : 'text-slate-400 border border-slate-700 hover:border-orange-600/50'
                        }`}
                    >
                        {m === 'invoice' ? 'By Invoice ID' : 'By Fingerprint'}
                    </button>
                ))}
            </div>

            {/* Input */}
            <div className="flex gap-2 mb-4">
                <input
                    placeholder={
                        mode === 'invoice'
                            ? 'Invoice ID (e.g. INV-2026-001)'
                            : 'Watermark fingerprint integer (e.g. 3735928559)'
                    }
                    className="flex-1 bg-slate-950 border border-slate-700 p-2.5 rounded-lg text-sm font-mono outline-none focus:border-orange-500 transition"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && generate()}
                />
                <button
                    onClick={generate}
                    disabled={loading || !input.trim()}
                    className="bg-orange-600 hover:bg-orange-500 disabled:opacity-40 text-white font-bold px-4 rounded-lg text-sm transition active:scale-95"
                >
                    {loading ? 'Generating…' : 'Generate'}
                </button>
            </div>

            {/* Error */}
            {error && (
                <div className="p-3 rounded-lg bg-red-900/20 border border-red-800/40 text-red-400 text-xs mb-4">
                    {error}
                </div>
            )}

            {/* Evidence Report */}
            {report && (
                <div className="space-y-4 mt-2">
                    {/* Report header */}
                    <div className="flex justify-between items-start p-3 rounded-lg bg-orange-900/10 border border-orange-900/30">
                        <div>
                            <p className="text-[9px] font-mono text-slate-500 uppercase tracking-wider">Report ID</p>
                            <p className="text-xs font-mono text-orange-300">{report.report_id}</p>
                            <p className="text-[10px] text-slate-500 mt-1">
                                {new Date(report.generated_at).toLocaleString()}
                            </p>
                        </div>
                        <button
                            onClick={downloadJSON}
                            className="text-xs font-bold text-orange-400 border border-orange-900/40 px-3 py-1.5 rounded hover:bg-orange-900/20 transition"
                        >
                            ↓ Download JSON
                        </button>
                    </div>

                    {/* Identified suspect */}
                    <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
                        <p className="text-[9px] uppercase font-bold tracking-wider text-slate-500 mb-3">
                            Identified Suspect
                        </p>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs font-mono">
                            <span className="text-slate-500">Invoice ID</span>
                            <span className="text-blue-400">{report.resolution.invoice_id}</span>
                            <span className="text-slate-500">Owner ID</span>
                            <span className="text-orange-300 font-bold">{report.resolution.owner_id}</span>
                            <span className="text-slate-500">Watermark FP</span>
                            <span className="text-yellow-400">{report.resolution.fingerprint}</span>
                            <span className="text-slate-500">Resolution</span>
                            <span className="text-slate-300">{report.resolution.method}</span>
                            <span className="text-slate-500">Regions</span>
                            <span className="text-slate-300">{report.license.allowed_countries ?? 'Unrestricted'}</span>
                        </div>
                    </div>

                    {/* Stats grid */}
                    <div className="grid grid-cols-3 gap-3">
                        <STAT label="Sessions" value={report.summary.total_sessions} color="text-blue-400" />
                        <STAT label="Bot Suspects" value={report.summary.bot_suspected_sessions} color="text-red-400" />
                        <STAT label="Unique IPs" value={report.summary.unique_ips.length} color="text-yellow-400" />
                        <STAT label="Audit Events" value={report.summary.total_audit_events} color="text-slate-300" />
                        <STAT label="Failed Verifications" value={report.summary.failed_verifications} color="text-red-400" />
                        <STAT label="Total Duration" value={`${report.viewing_sessions.reduce((s, v) => s + v.duration_seconds, 0)}s`} color="text-green-400" />
                    </div>

                    {/* IP list */}
                    {report.summary.unique_ips.length > 0 && (
                        <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                            <p className="text-[9px] uppercase font-bold tracking-wider text-slate-500 mb-2">Observed IPs</p>
                            <div className="flex flex-wrap gap-1.5">
                                {report.summary.unique_ips.map((ip) => (
                                    <span key={ip} className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-700 text-slate-300">{ip}</span>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Integrity seal */}
                    <div className="p-3 rounded-lg bg-green-900/10 border border-green-900/30 font-mono text-[10px] break-all">
                        <span className="text-green-500 font-bold">✓ INTEGRITY SEAL: </span>
                        <span className="text-slate-400">{report.integrity_hash}</span>
                    </div>

                    {/* Viewing sessions */}
                    {report.viewing_sessions.length > 0 && (
                        <div>
                            <p className="text-[9px] uppercase font-bold tracking-wider text-slate-500 mb-2">Viewing Sessions</p>
                            <div className="space-y-1 max-h-36 overflow-y-auto">
                                {report.viewing_sessions.map((s) => (
                                    <div key={s.session_id} className="flex justify-between text-[10px] font-mono p-2 rounded bg-slate-800/40 border border-slate-800">
                                        <span className="text-blue-400">{s.content_id}</span>
                                        <span className="text-slate-400">{s.ip_address}</span>
                                        <span className="text-green-400">{s.duration_seconds}s</span>
                                        {s.is_bot_suspect && (
                                            <span className="px-1 rounded text-[9px] font-bold bg-red-900/40 text-red-400">BOT</span>
                                        )}
                                        <span className="text-slate-600">{new Date(s.start_time).toLocaleTimeString()}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Past reports */}
            {pastReports.length > 0 && (
                <div className="mt-6 pt-4 border-t border-slate-800">
                    <p className="text-[9px] uppercase font-bold tracking-wider text-slate-500 mb-2">
                        Past Evidence Reports ({pastReports.length})
                    </p>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                        {pastReports.map((r) => (
                            <button
                                key={r.report_id}
                                onClick={() => loadReport(r.report_id)}
                                className="w-full flex justify-between text-[10px] font-mono p-2 rounded bg-slate-800/40 border border-slate-800 hover:border-orange-900/40 transition text-left"
                            >
                                <span className="text-blue-400">{r.invoice_id}</span>
                                <span className="text-slate-500">{r.submitted_fingerprint}</span>
                                <span className="text-slate-600">{new Date(r.generated_at).toLocaleString()}</span>
                            </button>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
