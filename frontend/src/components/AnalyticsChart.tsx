'use client';

import {
    LineChart, Line, XAxis, YAxis, CartesianGrid,
    Tooltip, ResponsiveContainer,
} from 'recharts';

interface Session {
    id: number;
    content_id: string;
    duration_seconds: number;
    start_time: string;
    ip_address: string;
    is_bot_suspect: boolean;
}

interface ChartPoint {
    name: string;
    duration: number;
}

function toChartData(sessions: Session[]): ChartPoint[] {
    // Aggregate total duration per content_id
    const totals: Record<string, number> = {};
    for (const s of sessions) {
        totals[s.content_id] = (totals[s.content_id] ?? 0) + s.duration_seconds;
    }
    return Object.entries(totals).map(([name, duration]) => ({ name, duration }));
}

interface AnalyticsChartProps {
    data: Session[];
    onRevoke?: (id: number) => void;
}

export default function AnalyticsChart({ data, onRevoke }: AnalyticsChartProps) {
    const chartData = toChartData(data);
    const totalSeconds = data.reduce((sum, s) => sum + s.duration_seconds, 0);
    const activeSessions = data.filter(
        (s) => Date.now() - new Date(s.start_time).getTime() < 5 * 60 * 1000
    ).length;

    return (
        <div className="bg-slate-900 p-6 rounded-2xl border border-slate-800 shadow-xl">
            <div className="flex items-center justify-between mb-6">
                <h3 className="text-white font-bold flex items-center gap-2">
                    <span className="text-blue-400">&#x2022;</span> Viewing Engagement
                </h3>
                <div className="flex gap-4 text-xs font-mono">
                    <span className="text-slate-400">
                        Total: <span className="text-blue-400">{totalSeconds}s</span>
                    </span>
                    <span className="text-slate-400">
                        Sessions: <span className="text-green-400">{data.length}</span>
                    </span>
                    <span className="text-slate-400">
                        Active (&lt;5m): <span className="text-yellow-400">{activeSessions}</span>
                    </span>
                </div>
            </div>

            {chartData.length === 0 ? (
                <div className="h-48 flex items-center justify-center text-slate-600 italic text-sm">
                    No viewing sessions yet
                </div>
            ) : (
                <div className="h-48 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={chartData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                            <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                            <YAxis stroke="#64748b" fontSize={11} unit="s" />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                                itemStyle={{ color: '#3b82f6' }}
                                formatter={(v: number | undefined) => [`${v ?? 0}s`, 'Duration']}
                            />
                            <Line
                                type="monotone"
                                dataKey="duration"
                                stroke="#3b82f6"
                                strokeWidth={2}
                                dot={{ r: 4, fill: '#3b82f6' }}
                                activeDot={{ r: 6 }}
                            />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            )}

            {/* Session list */}
            <div className="mt-4 space-y-1 max-h-40 overflow-y-auto">
                {data.slice(0, 10).map((s) => (
                    <div key={s.id} className="flex items-center justify-between text-xs font-mono p-2 border-b border-slate-800 gap-2">
                        <span className="text-blue-400 flex-1 truncate">{s.content_id}</span>
                        <span className="text-slate-400">{s.ip_address}</span>
                        <span className="text-green-400">{s.duration_seconds}s</span>
                        {s.is_bot_suspect && (
                            <span className="px-1 rounded text-[9px] font-bold bg-red-900/40 text-red-400">BOT</span>
                        )}
                        <span className="text-slate-600">
                            {new Date(s.start_time).toLocaleTimeString()}
                        </span>
                        {onRevoke && (
                            <button
                                onClick={() => onRevoke(s.id)}
                                className="text-[9px] px-1.5 py-0.5 rounded border border-red-900/40 text-red-400 hover:bg-red-900/20 hover:border-red-500/60 transition"
                            >
                                Revoke
                            </button>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}
