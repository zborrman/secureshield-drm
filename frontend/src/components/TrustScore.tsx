'use client';

interface TrustScoreProps {
    score: number;       // 0–100
    total?: number;      // total sessions (for footer)
    suspicious?: number; // bot-suspect count (for footer)
}

export default function TrustScore({ score, total, suspicious }: TrustScoreProps) {
    const barColor =
        score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-500' : 'bg-red-500';
    const textColor =
        score >= 80 ? 'text-green-400' : score >= 50 ? 'text-yellow-400' : 'text-red-400';
    const label =
        score >= 80 ? 'Trusted' : score >= 50 ? 'Suspicious' : 'High Risk';

    return (
        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800">
            <div className="flex justify-between items-center mb-2">
                <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                    Human Interaction Score
                </span>
                <span className={`font-mono font-bold text-sm ${textColor}`}>
                    {score}%&nbsp;
                    <span className="text-[10px] font-normal text-slate-500">{label}</span>
                </span>
            </div>

            <div className="w-full h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div
                    className={`h-full ${barColor} transition-all duration-500`}
                    style={{ width: `${score}%` }}
                />
            </div>

            {(total !== undefined || suspicious !== undefined) && (
                <div className="flex justify-between mt-2 text-[10px] font-mono text-slate-500">
                    <span>{total ?? 0} session{total !== 1 ? 's' : ''}</span>
                    <span className={(suspicious ?? 0) > 0 ? 'text-red-400' : 'text-slate-600'}>
                        {suspicious ?? 0} bot suspect{suspicious !== 1 ? 's' : ''}
                    </span>
                </div>
            )}
        </div>
    );
}
