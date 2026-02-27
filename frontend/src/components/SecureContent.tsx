'use client';

import { useEffect, useState, useRef } from 'react';
import { useViewingAnalytics } from '../hooks/useViewingAnalytics';
import { getOfflineTokenStatus, type OfflineTokenStatus } from '../hooks/useOfflineToken';

type WasmModule = typeof import('../../wasm/pkg/wasm_watermark');

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001';

export default function SecureContent({ encryptedData = [] }: { encryptedData?: number[] }) {
    const [wasm, setWasm] = useState<WasmModule | null>(null);
    const [viewer, setViewer] = useState<any>(null);
    const [isReady, setIsReady] = useState(false);
    const [sessionId, setSessionId] = useState<number | null>(null);
    const [offlineMode, setOfflineMode] = useState<OfflineTokenStatus | null>(null);
    const [isRevoked, setIsRevoked] = useState(false);
    // P3.2 — watermark fingerprint returned by /verify-license
    const [fingerprint, setFingerprint] = useState<number | null>(null);
    const canvasRef = useRef<HTMLCanvasElement>(null);

    // Heartbeat runs automatically whenever sessionId is set.
    // If admin revokes the session, wipe the sessionId and show the overlay.
    useViewingAnalytics(sessionId, () => {
        setSessionId(null);
        setIsRevoked(true);
    });

    // Load Wasm on mount
    useEffect(() => {
        const loadWasm = async () => {
            try {
                const module = await import('../../wasm/pkg/wasm_watermark');
                await module.default();
                setWasm(module);
                setViewer(new module.SecureViewer());
                setIsReady(true);
            } catch (err) {
                console.error('Failed to load Wasm module:', err);
            }
        };
        loadWasm();
    }, []);

    const handleUnlock = async (key: string) => {
        if (!viewer || !wasm) return;

        if (viewer.verify_key(key)) {
            // 1. Decrypt locally — must succeed regardless of connectivity
            let decrypted: Uint8Array;
            try {
                decrypted = viewer.decrypt_content(new Uint8Array(encryptedData));
            } catch {
                alert('Decryption error: key is valid but content data is corrupted.');
                return;
            }
            renderToCanvas(decrypted);

            const invoiceId = localStorage.getItem('invoice_id') ?? 'unknown';

            // 2. Try to register an online analytics session
            try {
                const res = await fetch(
                    `${API}/analytics/start?invoice_id=${encodeURIComponent(invoiceId)}&content_id=main`,
                    { method: 'POST' }
                );
                if (res.status === 409) {
                    alert('Session limit reached: this license is already active on another device. Contact your administrator to revoke the existing session.');
                    return;
                }
                if (res.ok) {
                    const { session_id } = await res.json();
                    setSessionId(session_id);
                    setOfflineMode(null);
                }
            } catch {
                // 3. Network unavailable — fall back to local offline-token check
                const status = getOfflineTokenStatus(invoiceId);
                if (status.isValid) {
                    setOfflineMode(status);
                } else {
                    alert(
                        status.reason === 'no_token'
                            ? 'No network connection and no offline token found. Ask your admin to issue an offline token.'
                            : status.reason === 'expired'
                              ? 'Your offline token has expired. Reconnect to the network or ask your admin for a new token.'
                              : 'No network connection and the offline token could not be verified.'
                    );
                }
            }

            // 4. P3.2 — fetch watermark fingerprint from backend (best-effort)
            try {
                const fpRes = await fetch(
                    `${API}/verify-license?invoice_id=${encodeURIComponent(invoiceId)}&license_key=${encodeURIComponent(key)}`
                );
                if (fpRes.ok) {
                    const { fingerprint: fp } = await fpRes.json();
                    if (typeof fp === 'number') setFingerprint(fp);
                }
            } catch {
                // fingerprint display is non-critical — ignore network failures
            }
        } else {
            alert('Access denied: invalid license key.');
        }
    };

    const renderToCanvas = (data: Uint8Array) => {
        const ctx = canvasRef.current?.getContext('2d');
        if (!ctx) return;
        const imageData = new ImageData(new Uint8ClampedArray(data), 100, 100);
        ctx.putImageData(imageData, 0, 0);
    };

    return (
        <div className="space-y-4 bg-slate-900 p-6 rounded-xl border border-slate-800 shadow-2xl">
            <div className="flex items-center gap-2 mb-2">
                {isReady ? (
                    <>
                        <div className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_10px_#22c55e]"></div>
                        <span className="text-xs font-mono text-green-500 uppercase tracking-widest">
                            Secure Enclave Active
                        </span>
                        {sessionId && (
                            <span className="ml-auto text-xs font-mono text-slate-500">
                                session #{sessionId}
                            </span>
                        )}
                        {offlineMode && (
                            <span className="ml-auto flex items-center gap-1 text-[10px] font-mono text-indigo-400 border border-indigo-800/40 px-2 py-0.5 rounded-full">
                                <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 inline-block"></span>
                                Offline — {offlineMode.hoursRemaining}h remaining
                            </span>
                        )}
                    </>
                ) : (
                    <div className="animate-pulse text-slate-500 text-xs font-mono">
                        Loading secure enclave...
                    </div>
                )}
            </div>

            <div className="relative">
                <canvas
                    ref={canvasRef}
                    width={100}
                    height={100}
                    className="w-full aspect-square bg-black rounded border border-slate-700 image-render-pixelated"
                    onContextMenu={(e) => e.preventDefault()}
                />
                {isRevoked && (
                    <div className="absolute inset-0 flex flex-col items-center justify-center rounded bg-black/80 backdrop-blur-sm">
                        <span className="text-2xl mb-2">&#x1F512;</span>
                        <p className="text-red-400 font-bold text-sm text-center px-4">
                            Session terminated
                        </p>
                        <p className="text-slate-500 text-[10px] text-center px-4 mt-1">
                            An administrator has revoked your viewing session.
                            Contact your administrator to regain access.
                        </p>
                    </div>
                )}
            </div>

            {/* P3.2 — watermark fingerprint badge */}
            {fingerprint !== null && (
                <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-indigo-900/10 border border-indigo-900/30">
                    <span className="text-[9px] uppercase tracking-wider text-slate-500 font-bold">Watermark ID</span>
                    <code className="text-indigo-400 font-mono text-xs">{fingerprint}</code>
                    <span className="text-[9px] text-slate-600 italic ml-auto">
                        Your copy is uniquely watermarked with this identifier.
                    </span>
                </div>
            )}

            {isReady && (
                <div className="flex gap-2">
                    <input
                        type="password"
                        id="key-input"
                        placeholder="License key"
                        className="flex-1 bg-slate-950 border border-slate-800 p-2 rounded text-sm focus:border-blue-500 outline-none transition"
                    />
                    <button
                        onClick={() =>
                            handleUnlock(
                                (document.getElementById('key-input') as HTMLInputElement).value
                            )
                        }
                        className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded text-sm font-bold transition-all active:scale-95"
                    >
                        Unlock
                    </button>
                </div>
            )}
        </div>
    );
}
