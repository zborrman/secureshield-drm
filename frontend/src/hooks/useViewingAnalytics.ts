import { useEffect, useRef } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001';
const HEARTBEAT_INTERVAL_MS = 30_000;

/**
 * Sends a heartbeat to /analytics/heartbeat/{sessionId} every 30 seconds.
 *
 * If the server returns {"revoked": true} (set by an admin via the real-time
 * revocation API), `onRevoked` is called so the parent component can lock
 * the content and show an appropriate message to the user.
 *
 * Automatically clears the interval when the component unmounts or
 * `sessionId` changes.
 */
export function useViewingAnalytics(
    sessionId: number | null,
    onRevoked?: () => void,
): void {
    // Stable ref so the interval callback always calls the latest onRevoked
    const onRevokedRef = useRef(onRevoked);
    useEffect(() => { onRevokedRef.current = onRevoked; }, [onRevoked]);

    useEffect(() => {
        if (!sessionId) return;

        const interval = setInterval(async () => {
            try {
                const res = await fetch(
                    `${API}/analytics/heartbeat/${sessionId}`,
                    { method: 'POST' }
                );
                if (res.ok) {
                    const data = await res.json();
                    if (data.revoked === true) {
                        // Parent sets sessionId → null, which clears this interval
                        onRevokedRef.current?.();
                    }
                }
            } catch {
                // Heartbeat failures are non-fatal (offline mode handles network loss)
            }
        }, HEARTBEAT_INTERVAL_MS);

        return () => clearInterval(interval);
    }, [sessionId]);
}
