/**
 * Real-time admin event stream over Server-Sent Events.
 *
 * Connects to GET /admin/events and forwards every JSON message to `onEvent`.
 * EventSource does not support custom request headers, so the admin key is
 * passed as a ?admin_key= query parameter.
 *
 * The connection auto-reconnects on network loss (built into EventSource).
 */
import { useEffect, useRef } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001';

export interface DrmRevocationEvent {
    type?: 'connected';
    session_id?: number;
    invoice_id?: string;
    action?: 'revoked';
}

export function useAdminEvents(
    adminKey: string,
    onEvent: (e: DrmRevocationEvent) => void,
): void {
    const onEventRef = useRef(onEvent);
    useEffect(() => { onEventRef.current = onEvent; }, [onEvent]);

    useEffect(() => {
        if (!adminKey) return;

        const url = `${API}/admin/events?admin_key=${encodeURIComponent(adminKey)}`;
        const es = new EventSource(url);

        es.onmessage = (e) => {
            try {
                onEventRef.current(JSON.parse(e.data));
            } catch {
                // Malformed frame — ignore
            }
        };

        // onerror fires on transient network issues too; EventSource retries automatically
        es.onerror = () => { /* intentionally empty */ };

        return () => es.close();
    }, [adminKey]);
}
